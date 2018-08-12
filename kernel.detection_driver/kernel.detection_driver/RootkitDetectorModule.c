/*++

	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
	KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
	PURPOSE.

Module Name:

	RootkitDetectorModule.c

Abstract:

	Rootkit detection module contains the thread that will write to
	the information buffer, and all the methods this driver has to detect
	a kernel mode rootkit.

Environment:

	Kernel mode only

--*/

#include "RootkitDetection.h"
#include "RootkitDetectorModule.h"
#include "Undocumented.h"
#include "ModuleHandler.h"
#include "HooksChecker.h"

#define SSDT_FOUND_HOOK_MSG "Hooked function found in the SSDT at index %.3d function name is %s, the hook points to 0x%x"

KSTART_ROUTINE RootkitDetectionRoutine;

KDD_DETECTION_REQUEST KddInformationBuffer = { 0 };
PETHREAD ptRootkitDetectionObject = NULL;
INT bStopDetectionThread = FALSE;

__declspec(dllimport) SYSTEM_SERVICE_TABLE KeServiceDescriptorTable;


VOID CleanInformationBuffer(
	PKDD_INFORMATION_BUFFER pInfoBuffer
)
{
	size_t cbInfoBufferLength = 0;

	RtlStringCbLengthA(
		pInfoBuffer->pszInformationBuffer,
		sizeof(pInfoBuffer->pszInformationBuffer) - 1,
		&cbInfoBufferLength);

	RtlZeroMemory((pInfoBuffer->pszInformationBuffer), cbInfoBufferLength + 1);
	pInfoBuffer->ulInformationBufferLength = 0;
}

VOID FormatString(
	_Out_ NTSTRSAFE_PSTR	  pszBuffer,
	_In_ CONST ULONG		  ulBufferSize,
	_In_ CONST NTSTRSAFE_PSTR pszFormat,
	...
)
{
	va_list arglist;
	va_start(arglist, pszFormat);

	RtlStringCbVPrintfA(
		pszBuffer,
		ulBufferSize,
		(NTSTRSAFE_PSTR)SSDT_FOUND_HOOK_MSG,
		arglist);

	va_end(arglist);
}

BOOL ScanSsdtForHooks(
	_Out_ NTSTRSAFE_PSTR pszBuffer,
	_In_ CONST ULONG	 ulBufferSize,
	_In_ CONST BOOLEAN   bCheckInline
)
{
	UINT uiIndex = 0;
	BOOLEAN bIsHooked = FALSE;
	DWORD dwFunctionAddress = 0x0;
	DWORD dwNtoskrnlBaseAddress = 0x0;
	DWORD dwNtoskrnlEndAddress = 0x0;
	PCHAR pszHookedFunction = NULL;
	PCHAR pszUnknownName = "Unknown function name";

	/*
	 * ntkrnlpa.exe is the name of ntoskrnl.exe for Windows 7 32-bis.
	 * There is a place to add mechanism to check the OS version and set 
	 * the name accordingly.
	 */
	dwNtoskrnlBaseAddress = (DWORD)KernelGetModuleBase("ntkrnlpa.exe", &dwNtoskrnlEndAddress);
	dwNtoskrnlEndAddress += dwNtoskrnlBaseAddress;
	if (0 == dwNtoskrnlBaseAddress)
	{
		InfoPrint("Couldn't find ntoskrnl.exe address: 0x%x", dwNtoskrnlBaseAddress);
	}
	//InfoPrint("ntoskrnl.exe address: 0x%x", dwNtoskrnlBaseAddress);

	for (uiIndex = 0; uiIndex < KeServiceDescriptorTable.ServiceLimit; uiIndex++)
	{
		dwFunctionAddress = (*(KeServiceDescriptorTable.ServiceTable + uiIndex));
		if (!((dwFunctionAddress > dwNtoskrnlBaseAddress) &&
			(dwFunctionAddress < dwNtoskrnlEndAddress)))
		{
			bIsHooked = TRUE;
			break;
		}
		else if (TRUE == bCheckInline)
		{
			if (TRUE == IsHookedJmpOutOfModule((LPVOID)dwFunctionAddress, dwNtoskrnlBaseAddress, dwNtoskrnlEndAddress))
			{
				bIsHooked = TRUE;
				break;
			}
		}
	}
	if (TRUE == bIsHooked)
	{
		// Get function address from shadow table and check if it is different from this hooked function,
		// if it is, get its name (maybe fix?).
		//pszHookedFunction = GetFuncNameByAddressFromExport((HMODULE)dwNtoskrnlBaseAddress, Address from shadow table);
		if (NULL == pszHookedFunction)
		{
			pszHookedFunction = pszUnknownName;
		}

		InfoPrint("Ord %.3d Name %s Address 0x%x is not in ntoskrnl range",
			uiIndex,
			pszHookedFunction,
			(*(KeServiceDescriptorTable.ServiceTable + uiIndex)));

		FormatString(
			pszBuffer,
			ulBufferSize,
			(NTSTRSAFE_PSTR)SSDT_FOUND_HOOK_MSG,
			uiIndex,
			pszHookedFunction,
			(*(KeServiceDescriptorTable.ServiceTable + uiIndex)));
	}

	return bIsHooked;
}

VOID RootkitDetectionRoutine(
	_In_ PVOID pInformationBuffer
)
{
	PKDD_INFORMATION_BUFFER pInfoBuffer = NULL;
	LARGE_INTEGER liSleepTime;
	size_t cbInfoBufferLength = 0;
	CHAR pszMessageToService[MAX_FUNC_MSG_SIZE] = { 0 };

	InfoPrint("RootkitDetectionRoutine entered.");
	
	ExReleaseFastMutex(&fmInformationMutex);

	ExAcquireFastMutex(&fmDetectionThreadMutex);

	if (uiDetectionThreadCounter >= 1)
	{
		ErrorPrint("RootkitDetectionRoutine received NULL argument.");
		uiDetectionThreadCounter--;
		ExReleaseFastMutex(&fmDetectionThreadMutex);
		PsTerminateSystemThread(STATUS_INVALID_PARAMETER); // Change return error 
	}
	if (bIsDetectionThreadAlive == TRUE)
	{
		ExReleaseFastMutex(&fmDetectionThreadMutex);
		PsTerminateSystemThread(STATUS_INVALID_PARAMETER); // Change return error 
	}
	bIsDetectionThreadAlive = TRUE;
	uiDetectionThreadCounter++;
	
ExReleaseFastMutex(&fmDetectionThreadMutex);

	if (NULL == pInformationBuffer)
	{
		ErrorPrint("RootkitDetectionRoutine received NULL argument.");
		PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
	}
	pInfoBuffer = (PKDD_INFORMATION_BUFFER)pInformationBuffer;

	liSleepTime.QuadPart = 1000 * RELATIVE_MILLISECOND;

	while (FALSE == bStopDetectionThread)
	{
		KeDelayExecutionThread(KernelMode, FALSE, (&liSleepTime));

		ExAcquireFastMutex(&fmInformationMutex);
		CleanInformationBuffer(pInfoBuffer);
		ExReleaseFastMutex(&fmInformationMutex);

		if (FALSE == ScanSsdtForHooks(pszMessageToService, MAX_FUNC_MSG_SIZE, TRUE))
		{
			continue;
		}

		ExAcquireFastMutex(&fmInformationMutex);

		RtlStringCbCopyNA(
			pInfoBuffer->pszInformationBuffer,
			INFORMATION_BUFFER_LENGTH - 1,
			pszMessageToService,
			MAX_FUNC_MSG_SIZE);

		RtlStringCbLengthA(
			pszMessageToService,
			MAX_FUNC_MSG_SIZE,
			&cbInfoBufferLength);
		pInfoBuffer->ulInformationBufferLength += cbInfoBufferLength;

		ExReleaseFastMutex(&fmInformationMutex);
	}
	
	// Add boolean if thread is done?
	InfoPrint("RootkitDetectionRoutine terminating thread.");

	ExAcquireFastMutex(&fmDetectionThreadMutex);
	bIsDetectionThreadAlive = FALSE;
	uiDetectionThreadCounter--;
	ExReleaseFastMutex(&fmDetectionThreadMutex);

	PsTerminateSystemThread(STATUS_SUCCESS);
}