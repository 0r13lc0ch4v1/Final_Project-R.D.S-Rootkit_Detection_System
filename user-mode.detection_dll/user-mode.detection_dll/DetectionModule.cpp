#include "stdafx.h"
#include "DetectionModule.h"
#include "ModuleHandler.h"
#include "Utils.h"
#include "IpcPipeClient.h"
#include "HooksCheck.h"

BOOL IsForwardFunction(
	_In_ CONST HMODULE hModule,
	_In_ CONST LPCSTR  pszFunctionName,
	_Out_ BOOL		   *bIsForwarded,
	_Out_ PCHAR		   *pszForwardFormat
)
{
	PVOID pFunctionAddress;
	DWORD dwExoprtDirLowAddress;
	DWORD dwExoprtDirHighAddress;

	if ((NULL == hModule) || (NULL == pszFunctionName) || (NULL == bIsForwarded))
	{
		return FALSE;
	}

	if (FALSE == GetDataDirectoryRange(hModule, IMAGE_DIRECTORY_ENTRY_EXPORT, &dwExoprtDirLowAddress, &dwExoprtDirHighAddress))
	{
		return FALSE;
	}

	pFunctionAddress = GetFuncAddressFromExport(hModule, pszFunctionName);
	if (NULL == pFunctionAddress)
	{
		return FALSE;
	}

	if (((DWORD)pFunctionAddress > dwExoprtDirLowAddress) &&
		((DWORD)pFunctionAddress < dwExoprtDirHighAddress))
	{
		(*pszForwardFormat) = (PCHAR)pFunctionAddress;
		(*bIsForwarded) = TRUE;
		return TRUE;
	}

	(*pszForwardFormat) = NULL;
	(*bIsForwarded) = FALSE;

	return TRUE;
}

BOOL SplitForwardFormat(
	_In_ CONST PCHAR pszForwardFormat,
	_Out_ PCHAR		 pszModuleName,
	_Out_ PCHAR		 pszFunctionName,
	_In_ DWORD		 dwBufferSize
)
{
	PVOID pTmpPtr = NULL;
	DWORD dwDelimiterIndex = 0;
	HRESULT hResult = NULL;

	if ((NULL == pszForwardFormat) || (NULL == pszModuleName) || (NULL == pszFunctionName))
	{
		return FALSE;
	}

	pTmpPtr = FindFirstChar(pszForwardFormat, dwBufferSize, FORWARD_DELIMITER, &dwDelimiterIndex);
	if (NULL == pTmpPtr)
	{
		return FALSE;
	}
	hResult = StringCchCopyNA(pszModuleName, dwBufferSize, pszForwardFormat, dwDelimiterIndex);
	if (FALSE == SUCCEEDED(hResult))
	{
		return FALSE;
	}
	pTmpPtr = pszForwardFormat + dwDelimiterIndex + 1;
	hResult = StringCchCopyNA(pszFunctionName, dwBufferSize, (PCHAR)pTmpPtr, lstrlenA((PCHAR)pTmpPtr));
	if (FALSE == SUCCEEDED(hResult))
	{
		return FALSE;
	}

	return TRUE;
}

PVOID GetFuncAddressFromForwardFormat(
	_In_ CONST PCHAR pszForwardFormat,
	_Out_ PCHAR		 pszModuleName,
	_Out_ PCHAR		 pszFunctionName,
	_In_ CONST DWORD dwBufferSize

)
{
	size_t uiModuleNameLength = 0;
	size_t uiFunctionNameLength = 0;
	HMODULE hModule = NULL;
	PVOID pForwardFuncAddress = NULL;

	if (FALSE == SplitForwardFormat(
		pszForwardFormat,
		pszModuleName,
		pszFunctionName,
		dwBufferSize))
	{
		return NULL;
	}

	StringCchLengthA(pszModuleName, dwBufferSize, (&uiModuleNameLength));
	StringCchLengthA(pszFunctionName, dwBufferSize, (&uiFunctionNameLength));

	if ((0 == uiModuleNameLength) || (0 == uiFunctionNameLength))
	{
		return NULL;
	}

	hModule = GetModuleHandleA(pszModuleName);
	if (NULL == hModule)
	{
		return NULL;
	}

	pForwardFuncAddress = GetFuncAddressFromExport(hModule, (LPCSTR)pszFunctionName);
	// Check if pForwardFuncAddress is in module range (maybe hooked too?)

	return pForwardFuncAddress;
}

BOOL IsAddressInModuleRange(
	_In_ CONST PCHAR  pszModuleName,
	_In_ CONST PVOID  pFunctionAddress,
	_Out_ HMODULE *hImportedModule,
	_Out_ PDWORD dwModuleLowAddress,
	_Out_ PDWORD dwModuleHighAddress
)
{
	HMODULE hLocalImportedModule = NULL;
	DWORD dwModuleSize = 0;
	DWORD dwLocalModuleLowAddress = 0;
	DWORD dwLocalModuleHighAddress = 0;

	hLocalImportedModule = GetModuleHandleA(pszModuleName);
	dwModuleSize = GetSizeOfImage(hLocalImportedModule);
	dwLocalModuleLowAddress = (DWORD)(hLocalImportedModule);
	dwLocalModuleHighAddress = (DWORD)(hLocalImportedModule)+dwModuleSize;

	if (NULL != hImportedModule)
	{
		(*hImportedModule) = hLocalImportedModule;
	}
	if (NULL != dwModuleLowAddress)
	{
		(*dwModuleLowAddress) = dwLocalModuleLowAddress;
	}
	if (NULL != dwModuleHighAddress)
	{
	(*dwModuleHighAddress) = dwLocalModuleHighAddress;
	}

	return (((DWORD)pFunctionAddress > dwLocalModuleLowAddress) &&
		((DWORD)pFunctionAddress < dwLocalModuleHighAddress)) ? TRUE : FALSE;
}

BOOL IsExceptionProcess()
{
	return lstrcmpW(TEXT("iexplore.exe"), (PWCHAR)ProcessName) ? FALSE : TRUE;
}

BOOL IsFunctionHooked(
	_In_ CONST PCHAR  pszModuleName,
	_In_ CONST LPCSTR pszFunctionName,
	_In_ CONST PVOID  pFunctionAddress,
	_In_ CONST BOOL   bCheckInlineHook
)
{
	HMODULE hImportedModule = NULL;
	DWORD dwModuleLowAddress = 0;
	DWORD dwModuleHighAddress = 0;
	BOOL bIsForwarded = FALSE;
	PCHAR pszForwardFormat = NULL;
	PVOID pForwardFuncAddress = NULL;
	CHAR pszForawrdFunctionName[MAX_PATH] = { NULL };
	CHAR pszForawrdModuleName[MAX_PATH] = { NULL };

	if (FALSE == IsAddressInModuleRange(pszModuleName, pFunctionAddress, &hImportedModule, &dwModuleLowAddress, &dwModuleHighAddress))
	{
		if (TRUE == IsForwardFunction(hImportedModule, pszFunctionName, &bIsForwarded, &pszForwardFormat))
		{
			if (TRUE == bIsForwarded)
			{
				pForwardFuncAddress = GetFuncAddressFromForwardFormat(pszForwardFormat, pszForawrdModuleName, pszForawrdFunctionName, MAX_PATH);
				if ((DWORD)pFunctionAddress != (DWORD)pForwardFuncAddress)
				{
					if (NULL == pForwardFuncAddress)
					{
						return TRUE;
					}
					else
					{
						return IsFunctionHooked(pszForawrdModuleName, pszForawrdFunctionName, pForwardFuncAddress, bCheckInlineHook);
					}
				}
			}
			else if (IsExceptionProcess()) //Hooked by legitimate source e.g. Microsoft ieshims.dll hooks the IAT
			{
				if (FALSE == IsAddressInModuleRange((PCHAR)"ieshims", pFunctionAddress))
				{
					return TRUE;
				}
			}
			else
			{
				return TRUE;
			}
		}
	}
	if (TRUE == bCheckInlineHook)
	{
		if (TRUE == IsHookedJmpOutOfModule((LPVOID)(pFunctionAddress), dwModuleLowAddress, dwModuleHighAddress))
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOL CheckHooksInIAT(
	_In_ CONST HMODULE hModule
)
{
	PIMAGE_IMPORT_DESCRIPTOR pImportedModuleDescriptor = NULL;
	PIMAGE_THUNK_DATA pFirstThunk = NULL;
	PIMAGE_THUNK_DATA pOriginalFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME pFunctionData = NULL;
	PCHAR pszModuleName = NULL;

	pImportedModuleDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)
		GetNtDataDirectoryPtr(hModule, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (NULL == pImportedModuleDescriptor)
	{
		return FALSE;
	}

	while (NULL != *(WORD*)pImportedModuleDescriptor)
	{
		pszModuleName = (PCHAR)((DWORD)hModule + pImportedModuleDescriptor->Name);

		pFirstThunk = (PIMAGE_THUNK_DATA)((DWORD)hModule + pImportedModuleDescriptor->FirstThunk);
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD)hModule + pImportedModuleDescriptor->OriginalFirstThunk);
		pFunctionData = (PIMAGE_IMPORT_BY_NAME)((DWORD)hModule + pOriginalFirstThunk->u1.AddressOfData);
		while (*(WORD*)pFirstThunk != 0 && *(WORD*)pOriginalFirstThunk != 0)
		{
			if (!(pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				if (TRUE == IsFunctionHooked(pszModuleName, (LPCSTR)(pFunctionData->Name), (PVOID)(pFirstThunk->u1).Function, TRUE))
				{
					DebugMsg(TEXT("Detected hook in module %S in function %S points to 0x%x"), 
						pszModuleName, (LPCSTR)(pFunctionData->Name), (PVOID)(pFirstThunk->u1).Function);
					return TRUE;
				}
			}

			pOriginalFirstThunk++;
			pFunctionData = (PIMAGE_IMPORT_BY_NAME)((DWORD)hModule + pOriginalFirstThunk->u1.AddressOfData);
			pFirstThunk++;
		}
		pImportedModuleDescriptor++;
	}
	return FALSE;
}

DWORD WINAPI DetectionThreadRoutine(
	_In_ LPVOID lpParameter
)
{
	HMODULE hModule = NULL;
	BOOL bMsgSent = FALSE;
	BOOL bIsHooked = FALSE;

	GetExeName();
	DebugMsg(TEXT("DetectionThread Started"));
	hModule = GetModuleHandleA(NULL);

	while ((FALSE == bMsgSent) && (TRUE == bKeepRunnig))
	{
		Sleep(5000);

		if (NULL == hModule)
		{
			MessageBoxA(NULL, "DetectionThreadRoutine: Module is null", "Rootkit detector", MB_OK);
		}

		if (FALSE == bIsHooked)
		{
			bIsHooked = CheckHooksInIAT(hModule);
		}

		while ((TRUE == bIsHooked) && (FALSE == bMsgSent))
		{
			//There is a hook in this module
			if (ERROR_SUCCESS == SendMessageToPipe((PWCHAR)L"Hook found"))
			{
				bMsgSent = TRUE;
				break;
			}
			Sleep(5000);
		}
	}
	DebugMsg(TEXT("DetectionThreadRoutine Exited"));
	return ERROR_SUCCESS;
}

BOOL StartDetectionThreadRoutine(
	_Out_ PHANDLE pThreadHandle,
	_Out_ PDWORD  pThreadId
)
{
	(*pThreadHandle) = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)DetectionThreadRoutine,
		NULL, // DetectionThreadRoutine lpParameter argument
		0,
		pThreadId);
	if (NULL == (*pThreadHandle))
	{
		return FALSE;
	}

	return TRUE;
}