#include "RootkitDetection.h"
#include "Undocumented.h"

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID  MappedBase;
	PVOID  ImageBase;
	ULONG  ImageSize;
	ULONG  Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAX_PATH];
}	SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11,
	SystemKernelDebuggerInformation = 35
}	SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG				Count;
	SYSTEM_MODULE_ENTRY Module[1];
}	SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(NTAPI* pZwQuerySystemInformation)(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_ PVOID		 SystemInformation,
	_In_ ULONG		 SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

static pZwQuerySystemInformation ZwQuerySystemInformation = NULL;

BOOLEAN StringToStringStruct(
	_In_ CONST PCHAR pszString,
	_Out_ PSTRING strStringStruct
)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	size_t ulStringLength = 0;

	NtStatus = RtlStringCbLengthA(
		pszString,
		MAX_PATH,
		&ulStringLength
	);
	if (!NT_SUCCESS(NtStatus))
	{
		return FALSE;
	}

	strStringStruct->Length = (USHORT)ulStringLength;
	strStringStruct->MaximumLength = MAX_PATH;
	strStringStruct->Buffer = pszString;

	return TRUE;
}

// Based on: http://alter.org.ua/docs/nt_kernel/procaddr
PVOID KernelGetModuleBase(
	_In_ CONST PCHAR pModuleName,
	_Out_ PULONG ulImageSize
)
{
	PVOID pModuleBase = NULL;
	PULONG pSystemInfoBuffer = NULL;
	UNICODE_STRING usRoutineName = { 0 };
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	ULONG SystemInfoBufferSize = 0;
	STRING strCurrentModuleName = { 0 };
	STRING strModuleName = { 0 };
	PSYSTEM_MODULE_ENTRY pSysModuleEntry = NULL;
	ULONG ulIndex = 0;

	if (NULL == ZwQuerySystemInformation)
	{
		RtlInitUnicodeString(&usRoutineName, L"ZwQuerySystemInformation");
		ZwQuerySystemInformation = (pZwQuerySystemInformation)
			MmGetSystemRoutineAddress(&usRoutineName);
		if (NULL == ZwQuerySystemInformation)
		{
			return NULL;
		}
	}

	try
	{
		StringToStringStruct(pModuleName, &strModuleName);

		status = ZwQuerySystemInformation(
			SystemModuleInformation,
			&SystemInfoBufferSize,
			0,
			&SystemInfoBufferSize);
		if (0 == SystemInfoBufferSize)
		{
			return NULL;
		}

		pSystemInfoBuffer = (PULONG)ExAllocatePool(NonPagedPool, SystemInfoBufferSize * 2);

		if (NULL == pSystemInfoBuffer)
		{
			return NULL;
		}

		RtlZeroMemory(pSystemInfoBuffer, SystemInfoBufferSize * 2);

		status = ZwQuerySystemInformation(
			SystemModuleInformation,
			pSystemInfoBuffer,
			SystemInfoBufferSize * 2,
			&SystemInfoBufferSize);
		if (NT_SUCCESS(status))
		{
			pSysModuleEntry = ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Module;

			for (ulIndex = 0; ulIndex < ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Count; ulIndex++)
			{
				StringToStringStruct((PCHAR)(pSysModuleEntry[ulIndex].FullPathName +
					pSysModuleEntry[ulIndex].OffsetToFileName),
					&strCurrentModuleName);

				if (TRUE == RtlEqualString(
					&strCurrentModuleName,
					&strModuleName,
					FALSE))
				{
					pModuleBase = pSysModuleEntry[ulIndex].ImageBase;
					(*ulImageSize) = pSysModuleEntry[ulIndex].ImageSize;
					break;
				}
			}
		}
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		pModuleBase = NULL;
	}
	if (NULL != pSystemInfoBuffer)
	{
		ExFreePool(pSystemInfoBuffer);
	}

	return pModuleBase;
}