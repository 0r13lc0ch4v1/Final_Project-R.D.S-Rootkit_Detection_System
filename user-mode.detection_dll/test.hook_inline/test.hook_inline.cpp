// test.hook_inline.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "test.hook_inline.h"

// Only for address to jump to
DWORD __cdecl MyFunction()
{
	MessageBoxA(NULL, "This function is inline hooked!", "The hooking module", MB_OK);
	return (DWORD)1;
}

#pragma pack(1)
typedef struct _PATCH
{
	BYTE nPatchType;
	DWORD dwAddress;
}	PATCH, PPATCH;
#pragma pack()

BOOL HookInline(
	LPCSTR pszModuleName,
	LPCSTR pszFunctionName,
	DWORD dwAddressToHook,
	PDWORD pOldAdress
)
{
	FARPROC fpFunctionAddress = nullptr;

	fpFunctionAddress = GetProcAddress(LoadLibraryA(pszModuleName), pszFunctionName);
	if (nullptr == fpFunctionAddress)
	{
		return FALSE;
	}

	if (nullptr != pOldAdress)
	{
		*pOldAdress = (DWORD)fpFunctionAddress;
	}

	DWORD dwOldProt = 0;
	if (FALSE == VirtualProtect(fpFunctionAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		return FALSE;
	}

	DWORD dwJmpTo = (dwAddressToHook - (DWORD)fpFunctionAddress - 5);

	PATCH pPatchToWrite =
	{
		(BYTE)0xe9,
		dwJmpTo
	};

	RtlCopyMemory(fpFunctionAddress, &pPatchToWrite, sizeof(pPatchToWrite));

	return VirtualProtect(fpFunctionAddress, 5, dwOldProt, &dwOldProt);
}