// test.hook_iat.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "test.hook_iat.h"

VOID RewriteThunk(
	PIMAGE_THUNK_DATA pThunk,
	DWORD newFunc,
	DWORD *oldFunc
)
{
	DWORD CurrentProtect;
	DWORD junk;

	VirtualProtect(pThunk, 4096, PAGE_READWRITE, &CurrentProtect);
	if (oldFunc != NULL)
	{
		*oldFunc = pThunk->u1.Function;
	}
	pThunk->u1.Function = newFunc;
	VirtualProtect(pThunk, 4096, CurrentProtect, &junk);
}

PIMAGE_IMPORT_DESCRIPTOR GetImportTable(
	HMODULE hInstance
)
{
	PIMAGE_DOS_HEADER dosHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
	PIMAGE_NT_HEADERS ntHeader;
	IMAGE_DATA_DIRECTORY dataDirectory;

	dosHeader = (PIMAGE_DOS_HEADER)hInstance;
	ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);
	optionalHeader = (ntHeader->OptionalHeader);
	dataDirectory = (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hInstance + dataDirectory.VirtualAddress);
}

BOOL HookIAT(
	HMODULE hInstance, 
	LPCSTR targetFunction,
	DWORD newFunc,
	DWORD *oldFunc
)
{
	PIMAGE_IMPORT_DESCRIPTOR importedModule;
	PIMAGE_THUNK_DATA pFirstThunk, pOriginalFirstThunk;
	PIMAGE_IMPORT_BY_NAME pFuncData;

	importedModule = GetImportTable(hInstance);
	while (*(WORD*)importedModule != 0)
	{
		pFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)hInstance + importedModule->FirstThunk);
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)hInstance + importedModule->OriginalFirstThunk);
		pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hInstance + pOriginalFirstThunk->u1.AddressOfData);
		while (*(WORD*)pFirstThunk != 0 && *(WORD*)pOriginalFirstThunk != 0)
		{
			if (!(pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) && strcmp(targetFunction, (char*)pFuncData->Name) == 0)
			{
				RewriteThunk(pFirstThunk, newFunc, NULL);
				return TRUE;
			}

			pOriginalFirstThunk++; 
			pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hInstance + pOriginalFirstThunk->u1.AddressOfData);
			pFirstThunk++;
		}
		importedModule++;
	}

	return FALSE;
}