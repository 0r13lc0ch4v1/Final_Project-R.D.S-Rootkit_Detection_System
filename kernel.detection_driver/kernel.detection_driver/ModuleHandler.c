#include "RootkitDetection.h"
#include "ModuleHandler.h"


PIMAGE_DOS_HEADER GetModuleNtDosHeaderPtr(
	_In_ CONST HMODULE hModule
)
{
	PIMAGE_DOS_HEADER pModuleDosHeader = NULL;

	if (NULL == hModule)
	{
		return NULL;
	}

	pModuleDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (IMAGE_DOS_SIGNATURE != pModuleDosHeader->e_magic)
	{
		return NULL;
	}

	return pModuleDosHeader;
}

PIMAGE_NT_HEADERS GetModuleNtHeadersPtr(
	_In_ CONST HMODULE hModule
)
{
	PIMAGE_DOS_HEADER pModuleDosHeader = NULL;
	PIMAGE_NT_HEADERS pModuleNtHeaders = NULL;

	pModuleDosHeader = GetModuleNtDosHeaderPtr(hModule);
	if (NULL == pModuleDosHeader)
	{
		return NULL;
	}

	pModuleNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)hModule + (DWORD)(pModuleDosHeader->e_lfanew));
	if (IMAGE_NT_SIGNATURE != (DWORD)pModuleNtHeaders->Signature)
	{
		return NULL;
	}

	return pModuleNtHeaders;
}

PIMAGE_OPTIONAL_HEADER GetNtOptionalHeaderPtr(
	_In_ CONST HMODULE hModule
)
{
	PIMAGE_NT_HEADERS pModuleNtHeaders = NULL;
	PIMAGE_OPTIONAL_HEADER pNtOptionalHeader = NULL;

	pModuleNtHeaders = GetModuleNtHeadersPtr(hModule);
	if (NULL == pModuleNtHeaders)
	{
		return NULL;
	}

	pNtOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(&(pModuleNtHeaders->OptionalHeader));
	if ((NULL == pNtOptionalHeader) ||
		(IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNtOptionalHeader->Magic))
	{
		return NULL;
	}

	return pNtOptionalHeader;
}

PVOID GetNtDataDirectoryPtr(
	_In_ CONST HMODULE hModule,
	_In_ CONST DWORD   dwDirectoryIndex
)
{
	PVOID pDataDirectory = NULL;
	PIMAGE_OPTIONAL_HEADER pNtOptionalHeader = NULL;
	IMAGE_DATA_DIRECTORY pImageDataDirectory = { 0 };

	if (dwDirectoryIndex >= (DWORD)IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
	{
		return NULL;
	}

	pNtOptionalHeader = GetNtOptionalHeaderPtr(hModule);
	if (NULL == pNtOptionalHeader)
	{
		return NULL;
	}

	pImageDataDirectory = pNtOptionalHeader->DataDirectory[dwDirectoryIndex];
	if ((0 == pImageDataDirectory.VirtualAddress) ||
		(0 == pImageDataDirectory.Size))
	{
		return NULL;
	}

	pDataDirectory = (PVOID)((DWORD)hModule + pImageDataDirectory.VirtualAddress);

	return pDataDirectory;
}

DWORD GetSizeOfImage(
	_In_ CONST HMODULE hModule
)
{
	PIMAGE_OPTIONAL_HEADER pNtOptionalHeader = NULL;

	pNtOptionalHeader = GetNtOptionalHeaderPtr(hModule);
	if (NULL == pNtOptionalHeader)
	{
		return (DWORD)0;
	}

	return pNtOptionalHeader->SizeOfImage;
}

DWORD GetImageBase(
	_In_ CONST HMODULE hModule
)
{
	PIMAGE_OPTIONAL_HEADER pNtOptionalHeader = NULL;

	pNtOptionalHeader = GetNtOptionalHeaderPtr(hModule);
	if (NULL == pNtOptionalHeader)
	{
		return (DWORD)0;
	}

	return pNtOptionalHeader->ImageBase;
}

BOOL GetDataDirectoryRange(
	_In_ CONST HMODULE hModule,
	_In_ CONST DWORD   dwDirectoryIndex,
	_Out_ PDWORD	   pdwLowAddress,
	_Out_ PDWORD	   pdwHighAddress
)
{
	PIMAGE_OPTIONAL_HEADER pNtOptionalHeader = NULL;
	IMAGE_DATA_DIRECTORY pImageDataDirectory = { 0 };

	if ((dwDirectoryIndex >= (DWORD)IMAGE_NUMBEROF_DIRECTORY_ENTRIES) ||
		(NULL == pdwLowAddress) ||
		(NULL == pdwHighAddress))
	{
		return FALSE;
	}

	pNtOptionalHeader = GetNtOptionalHeaderPtr(hModule);
	if (NULL == pNtOptionalHeader)
	{
		return FALSE;
	}

	pImageDataDirectory = pNtOptionalHeader->DataDirectory[dwDirectoryIndex];
	if ((0 == pImageDataDirectory.VirtualAddress) ||
		(0 == pImageDataDirectory.Size))
	{
		return FALSE;
	}

	(*pdwLowAddress) = (DWORD)hModule + pImageDataDirectory.VirtualAddress;
	(*pdwHighAddress) = (*pdwLowAddress) + pImageDataDirectory.Size;

	return TRUE;
}

PVOID GetFuncAddressFromExport(
	_In_ CONST HMODULE hModule,
	_In_ CONST LPCSTR pszFunctionName
)
{
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PDWORD pAddressOfFunctions = NULL;
	PDWORD pAddressOfNames = NULL;
	PWORD AddressOfNameOrdinals = NULL;
	DWORD dwIndex = 0;
	PCHAR pszTmpFunctionName = NULL;

	if (!hModule)
	{
		return NULL;
	}

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		GetNtDataDirectoryPtr(hModule, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (NULL == pExportDirectory)
	{
		return NULL;
	}

	pAddressOfFunctions = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfFunctions);
	pAddressOfNames = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNames);
	AddressOfNameOrdinals = (PWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);

	for (dwIndex = 0; dwIndex < pExportDirectory->AddressOfFunctions; dwIndex++)
	{
		pszTmpFunctionName = (PCHAR)((DWORD)hModule + pAddressOfNames[dwIndex]);
		if (0 == strcmp(pszFunctionName, pszTmpFunctionName))
		{
			return (PVOID)((DWORD)hModule + pAddressOfFunctions[AddressOfNameOrdinals[dwIndex]]);
		}
	}

	return NULL;
}

PCHAR GetFuncNameByAddressFromExport(
	_In_ CONST HMODULE hModule,
	_In_ CONST PVOID pszFuncAddress
)
{
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PDWORD pAddressOfFunctions = NULL;
	PDWORD pAddressOfNames = NULL;
	PWORD AddressOfNameOrdinals = NULL;
	DWORD dwIndex = 0;

	if (!hModule)
	{
		return NULL;
	}

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		GetNtDataDirectoryPtr(hModule, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (NULL == pExportDirectory)
	{
		return NULL;
	}

	pAddressOfFunctions = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfFunctions);
	pAddressOfNames = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNames);
	AddressOfNameOrdinals = (PWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);

	for (dwIndex = 0; dwIndex < pExportDirectory->AddressOfFunctions; dwIndex++)
	{
		if (pszFuncAddress == (PVOID)((DWORD)hModule + pAddressOfFunctions[AddressOfNameOrdinals[dwIndex]]))
		{
			return (PCHAR)((DWORD)hModule + pAddressOfNames[dwIndex]);
		}
	}

	return NULL;
}