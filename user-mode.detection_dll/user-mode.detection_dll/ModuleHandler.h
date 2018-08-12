#pragma once


PIMAGE_DOS_HEADER GetModuleNtDosHeaderPtr(
	_In_ CONST HMODULE hModule
);

PIMAGE_NT_HEADERS GetModuleNtHeadersPtr(
	_In_ CONST HMODULE hModule
);

PIMAGE_OPTIONAL_HEADER GetNtOptionalHeaderPtr(
	_In_ CONST HMODULE hModule
);

PVOID GetNtDataDirectoryPtr(
	_In_ CONST HMODULE hModule,
	_In_ CONST DWORD   dwDirectoryIndex
);

DWORD GetSizeOfImage(
	_In_ CONST HMODULE hModule
);

DWORD GetImageBase(
	_In_ CONST HMODULE hModule
);

BOOL GetDataDirectoryRange(
	_In_ CONST HMODULE hModule,
	_In_ CONST DWORD   dwDirectoryIndex,
	_Out_ PDWORD       pdwLowAddress,
	_Out_ PDWORD       pdwHighAddress
);

PVOID GetFuncAddressFromExport(
	_In_ CONST HMODULE hModule,
	_In_ CONST LPCSTR pszFunctionName
);