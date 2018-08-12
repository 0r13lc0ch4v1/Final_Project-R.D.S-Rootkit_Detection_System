#pragma once

#define FORWARD_DELIMITER '.'

static volatile BOOL bKeepRunnig = TRUE;

BOOL IsForwardFunction(
	_In_ CONST HMODULE hModule,
	_In_ CONST LPCSTR  pszFunctionName,
	_Out_ BOOL		   *bIsForwarded,
	_Out_ PCHAR		   *pszForwardFormat
);

BOOL SplitForwardFormat(
	_In_ CONST PCHAR pszForwardFormat,
	_Out_ PCHAR		 pszModuleName,
	_Out_ PCHAR		 pszFunctionName,
	_In_ DWORD		 dwBufferSize
);

// pszModuleName and pszFunctionName buffers must be the size of dwBufferSize.
PVOID GetFuncAddressFromForwardFormat(
	_In_ CONST PCHAR pszForwardFormat,
	_Out_ PCHAR		 pszModuleName,
	_Out_ PCHAR		 pszFunctionName,
	_In_ CONST DWORD dwBufferSize
);

BOOL IsFunctionHooked(
	_In_ CONST PCHAR  pszModuleName,
	_In_ CONST LPCSTR pszFunctionName,
	_In_ CONST PVOID  pFunctionAddress,
	_In_ CONST BOOL   bCheckInlineHook
);

BOOL CheckHooksInIAT(
	_In_ CONST HMODULE hModule
);

DWORD WINAPI DetectionThreadRoutine(
	_In_ LPVOID lpParameter
);

BOOL StartDetectionThreadRoutine(
	_Out_ PHANDLE pThreadHandle,
	_Out_ PDWORD  pThreadId
);

BOOL IsAddressInModuleRange(
	_In_ CONST PCHAR  pszModuleName,
	_In_ CONST PVOID  pFunctionAddress,
	_Out_ HMODULE *hImportedModule = NULL,
	_Out_ PDWORD dwModuleLowAddress = NULL,
	_Out_ PDWORD dwModuleHighAddress = NULL
);