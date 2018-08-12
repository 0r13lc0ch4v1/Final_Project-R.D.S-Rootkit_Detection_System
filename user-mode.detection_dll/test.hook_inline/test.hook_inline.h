#pragma once

BOOL HookInline(
	LPCSTR pszModuleName,
	LPCSTR pszFunctionName,
	DWORD dwAddressToHook,
	PDWORD pOldAdress
);

DWORD __cdecl MyFunction();