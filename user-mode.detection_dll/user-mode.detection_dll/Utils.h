#pragma once

#define MAX_FILE_NAME 64 

extern WCHAR ProcessName[MAX_FILE_NAME];

VOID GetExeName();

PVOID FindFirstChar(
	_In_ CONST PCHAR pszString,
	_In_ CONST DWORD dwMaxLength,
	_In_ CONST CHAR  cCharToFind,
	_Out_ PDWORD	 pdwIndex
);

VOID DebugMsg(
	CONST WCHAR* pszFormat,
	...
);