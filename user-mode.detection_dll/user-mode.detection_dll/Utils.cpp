#include "stdafx.h"
#include "Shlwapi.h"
#pragma comment (lib, "Shlwapi.lib")
#include "Utils.h"

WCHAR ProcessName[MAX_FILE_NAME] = { NULL };

VOID GetExeName()
{
	WCHAR pszExePath[MAX_PATH + 1] = { NULL };
	PWCHAR pszExeNamePtr = nullptr;
	DWORD pszExePathLength = 0;

	pszExePathLength = GetModuleFileNameW(NULL, pszExePath, MAX_PATH);
	if (0 < pszExePathLength)
	{
		pszExeNamePtr = PathFindFileName(pszExePath);
		StringCchCat((PWCHAR)ProcessName, MAX_FILE_NAME, pszExeNamePtr);
	}
}

PVOID FindFirstChar(
	_In_ CONST PCHAR pszString,
	_In_ CONST DWORD dwMaxLength,
	_In_ CONST CHAR  cCharToFind,
	_Out_ PDWORD	 pdwIndex
)
{
	DWORD dwIndex = 0;

	for (dwIndex = 0; (dwIndex < dwMaxLength) && (NULL != pszString[dwIndex]); dwIndex++)
	{
		if (cCharToFind == pszString[dwIndex])
		{
			(*pdwIndex) = dwIndex;
			return (PVOID)pszString[dwIndex];
		}
	}

	return NULL;
}

VOID DebugMsg(
	CONST WCHAR* pszFormat,
	...
)
{
	WCHAR pBuffer[1024];
	StringCchPrintf(pBuffer, 1024, TEXT("[RDS-dll][%ls](%lu): "), ProcessName, GetCurrentThreadId());
	va_list arglist;
	va_start(arglist, pszFormat);
	// Check the pBuffer size calculation
	StringCchVPrintf(&pBuffer[wcslen(pBuffer)], 1024 - wcslen(pBuffer), pszFormat, arglist);
	va_end(arglist);
	StringCchCat(pBuffer, 1024, TEXT("\n"));
	OutputDebugString(pBuffer);
}