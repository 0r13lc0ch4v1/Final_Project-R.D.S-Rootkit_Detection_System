#pragma once

#define MSG_BUFFER_SIZE (1 << 10)
#define ERROR_FAILURE 1

VOID FlashPipe(
	_In_ CONST HANDLE hPipe
);

DWORD CreatePipe(
	_In_ CONST LPCTSTR pszPipeName,
	_Out_ PHANDLE hPipe
);

DWORD SendMessageToPipe(
	_In_ PWCHAR pszMessage
);