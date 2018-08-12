#include "stdafx.h"
#include "IpcPipeClient.h"

VOID FlashPipe(
	_In_ CONST HANDLE hPipe
)
{
	BOOL bReadFileSuccess = FALSE;
	CHAR pBuffer[MSG_BUFFER_SIZE] = { 0 };
	DWORD dwNumberOfbytesRead = 0;

	do
	{
		bReadFileSuccess = ReadFile(hPipe, pBuffer, MSG_BUFFER_SIZE, &dwNumberOfbytesRead, NULL);
		if ((FALSE == bReadFileSuccess) && (GetLastError() != ERROR_MORE_DATA))
		{
			break;
		}
	} while (FALSE == bReadFileSuccess);  // repeat loop if ERROR_MORE_DATA 
}

DWORD CreatePipe(
	_In_ CONST LPCTSTR pszPipeName,
	_Out_ PHANDLE hPipe
)
{
	if (NULL == hPipe)
	{
		return ERROR_FAILURE;
	}
	(*hPipe) = INVALID_HANDLE_VALUE;

	/* Try connect to the pipe */
	while (TRUE) {
		(*hPipe) = CreateFile(pszPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (INVALID_HANDLE_VALUE != (*hPipe))
		{
			break;
		}
		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			return ERROR_FAILURE;
		}

		if (FALSE == WaitNamedPipe(pszPipeName, 5000))
		{
			return ERROR_FAILURE;
		}
	}

	return ERROR_SUCCESS;
}

DWORD SendMessageToPipe(
	_In_ CONST PWCHAR pszMessage
)
{
	CONST LPCTSTR pszPipeName = TEXT("\\\\.\\pipe\\RDS_DLL_pipe");
	DWORD dwMessageLength = 0;
	DWORD dwNumberOfBytesToWrite = 0;
	DWORD dwMode = 0;
	DWORD dwReturn = ERROR_SUCCESS;
	HANDLE hPipe = INVALID_HANDLE_VALUE;

	if (ERROR_FAILURE == CreatePipe(pszPipeName, &hPipe))
	{
		return ERROR_FAILURE;
	}

	/* After a connection were made */
	dwMode = PIPE_READMODE_MESSAGE;
	if (FALSE == SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL))
	{
		dwReturn = ERROR_FAILURE;
		goto ExitStageLeft;
	}

	dwMessageLength = (DWORD)((lstrlen(pszMessage) + 1) * sizeof(WCHAR));
	if ((FALSE == WriteFile(hPipe, pszMessage, dwMessageLength, &dwNumberOfBytesToWrite, NULL)) ||
		(dwNumberOfBytesToWrite != dwMessageLength))
	{
		dwReturn = ERROR_FAILURE;
		goto ExitStageLeft;
	}

ExitStageLeft:

	FlashPipe(hPipe);
	CloseHandle(hPipe);

	return dwReturn;
}
