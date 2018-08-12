#include "stdafx.h"
#include "IpcPipeClient.h"

VOID FlashPipe(
	_In_ CONST HANDLE hPipe
)
{
	BOOL bReadFileSuccess = FALSE;
	WCHAR pBuffer[MSG_BUFFER_SIZE] = { 0 };
	DWORD dwNumberOfbytesRead = 0;

	do
	{
		bReadFileSuccess = ReadFile(hPipe, pBuffer, MSG_BUFFER_SIZE * sizeof(WCHAR), &dwNumberOfbytesRead, NULL);
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
		(*hPipe) = CreateFile(pszPipeName, 
			GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING, 0, NULL);
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

DWORD ReceiveMessageFromPipe(
	_In_ CONST LPCTSTR pszPipeName,
	_In_ PWCHAR pszMessage
)
{
	DWORD dwMessageLength = 0;
	DWORD dwNumberOfBytesToRead = 0;
	DWORD dwMode = 0;
	DWORD dwReturn = ERROR_SUCCESS;
	HANDLE hPipe = INVALID_HANDLE_VALUE;

	if (ERROR_FAILURE == CreatePipe(pszPipeName, &hPipe) || 
		INVALID_HANDLE_VALUE == hPipe)
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

	if (FALSE == ReadFile(hPipe, pszMessage, MSG_BUFFER_SIZE * sizeof(WCHAR), &dwNumberOfBytesToRead, NULL) ||
		0 == dwNumberOfBytesToRead)
	{
		dwReturn = ERROR_FAILURE;
		goto ExitStageLeft;
	}
	
	FlashPipe(hPipe);
ExitStageLeft:
	CloseHandle(hPipe);

	return dwReturn;
}
