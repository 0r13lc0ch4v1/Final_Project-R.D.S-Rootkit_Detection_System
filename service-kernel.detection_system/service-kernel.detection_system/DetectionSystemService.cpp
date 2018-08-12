#include "StdAfx.h"
#include "DetectionSystemService.h"


DetectionSystemService::DetectionSystemService() :
	ServiceWrapper((PWCHAR)TEXT("RdsKernelManagementService"),
	(PWCHAR)TEXT("RDS - Rootkit Detection System")),
	m_DetectionDriverConnected(FALSE), m_RdsKernelInfoHandle(INVALID_HANDLE_VALUE),
	m_RequestDriverConnected(FALSE), m_RdsKernelRequestHandle(INVALID_HANDLE_VALUE)
{
	m_hAlertHandle = CreateEvent(
		NULL,
		TRUE,
		FALSE,
		NULL);
	if (NULL == m_hAlertHandle)
	{
		DebugMsg(TEXT("DetectionSystemService - CreateEvent failed with %d."), GetLastError());
		// Quit?
	}

	if (FALSE == CreateNamedMutex(TEXT("ReadWriteMsgFromDll"), &hRWMsgFromKernelMutex))
	{
		// Quit?
	}

	CreateSecurityDescriptor(&SecurityAttributes);
}

DetectionSystemService::~DetectionSystemService()
{
	DebugMsg(TEXT("DetectionSystemService::~DetectionSystemService()"));
	if (NULL != m_hAlertHandle)
	{
		CloseHandle(m_hAlertHandle);
	}
	if (NULL != hRWMsgFromKernelMutex)
	{
		CloseHandle(hRWMsgFromKernelMutex);
	}
}

BOOL DetectionSystemService::OnInit()
{
	m_RdsKernelInfoHandle = CreateFile(
		TEXT("\\\\.\\RdsDetectionDriver"),
		GENERIC_READ,
		NULL, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL
	);
	if (INVALID_HANDLE_VALUE != m_RdsKernelInfoHandle)
	{
		m_DetectionDriverConnected = TRUE;
	}

	m_RdsKernelRequestHandle = CreateFile(
		TEXT("\\\\.\\RdsRequestDriver"),
		GENERIC_READ,
		NULL, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL
	);
	if (INVALID_HANDLE_VALUE != m_RdsKernelRequestHandle)
	{
		m_RequestDriverConnected = TRUE;
	}

	return TRUE;
}

/* The caller should close the mutex handler */
BOOL DetectionSystemService::CreateNamedMutex(
	_In_ CONST LPCWSTR pszMutexName,
	_In_ PHANDLE hMutex
)
{
	(*hMutex) = CreateMutex(NULL, FALSE, pszMutexName);
	if (NULL == (*hMutex)) {
		m_pThis->DebugMsg(TEXT("CreateMutex failed GLE=%d"), GetLastError());
		return FALSE;
	}

	return TRUE;
}

/*
* FREE MEMORY!!!!!!!!!!!!!!!!!!
*/
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446595(v=vs.85).aspx
BOOL DetectionSystemService::CreateSecurityDescriptor(
	_Out_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
	DWORD dwRes;
	PSID pEveryoneSID = NULL, pAdminSID = NULL;
	PACL pACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea[2];
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld =
		SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

	// Create a well-known SID for the Everyone group.
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pEveryoneSID))
	{
		DebugMsg(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for an ACE.
	// The ACE will allow Everyone read access to the key.
	ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = GENERIC_WRITE | GENERIC_READ;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

	// Create a SID for the BUILTIN\Administrators group.
	if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdminSID))
	{
		DebugMsg(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for an ACE.
	// The ACE will allow the Administrators group full access to
	// the key.
	ea[1].grfAccessPermissions = GENERIC_WRITE | GENERIC_READ;;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pAdminSID;

	// Create a new ACL that contains the new ACEs.
	dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);
	if (ERROR_SUCCESS != dwRes)
	{
		DebugMsg(_T("SetEntriesInAcl Error %u\n"), GetLastError());
		goto Cleanup;
	}

	// Initialize a security descriptor.  
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
		SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (NULL == pSD)
	{
		DebugMsg(_T("LocalAlloc Error %u\n"), GetLastError());
		goto Cleanup;
	}

	if (!InitializeSecurityDescriptor(pSD,
		SECURITY_DESCRIPTOR_REVISION))
	{
		DebugMsg(_T("InitializeSecurityDescriptor Error %u\n"),
			GetLastError());
		goto Cleanup;
	}

	// Add the ACL to the security descriptor. 
	if (!SetSecurityDescriptorDacl(pSD,
		TRUE,     // bDaclPresent flag   
		pACL,
		FALSE))   // not a default DACL 
	{
		DebugMsg(_T("SetSecurityDescriptorDacl Error %u\n"),
			GetLastError());
		goto Cleanup;
	}

	// Initialize a security attributes structure.
	(*lpSecurityAttributes).nLength = sizeof(SECURITY_ATTRIBUTES);
	(*lpSecurityAttributes).lpSecurityDescriptor = pSD;
	(*lpSecurityAttributes).bInheritHandle = FALSE;

Cleanup:

	//if (pEveryoneSID)
	//	FreeSid(pEveryoneSID);
	//if (pAdminSID)
	//	FreeSid(pAdminSID);
	//if (pACL)
	//	LocalFree(pACL);
	//if (pSD)
	//	LocalFree(pSD);

	return TRUE;
}

BOOL DetectionSystemService::PushMsgFromKernelToQueue(
	_In_ CONST PWCHAR pszMessage
)
{
	BOOL bReturn = TRUE;
	DWORD dwWaitResult = 0;

	//DebugMsg(TEXT("PushMsgFromKernelToQueue entered"));

	dwWaitResult = WaitForSingleObject(hRWMsgFromKernelMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		vMsgQueue.push_back(std::wstring(pszMessage));
		//DebugMsg(TEXT("PushMsgFromKernelToQueue pushed message \"%s\""), (vMsgQueue.back()).c_str());
		break;

	case WAIT_FAILED:
		//DebugMsg(TEXT("PushMsgFromKernelToQueue - WaitForSingleObject failed GLE=%d"), GetLastError());
		bReturn = FALSE;
	}
	ReleaseMutex(hRWMsgFromKernelMutex);

	return bReturn;
}

BOOL DetectionSystemService::PopMsgFromKernelToQueue(
	_Out_ std::wstring *pszMessage
)
{
	BOOL bReturn = TRUE;
	DWORD dwWaitResult = 0;

	//DebugMsg(TEXT("PopMsgFromKernelToQueue entered"));

	dwWaitResult = WaitForSingleObject(hRWMsgFromKernelMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		if (0 < vMsgQueue.size())
		{
			(*pszMessage) = vMsgQueue.back();
			vMsgQueue.pop_back();
			//DebugMsg(TEXT("PopMsgFromKernelToQueue popped message \"%s\""), (*pszMessage).c_str());
		}
		else
		{
			bReturn = FALSE; //There is no messages
		}
		break;

	case WAIT_FAILED:
		DebugMsg(TEXT("PopMsgFromKernelToQueue - WaitForSingleObject failed GLE=%d"), GetLastError());
		bReturn = FALSE;
	}
	ReleaseMutex(hRWMsgFromKernelMutex);

	return bReturn;
}

DWORD DetectionSystemService::CreatePipes(
	_In_ CONST LPCWSTR lpszPipeName,
	_In_ CONST DWORD dwNumberOfInstances,
	_In_ CONST DWORD dwState,
	_Out_ PHANDLE hEvents,
	_Out_ PPIPE_INSTANCE piPipe
)
{
	DWORD dwIndex = 0;
	DWORD dwError = ERROR_SUCCESS;

	for (dwIndex = 0; dwIndex < dwNumberOfInstances; dwIndex++)
	{
		hEvents[dwIndex] = CreateEvent(
			NULL,
			TRUE,
			TRUE,
			NULL);
		if (NULL == hEvents[dwIndex])
		{
			dwError = GetLastError();
			DebugMsg(TEXT("CreateEvent failed with %d."), dwError);
			// Close handles and continue? crash the service?
			return dwError;
		}

		piPipe[dwIndex].olOverlap = { 0 };
		piPipe[dwIndex].olOverlap.hEvent = hEvents[dwIndex];

		piPipe[dwIndex].hPipeInst = CreateNamedPipe(
			lpszPipeName,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			dwNumberOfInstances,
			PIPE_BUFFER_SIZE * sizeof(WCHAR),
			PIPE_BUFFER_SIZE * sizeof(WCHAR),
			PIPE_TIMEOUT,
			&SecurityAttributes);
		if (INVALID_HANDLE_VALUE == piPipe[dwIndex].hPipeInst)
		{
			dwError = GetLastError();
			DebugMsg(TEXT("CreateNamedPipe failed with %d."), dwError);
			// Close handles and continue? crash the service?
			return dwError;
		}

		piPipe[dwIndex].bPendingIO = ConnectToNewClient(
			piPipe[dwIndex].hPipeInst,
			&piPipe[dwIndex].olOverlap);

		piPipe[dwIndex].dwState = piPipe[dwIndex].bPendingIO ?
			CONNECTING_STATE : dwState;
	}

	return dwError;
}

DWORD DetectionSystemService::RdsUiReporterThread(
	_In_ LPVOID lpParameter)
{
	DetectionSystemService * ptrThis = (DetectionSystemService *)lpParameter;
	if (NULL == ptrThis)
	{
		return ERROR_INVALID_PARAMETER;
	}

	ptrThis->DebugMsg(TEXT("RdsUiReporterThread entered"));

	PIPE_INSTANCE piPipe[UI_PIPE_INSTANCES];
	HANDLE hEvents[UI_PIPE_INSTANCES + 1]; // +1 is for the m_hAlertHandler so the service could stop at any time and not wait for signal of some pipe.
	DWORD dwIndex = 0;
	DWORD dwWait = 0;
	DWORD dwNumberOfBytes = 0;
	DWORD dwError = ERROR_SUCCESS;
	BOOL bSuccess = FALSE;
	LPCWSTR lpszUiPipeName = (LPCWSTR)TEXT("\\\\.\\pipe\\RDS_Kernel_UI_pipe");
	std::wstring pszTmpMsg;

	pszTmpMsg.clear();

	dwError = ptrThis->CreatePipes(lpszUiPipeName, 1, WRITING_STATE, hEvents, piPipe);
	if (ERROR_SUCCESS != dwError)
	{
		ptrThis->DebugMsg(TEXT("RdsDllListenerThread - CreatePipes failed to create UI pipes."));
		return dwError;
	}
	hEvents[UI_PIPE_INSTANCES] = ptrThis->m_hAlertHandle; // The watch for service stop handle

	while (TRUE == ptrThis->m_bIsRunning)
	{
		dwWait = WaitForMultipleObjects(
			UI_PIPE_INSTANCES + 1,
			hEvents,
			FALSE,
			INFINITE);

		dwIndex = dwWait - WAIT_OBJECT_0;  // determines which pipe 
		if ((dwIndex < 0) || (dwIndex > UI_PIPE_INSTANCES - 1))
		{
			if (UI_PIPE_INSTANCES == dwIndex)
			{
				//ptrThis->DebugMsg(TEXT("RdsUiReporterThread - m_hAlertHandler was signaled"));
				SetEvent(ptrThis->m_hAlertHandle); // in case the other threads depend on this alert to finish run didn't watch for this handle yet.
			}
			else
			{
				ptrThis->DebugMsg(TEXT("RdsUiReporterThread - Index out of range."));
			}
			// Close handles and continue? crash the service?
			return dwError;
		}

		if (piPipe[dwIndex].bPendingIO)
		{
			bSuccess = GetOverlappedResult(
				piPipe[dwIndex].hPipeInst,
				&piPipe[dwIndex].olOverlap,
				&dwNumberOfBytes,
				FALSE);

			switch (piPipe[dwIndex].dwState)
			{
				// Pending connect operation 
			case CONNECTING_STATE:
				if (FALSE == bSuccess)
				{
					dwError = GetLastError();
					ptrThis->DebugMsg(TEXT("RdsUiReporterThread - GetOverlappedResult in CONNECTING_STATE GLE=%d."), dwError);
					// Close handles and continue? crash the service?
					return dwError;
				}
				piPipe[dwIndex].dwState = WRITING_STATE;
				break;

				// Pending write operation 
			case WRITING_STATE:
				if ((FALSE == bSuccess) || (0 == dwNumberOfBytes))
				{
					ptrThis->DebugMsg(TEXT("RdsUiReporterThread - GetOverlappedResult in WRITING_STATE GLE=%d."), GetLastError());
				}
				else
				{
					//ptrThis->DebugMsg(TEXT("RdsUiReporterThread - msg \"%s\" sent from queue"), piPipe[dwIndex].pbuffer);
					pszTmpMsg.clear();
				}
				ptrThis->DisconnectAndReconnect(&(piPipe[dwIndex]));
				continue;

			default:
			{
				ptrThis->DebugMsg(TEXT("RdsDllListenerThread - Invalid pipe state"));
				// Close handles and continue? crash the service?
				return dwError;
			}
			}
		}

		// The pipe state determines which operation to do next. 
		switch (piPipe[dwIndex].dwState)
		{
		case WRITING_STATE:
			if (FALSE == ptrThis->PopMsgFromKernelToQueue(&pszTmpMsg))
			{
				//ptrThis->DebugMsg(TEXT("RdsUiReporterThread - no msg in queue"));
				ptrThis->DisconnectAndReconnect(&(piPipe[dwIndex]));
				continue;
			}
			else
			{
				piPipe[dwIndex].dwNumberOfBytes = (pszTmpMsg.length() + 1) * sizeof(WCHAR);
				RtlCopyMemory(piPipe[dwIndex].pbuffer, pszTmpMsg.c_str(), piPipe[dwIndex].dwNumberOfBytes);
				pszTmpMsg.clear();
			}

			//ptrThis->DebugMsg(TEXT("RdsUiReporterThread - writing \"%s\" from queue to UI"), piPipe[dwIndex].pbuffer);
			bSuccess = WriteFile(
				piPipe[dwIndex].hPipeInst,
				piPipe[dwIndex].pbuffer,
				piPipe[dwIndex].dwNumberOfBytes,
				&dwNumberOfBytes,
				&piPipe[dwIndex].olOverlap);

			// The write operation completed successfully. 
			if ((TRUE == bSuccess) && (dwNumberOfBytes == piPipe[dwIndex].dwNumberOfBytes))
			{
				//ptrThis->DebugMsg(TEXT("RdsUiReporterThread - pop \"%s\" from queue"), piPipe[dwIndex].pbuffer);
				ptrThis->DisconnectAndReconnect(&(piPipe[dwIndex]));
				continue;
			}

			// The write operation is still pending. 
			dwError = GetLastError();
			if ((FALSE == bSuccess) && (dwError == ERROR_IO_PENDING))
			{
				piPipe[dwIndex].bPendingIO = TRUE;
				continue;
			}

			// An error occurred; disconnect from the client. 
			ptrThis->DisconnectAndReconnect(&(piPipe[dwIndex]));
			break;

		default:
		{
			ptrThis->DebugMsg(TEXT("RdsDllListenerThread - Invalid pipe state"));
			// Close handles and continue? crash the service?
			return dwError;
		}
		}
	}

	for (dwIndex = 0; dwIndex < UI_PIPE_INSTANCES; dwIndex++)
	{
		CloseHandle(piPipe[dwIndex].hPipeInst);
		CloseHandle(hEvents[dwIndex]);
	}

	return dwError;
}

VOID DetectionSystemService::DisconnectAndReconnect(
	_Inout_ PPIPE_INSTANCE piPipeInstance
)
{
	// Disconnect the pipe instance. 
	if (!DisconnectNamedPipe(piPipeInstance->hPipeInst))
	{
		DebugMsg(TEXT("DisconnectNamedPipe failed with GLE=%d"), GetLastError());
	}

	// Call a subroutine to connect to the new client. 

	piPipeInstance->bPendingIO = ConnectToNewClient(
		piPipeInstance->hPipeInst,
		&(piPipeInstance->olOverlap));

	piPipeInstance->dwState = piPipeInstance->bPendingIO ?
		CONNECTING_STATE : // still connecting 
		WRITING_STATE;     // ready to read / write
}

BOOL DetectionSystemService::ConnectToNewClient(
	_In_ CONST HANDLE hNamedPipe,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
	BOOL bConnected = FALSE;
	BOOL bPendingIO = FALSE;

	// Start an overlapped connection for this pipe instance. 
	bConnected = ConnectNamedPipe(hNamedPipe, lpOverlapped);

	// Overlapped ConnectNamedPipe should return zero. 
	if (bConnected)
	{
		DebugMsg(TEXT("ConnectNamedPipe failed with %d."), GetLastError());
		return FALSE;
	}

	switch (GetLastError())
	{
		// The overlapped connection in progress. 
	case ERROR_IO_PENDING:
		bPendingIO = TRUE;
		break;

		// Client is already connected, so signal an event. 

	case ERROR_PIPE_CONNECTED:
		if (SetEvent(lpOverlapped->hEvent))
		{
			break;
		}

		// If an error occurs during the connect operation... 
	default:
	{
		DebugMsg(TEXT("ConnectNamedPipe failed with %d."), GetLastError());
		return FALSE;
	}
	}

	return bPendingIO;
}

DWORD WINAPI DetectionSystemService::KernelDetectionThread(
	_In_ LPVOID lpParam
)
{
	OVERLAPPED						  InfoRequestOverlapped = { 0 };
	DSS_DETECTION_INFORMATION_REQUEST InfoRequest = { 0 };
	BOOL							  bReturn = FALSE;
	BOOL							  bRunning = FALSE;
	DetectionSystemService * ptrThis = (DetectionSystemService *)lpParam;
	if (NULL == ptrThis)
	{
		return ERROR_INVALID_PARAMETER;
	}

	ptrThis->DebugMsg(TEXT("DetectionSystemService::KernelDetectionThread Entered."));

	//DebugBreak();

	while (TRUE == ptrThis->m_bIsRunning)
	{
		// Sleep for a while
		//ptrThis->DebugMsg(TEXT("KernelDetectionThread is sleeping..."));
		Sleep(5000);

		if (FALSE == ptrThis->m_DetectionDriverConnected)
		{
			ptrThis->m_RdsKernelInfoHandle = CreateFile(
				TEXT("\\\\.\\RdsDetectionDriver"),
				GENERIC_READ,
				NULL, NULL, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
				NULL
			);
			if (INVALID_HANDLE_VALUE != ptrThis->m_RdsKernelInfoHandle)
			{
				ptrThis->m_DetectionDriverConnected = TRUE;
			}
			else
			{
				ptrThis->DebugMsg(TEXT("KernelDetectionThread Can't Connect to Control GLE=%d..."), GetLastError());
				continue;
			}
		}

		ZeroMemory(&InfoRequestOverlapped, sizeof(InfoRequestOverlapped));

		InfoRequestOverlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (INVALID_HANDLE_VALUE == InfoRequestOverlapped.hEvent)
		{
			continue;
		}

		ZeroMemory(&InfoRequest, sizeof(InfoRequest));
		InfoRequest.ulInformationBufferLength = sizeof(InfoRequest.pszInformationBuffer);
		bReturn = ptrThis->GetInformationFromKernel(&InfoRequest, &InfoRequestOverlapped);
		if (FALSE == bReturn)
		{
			CloseHandle(InfoRequestOverlapped.hEvent);
			continue;
		}
		else
		{
			while (FALSE == HasOverlappedIoCompleted(&InfoRequestOverlapped))
			{
				if (FALSE == ptrThis->m_bIsRunning)
				{
					goto exitStageLeft;
				}
				Sleep(100);
			}

			DWORD dwBytesTransferred;

			bRunning = GetOverlappedResult(
				ptrThis->m_RdsKernelInfoHandle,
				&InfoRequestOverlapped,
				&dwBytesTransferred,
				FALSE
			);

			_ASSERT(bRunning);

			//DebugBreak();

			//ptrThis->DebugMsg(TEXT("DetectionSystemService::GetInformationFromKernel Completed"));

			//ptrThis->DebugMsg(TEXT("From RdsDetectionDriver driver: %S"), InfoRequest.pszInformationBuffer); // This buffer is Multi-bytes.
			if ((0 != (InfoRequest.ulInformationBufferLength)) &&
				('\0' != (InfoRequest.pszInformationBuffer)[0]))
			{
				WCHAR msg[INFORMATION_BUFFER_LENGTH] = { 0 };
				MultiByteToWideChar(CP_UTF8, 0, InfoRequest.pszInformationBuffer, -1, msg, INFORMATION_BUFFER_LENGTH);
				ptrThis->PushMsgFromKernelToQueue(msg);
			}

			//ResetEvent(InfoRequestOverlapped.hEvent);

			CloseHandle(InfoRequestOverlapped.hEvent);
		}
	}

exitStageLeft:

	if (INVALID_HANDLE_VALUE != ptrThis->m_RdsKernelInfoHandle)
	{
		CloseHandle(ptrThis->m_RdsKernelInfoHandle);
		ptrThis->m_RdsKernelInfoHandle = INVALID_HANDLE_VALUE;
		ptrThis->m_DetectionDriverConnected = FALSE;
	}
	return ERROR_SUCCESS;
}

DWORD WINAPI DetectionSystemService::HandleKernelRequestThread(
	_In_ LPVOID lpParam
)
{
	OVERLAPPED						  InfoRequestOverlapped = { 0 };
	DSS_DETECTION_INFORMATION_REQUEST KernelRequest = { 0 };
	BOOL							  bReturn = FALSE;
	BOOL							  bRunning = FALSE;
	DetectionSystemService			  *ptrThis = (DetectionSystemService *)lpParam;
	if (NULL == ptrThis)
	{
		return ERROR_INVALID_PARAMETER;
	}

	//ptrThis->DebugMsg(TEXT("HandleKernelRequestThread Entered."));

	//DebugBreak();

	while (TRUE == ptrThis->m_bIsRunning)
	{
		// Sleep for a while
		//ptrThis->DebugMsg(TEXT("HandleKernelRequestThread is sleeping..."));
		Sleep(1000);

		if (FALSE == ptrThis->m_RequestDriverConnected)
		{
			ptrThis->m_RdsKernelRequestHandle = CreateFile(
				TEXT("\\\\.\\RdsRequestDriver"),
				GENERIC_READ,
				NULL, NULL, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
				NULL
			);
			if (INVALID_HANDLE_VALUE != ptrThis->m_RdsKernelRequestHandle)
			{
				ptrThis->m_DetectionDriverConnected = TRUE;
			}
			else
			{
				ptrThis->DebugMsg(TEXT("HandleKernelRequestThread Can't Connect to Control GLE=%d..."), GetLastError());
				continue;
			}
		}

		ZeroMemory(&InfoRequestOverlapped, sizeof(InfoRequestOverlapped));

		InfoRequestOverlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (INVALID_HANDLE_VALUE == InfoRequestOverlapped.hEvent)
		{
			continue;
		}

		ZeroMemory(&KernelRequest, sizeof(KernelRequest));
		KernelRequest.ulInformationBufferLength = sizeof(KernelRequest.pszInformationBuffer);
		bReturn = ptrThis->GetRequestFromKernel(&KernelRequest, &InfoRequestOverlapped);
		if (FALSE == bReturn)
		{
			CloseHandle(InfoRequestOverlapped.hEvent);
			continue;
		}
		else
		{
			while (FALSE == HasOverlappedIoCompleted(&InfoRequestOverlapped))
			{
				if (FALSE == ptrThis->m_bIsRunning)
				{
					goto exitStageLeft;
				}
				Sleep(100);
			}

			DWORD dwBytesTransferred;

			bRunning = GetOverlappedResult(
				ptrThis->m_RdsKernelRequestHandle,
				&InfoRequestOverlapped,
				&dwBytesTransferred,
				FALSE
			);

			_ASSERT(bRunning);

			//DebugBreak();
			//ptrThis->DebugMsg(TEXT("HandleKernelRequestThread: GetRequestFromKernel Completed"));
			//ptrThis->DebugMsg(TEXT("From RdsRequestDriver driver: %S"), KernelRequest.pszInformationBuffer);// This buffer is Multi-bytes.

			ResetEvent(InfoRequestOverlapped.hEvent);
			/*
			 * Parse the driver request and respond to it.
			 * TO-DO: Mechanism to handle multiple requests
			 */
			ZeroMemory(KernelRequest.pszInformationBuffer, 20);
			StringCchCopyA(KernelRequest.pszInformationBuffer, 100, "Hello from Service");
			size_t pcch = 0;
			StringCchLengthA(
				"Hello from Service",
				20,
				&pcch
			);
			KernelRequest.ulInformationBufferLength = pcch;

			bReturn = ptrThis->SendResponseToKernel(&KernelRequest, &InfoRequestOverlapped);
			if (FALSE == bReturn)
			{
				//DebugBreak();
				CloseHandle(InfoRequestOverlapped.hEvent);
				continue;
			}
			else
			{
				while (FALSE == HasOverlappedIoCompleted(&InfoRequestOverlapped))
				{
					if (FALSE == ptrThis->m_bIsRunning)
					{
						goto exitStageLeft;
					}
					Sleep(100);
				}

				//ptrThis->DebugMsg(TEXT("DetectionSystemService: SendResponseToKernel Completed"));

				CloseHandle(InfoRequestOverlapped.hEvent);
			}
		}
	}

exitStageLeft:

	if (INVALID_HANDLE_VALUE != ptrThis->m_RdsKernelRequestHandle)
	{
		CloseHandle(ptrThis->m_RdsKernelRequestHandle);
		ptrThis->m_RdsKernelRequestHandle = INVALID_HANDLE_VALUE;
		ptrThis->m_DetectionDriverConnected = FALSE;
	}
	return ERROR_SUCCESS;
}

VOID DetectionSystemService::Run()
{
	DebugMsg(TEXT("DetectionSystemService Run entered"));

	hThreadArray[0] = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)DetectionSystemService::KernelDetectionThread,
		(PVOID)this,
		0,
		&dwThreadIdArray[0]
	);
	if (hThreadArray[0] == NULL)
	{
		DebugMsg(TEXT("DetectionSystemService failed to create KernelDetectionThread thread GLE=%d"), GetLastError());
		return;
	}

	hThreadArray[1] = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)DetectionSystemService::HandleKernelRequestThread,
		(PVOID)this,
		0,
		&dwThreadIdArray[1]
	);
	if (hThreadArray[1] == NULL)
	{
		DebugMsg(TEXT("DetectionSystemService failed to create HandleKernelRequestThread thread GLE=%d"), GetLastError());
		return;
	}

	hThreadArray[2] = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)DetectionSystemService::RdsUiReporterThread,
		(PVOID)this,
		0,
		&dwThreadIdArray[2]
	);
	if (hThreadArray[2] == NULL)
	{
		DebugMsg(TEXT("DetectionSystemService failed to create RdsUiReporterThread thread GLE=%d"), GetLastError());
		return;
	}

	WaitForMultipleObjects(2, hThreadArray, TRUE, INFINITE);

	for (int i = 0; i < 3; i++)
	{
		CloseHandle(hThreadArray[i]);
	}
}

BOOL DetectionSystemService::OnUserControl(
	_In_ CONST DWORD dwOpcode
)
{
	switch (dwOpcode)
	{
	case (DWORD)SERVICE_CONTROL_USER:
		DebugMsg(TEXT("KernelDetectionSystemService::OnUserControl"));
		return TRUE;

	default:
		break;
	}

	return FALSE;
}

VOID DetectionSystemService::OnDeviceEvent(
	_In_ CONST DWORD  dwEventType,
	_In_ CONST LPVOID lpEventData
)
{
	PDEV_BROADCAST_DEVICEINTERFACE pBroadcastInterface = (PDEV_BROADCAST_DEVICEINTERFACE)lpEventData;

	switch (dwEventType)
	{
	case DBT_DEVICEARRIVAL:
		DebugMsg(TEXT("DetectionSystemService::OnDeviceEvent - Arrival %ls"), &pBroadcastInterface->dbcc_name[0]);
		break;

	case DBT_DEVICEREMOVECOMPLETE:
		DebugMsg(TEXT("DetectionSystemService::OnDeviceEvent - Removal %ls"), &pBroadcastInterface->dbcc_name[0]);
		break;

	default:
		break;
	}
}

BOOL DetectionSystemService::GetInformationFromKernel(
	_In_ CONST PDSS_DETECTION_INFORMATION_REQUEST pRequest,
	_In_ CONST LPOVERLAPPED                       pOverlapped
)
{
	BOOL  bStatus = FALSE;
	DWORD dwBytesReturned = 0;

	//DebugMsg(TEXT("DetectionSystemService::GetInformationFromKernel - Entered"));

	bStatus = DeviceIoControl(
		m_RdsKernelInfoHandle,
		(DWORD)KDD_COMMUNICATION_GET_INFORMATION,
		pRequest, sizeof(DSS_DETECTION_INFORMATION_REQUEST),
		pRequest, sizeof(DSS_DETECTION_INFORMATION_REQUEST),
		&dwBytesReturned,
		pOverlapped
	);
	if (FALSE == bStatus) {

		DWORD dwError = GetLastError();

		if (ERROR_IO_PENDING != dwError)
		{
			DebugMsg(TEXT("DetectionSystemService::GetInformationFromKernel - Status GLE=%d"), dwError);
			return FALSE;
		}
		else
		{
			DebugMsg(TEXT("DetectionSystemService::GetInformationFromKernel Pending"));
		}
	}

	//DebugMsg(TEXT("DetectionSystemService::GetInformationFromKernel - Exit."));

	return TRUE;
}

BOOL DetectionSystemService::GetRequestFromKernel(
	_In_ CONST PDSS_DETECTION_DRIVER_REQUEST pRequest,
	_In_ CONST LPOVERLAPPED                  pOverlapped
)
{
	BOOL  bStatus = FALSE;
	DWORD dwBytesReturned = 0;

	//DebugMsg(TEXT("DetectionSystemService::GetRequestFromKernel - Entered"));

	bStatus = DeviceIoControl(
		m_RdsKernelRequestHandle,
		(DWORD)KDD_COMMUNICATION_GET_REQUEST,
		pRequest, sizeof(DSS_DETECTION_DRIVER_REQUEST),
		pRequest, sizeof(DSS_DETECTION_DRIVER_REQUEST),
		&dwBytesReturned,
		pOverlapped
	);
	if (FALSE == bStatus) {

		DWORD dwError = GetLastError();

		if (ERROR_IO_PENDING != dwError)
		{
			DebugMsg(TEXT("DetectionSystemService::GetRequestFromKernel - Status GLE=%d"), dwError);
			return FALSE;
		}
		else
		{
			DebugMsg(TEXT("DetectionSystemService::GetRequestFromKernel Pending"));
		}
	}

	//DebugMsg(TEXT("DetectionSystemService::GetRequestFromKernel - Exit."));

	return TRUE;
}

BOOL DetectionSystemService::SendResponseToKernel(
	_In_ CONST PDSS_DETECTION_DRIVER_RESPONSE pResponse,
	_In_ CONST LPOVERLAPPED                   pOverlapped
)
{
	BOOL  bStatus = FALSE;
	DWORD dwBytesReturned = 0;

	//DebugMsg(TEXT("DetectionSystemService::SendResponseToKernel - Entered"));

	bStatus = DeviceIoControl(
		m_RdsKernelRequestHandle,
		(DWORD)KDD_COMMUNICATION_SEND_RESPONSE,
		pResponse, sizeof(DSS_DETECTION_DRIVER_RESPONSE),
		NULL, 0,
		&dwBytesReturned,
		pOverlapped
	);
	if (FALSE == bStatus) {

		DWORD dwError = GetLastError();

		if (ERROR_IO_PENDING != dwError)
		{
			DebugMsg(TEXT("DetectionSystemService::SendResponseToKernel - Status GLE=%d"), dwError);
			return FALSE;
		}
		else
		{
			DebugMsg(TEXT("DetectionSystemService::SendResponseToKernel Pending"));
		}
	}

	//DebugMsg(TEXT("DetectionSystemService::SendResponseToKernel - Exit."));

	return TRUE;
}