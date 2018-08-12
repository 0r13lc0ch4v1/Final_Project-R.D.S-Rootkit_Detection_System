#include "StdAfx.h"
#include "DetectionSystemService.h"

DetectionSystemService* DetectionSystemService::m_pDssThis = NULL;

DetectionSystemService::DetectionSystemService() :
	ServiceWrapper((PWCHAR)TEXT("RdsUserModeManagementService"),
	(PWCHAR)TEXT("RDS - Rootkit Detection System"))
{
	// copy the address of the current object so we can access it from
	// the static member callback functions. 
	// WARNING: This limits the application to only one ServiceWrapper object. 
	m_pDssThis = this;

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

	if (FALSE == CreateNamedMutex(TEXT("ReadWriteMsgFromDll"), &hRWMsgFromDllMutex))
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
	if (NULL != hRWMsgFromDllMutex)
	{
		CloseHandle(hRWMsgFromDllMutex);
	}
}

BOOL DetectionSystemService::OnUserControl(
	_In_ CONST DWORD dwOpcode
)
{
	switch (dwOpcode)
	{
	case (DWORD)SERVICE_CONTROL_USER:
		DebugMsg(TEXT("UserModeDetectionSystemService::OnUserControl"));
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

BOOL DetectionSystemService::PushMsgFromDllToQueue(
	_In_ CONST PWCHAR pszMessage
)
{
	BOOL bReturn = TRUE;
	DWORD dwWaitResult = 0;

	//m_pDssThis->DebugMsg(TEXT("PushMsgFromDllToQueue entered"));

	dwWaitResult = WaitForSingleObject(hRWMsgFromDllMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		vMsgQueue.push_back(std::wstring(pszMessage));
		m_pDssThis->DebugMsg(TEXT("PushMsgFromDllToQueue pushed message \"%s\""), (vMsgQueue.back()).c_str());
		break;

	case WAIT_FAILED:
		DebugMsg(TEXT("PushMsgFromDllToQueue - WaitForSingleObject failed GLE=%d"), GetLastError());
		bReturn = FALSE;
	}
	ReleaseMutex(hRWMsgFromDllMutex);

	return bReturn;
}

BOOL DetectionSystemService::PopMsgFromDllToQueue(
	_Out_ std::wstring *pszMessage
)
{
	BOOL bReturn = TRUE;
	DWORD dwWaitResult = 0;

	//m_pDssThis->DebugMsg(TEXT("PopMsgFromDllToQueue entered"));

	dwWaitResult = WaitForSingleObject(hRWMsgFromDllMutex, INFINITE);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		if (0 < vMsgQueue.size())
		{
			(*pszMessage) = vMsgQueue.back();
			vMsgQueue.pop_back();
			m_pDssThis->DebugMsg(TEXT("PopMsgFromDllToQueue popped message \"%s\""), (*pszMessage).c_str());
		}
		else
		{
			bReturn = FALSE; //There is no messages
		}
		break;

	case WAIT_FAILED:
		DebugMsg(TEXT("PopMsgFromDllToQueue - WaitForSingleObject failed GLE=%d"), GetLastError());
		bReturn = FALSE;
	}
	ReleaseMutex(hRWMsgFromDllMutex);

	return bReturn;
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

VOID DetectionSystemService::Run()
{
	DebugMsg(TEXT("DetectionSystemService::Run - Entered"));

	CONST DWORD dwNumberOfThreads = 2;
	CONST LPTHREAD_START_ROUTINE pThreadRoutine[dwNumberOfThreads] = {
		LPTHREAD_START_ROUTINE(RdsDllListenerThread),
		LPTHREAD_START_ROUTINE(RdsUiReporterThread)
	};
	HANDLE hThread[dwNumberOfThreads] = { 0 };
	DWORD dwThreadId[dwNumberOfThreads] = { 0 };
	DWORD dwIndex = 0;

	for (dwIndex = 0; dwIndex < dwNumberOfThreads; dwIndex++)
	{
		hThread[dwIndex] = CreateThread(
			NULL,
			0,
			pThreadRoutine[dwIndex],
			NULL,
			0,
			&(dwThreadId[dwIndex])
		);
		if (NULL == hThread[dwIndex])
		{
			DebugMsg(TEXT("DetectionSystemService::Run - CreateThread failed GLE=%d"), GetLastError());
			return;
		}
	}

	WaitForMultipleObjects(dwNumberOfThreads, hThread, TRUE, INFINITE);

	for (dwIndex = 0; dwIndex < dwNumberOfThreads; dwIndex++)
	{
		if (NULL != hThread[dwIndex])
		{
			CloseHandle(hThread[dwIndex]);
		}
	}

	DebugMsg(TEXT("DetectionSystemService::Run - Exit"));
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa365603(v=vs.85).aspx
DWORD DetectionSystemService::RdsDllListenerThread(
	_In_ LPVOID lpParameter)
{
	m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread entered"));
	UNREFERENCED_PARAMETER(lpParameter);

	PIPE_INSTANCE piPipe[DLL_PIPE_INSTANCES];
	HANDLE hEvents[DLL_PIPE_INSTANCES + 1]; // +1 is for the m_hAlertHandler so the service could stop at any time and not wait for signal of some pipe.
	DWORD dwIndex = 0;
	DWORD dwWait = 0;
	DWORD dwNumberOfBytes = 0;
	DWORD dwError = ERROR_SUCCESS;
	BOOL bSuccess = FALSE;
	CONST LPCWSTR lpszDllPipeName = (LPCWSTR)TEXT("\\\\.\\pipe\\RDS_DLL_pipe");

	dwError = m_pDssThis->CreatePipes(lpszDllPipeName, DLL_PIPE_INSTANCES, READING_STATE, hEvents, piPipe);
	if (ERROR_SUCCESS != dwError)
	{
		m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - CreatePipes failed to create Dll pipes."));
		return dwError;
	}
	hEvents[DLL_PIPE_INSTANCES] = m_pDssThis->m_hAlertHandle; // The watch for service stop handle

	while (TRUE == m_pDssThis->m_bIsRunning)
	{
		dwWait = WaitForMultipleObjects(
			DLL_PIPE_INSTANCES + 1,
			hEvents,
			FALSE,
			INFINITE);

		dwIndex = dwWait - WAIT_OBJECT_0;  // determines which pipe 
		if ((dwIndex < 0) || (dwIndex > DLL_PIPE_INSTANCES - 1))
		{
			if (DLL_PIPE_INSTANCES == dwIndex)
			{
				m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - m_hAlertHandler was signaled"));
				SetEvent(m_pDssThis->m_hAlertHandle); // in case the other threads depend on this alert to finish run didn't watch for this handle yet.
			}
			else
			{
				m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - Index out of range."));
			}
			// Close handles and continue? crash the service?
			return dwError; //??
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
			case CONNECTING_STATE:
				if (FALSE == bSuccess)
				{
					dwError = GetLastError();
					m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - GetOverlappedResult in CONNECTING_STATE GLE=%d."), dwError);
					// Close handles and continue? crash the service?
					return dwError;
				}
				piPipe[dwIndex].dwState = READING_STATE;
				break;

			case READING_STATE:
				if (!(FALSE == bSuccess || 0 == dwNumberOfBytes))
				{
					piPipe[dwIndex].dwNumberOfBytes = dwNumberOfBytes;
					m_pDssThis->DebugMsg(TEXT("DLL send \"%s\""), piPipe[dwIndex].pbuffer);
					m_pDssThis->PushMsgFromDllToQueue((PWCHAR)piPipe[dwIndex].pbuffer);
				}
				else
				{
					m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - GetOverlappedResult in READING_STATE GLE=%d."), GetLastError());
				}
				m_pDssThis->DisconnectAndReconnect(&(piPipe[dwIndex]), DllListener);
				continue;

			default:
			{
				m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - Invalid pipe state"));
				// Close handles and continue? crash the service?
				return dwError;
			}
			}
		}

		// The pipe state determines which operation to do next. 

		switch (piPipe[dwIndex].dwState)
		{

		case READING_STATE:
			bSuccess = ReadFile(
				piPipe[dwIndex].hPipeInst,
				piPipe[dwIndex].pbuffer,
				PIPE_BUFFER_SIZE,
				&piPipe[dwIndex].dwNumberOfBytes,
				&piPipe[dwIndex].olOverlap);

			if ((TRUE == bSuccess) && (0 != piPipe[dwIndex].dwNumberOfBytes))
			{
				m_pDssThis->DebugMsg(TEXT("DLL send \"%s\""), piPipe[dwIndex].pbuffer);
				m_pDssThis->PushMsgFromDllToQueue((PWCHAR)piPipe[dwIndex].pbuffer);
				m_pDssThis->DisconnectAndReconnect(&(piPipe[dwIndex]), DllListener);
				break;
			}

			// The read operation is still pending. 
			dwError = GetLastError();
			if ((FALSE == bSuccess) && (ERROR_IO_PENDING == dwError))
			{
				piPipe[dwIndex].bPendingIO = TRUE;
				continue;
			}

			// An error occurred; disconnect from the client. 
			m_pDssThis->DisconnectAndReconnect(&(piPipe[dwIndex]), DllListener);
			break;

		default:
		{
			m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - Invalid pipe state"));
			// Close handles and continue? crash the service?
			return dwError;
		}
		}
	}

	for (dwIndex = 0; dwIndex < DLL_PIPE_INSTANCES; dwIndex++)
	{
		if (NULL != piPipe[dwIndex].hPipeInst)
		{
			CloseHandle(piPipe[dwIndex].hPipeInst);
		}
		if (NULL != hEvents[dwIndex])
		{
			CloseHandle(hEvents[dwIndex]);
		}
	}

	return dwError;
}

DWORD DetectionSystemService::RdsUiReporterThread(
	_In_ LPVOID lpParameter)
{
	m_pDssThis->DebugMsg(TEXT("RdsUiReporterThread entered"));
	UNREFERENCED_PARAMETER(lpParameter);

	PIPE_INSTANCE piPipe[UI_PIPE_INSTANCES];
	HANDLE hEvents[UI_PIPE_INSTANCES + 1]; // +1 is for the m_hAlertHandler so the service could stop at any time and not wait for signal of some pipe.
	DWORD dwIndex = 0;
	DWORD dwWait = 0;
	DWORD dwNumberOfBytes = 0;
	DWORD dwError = ERROR_SUCCESS;
	BOOL bSuccess = FALSE;
	LPCWSTR lpszUiPipeName = (LPCWSTR)TEXT("\\\\.\\pipe\\RDS_UI_pipe");
	std::wstring pszTmpMsg;

	pszTmpMsg.clear();

	dwError = m_pDssThis->CreatePipes(lpszUiPipeName, 1, WRITING_STATE, hEvents, piPipe);
	if (ERROR_SUCCESS != dwError)
	{
		m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - CreatePipes failed to create UI pipes."));
		return dwError;
	}
	hEvents[UI_PIPE_INSTANCES] = m_pDssThis->m_hAlertHandle; // The watch for service stop handle

	while (TRUE == m_pDssThis->m_bIsRunning)
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
				m_pDssThis->DebugMsg(TEXT("RdsUiReporterThread - m_hAlertHandler was signaled"));
				SetEvent(m_pDssThis->m_hAlertHandle); // in case the other threads depend on this alert to finish run didn't watch for this handle yet.
			}
			else
			{
				m_pDssThis->DebugMsg(TEXT("RdsUiReporterThread - Index out of range."));
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
					m_pDssThis->DebugMsg(TEXT("RdsUiReporterThread - GetOverlappedResult in CONNECTING_STATE GLE=%d."), dwError);
					// Close handles and continue? crash the service?
					return dwError;
				}
				piPipe[dwIndex].dwState = WRITING_STATE;
				break;

				// Pending write operation 
			case WRITING_STATE:
				if ((FALSE == bSuccess) || (0 == dwNumberOfBytes))
				{
					m_pDssThis->DebugMsg(TEXT("RdsUiReporterThread - GetOverlappedResult in WRITING_STATE GLE=%d."), GetLastError());
				}
				else
				{
					m_pDssThis->DebugMsg(TEXT("RdsUiReporterThread - msg \"%s\" sent from queue"), piPipe[dwIndex].pbuffer);
					pszTmpMsg.clear();
				}
				m_pDssThis->DisconnectAndReconnect(&(piPipe[dwIndex]), UiReporter);
				continue;

			default:
			{
				m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - Invalid pipe state"));
				// Close handles and continue? crash the service?
				return dwError;
			}
			}
		}

		// The pipe state determines which operation to do next. 
		switch (piPipe[dwIndex].dwState)
		{
		case WRITING_STATE:
			if (FALSE == m_pDssThis->PopMsgFromDllToQueue(&pszTmpMsg))
			{
				//m_pDssThis->DebugMsg(TEXT("RdsUiReporterThread - no msg in queue"));
				m_pDssThis->DisconnectAndReconnect(&(piPipe[dwIndex]), UiReporter);
				continue;
			}
			else
			{
				piPipe[dwIndex].dwNumberOfBytes = (pszTmpMsg.length() + 1) * sizeof(WCHAR);
				RtlCopyMemory(piPipe[dwIndex].pbuffer, pszTmpMsg.c_str(), piPipe[dwIndex].dwNumberOfBytes);
				pszTmpMsg.clear();
			}

			m_pDssThis->DebugMsg(TEXT("RdsUiReporterThread - writing \"%s\" from queue to UI"), piPipe[dwIndex].pbuffer);
			bSuccess = WriteFile(
				piPipe[dwIndex].hPipeInst,
				piPipe[dwIndex].pbuffer,
				piPipe[dwIndex].dwNumberOfBytes,
				&dwNumberOfBytes,
				&piPipe[dwIndex].olOverlap);

			// The write operation completed successfully. 
			if ((TRUE == bSuccess) && (dwNumberOfBytes == piPipe[dwIndex].dwNumberOfBytes))
			{
				m_pDssThis->DebugMsg(TEXT("RdsUiReporterThread - pop \"%s\" from queue"), piPipe[dwIndex].pbuffer);
				m_pDssThis->DisconnectAndReconnect(&(piPipe[dwIndex]), UiReporter);
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
			m_pDssThis->DisconnectAndReconnect(&(piPipe[dwIndex]), UiReporter);
			break;

		default:
		{
			m_pDssThis->DebugMsg(TEXT("RdsDllListenerThread - Invalid pipe state"));
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
	_Inout_ PPIPE_INSTANCE piPipeInstance,
	_In_ CONST PipeType ptPipeType
)
{
	DWORD dwState = UNDEFINE_PIPE_STATE;

	if (DllListener == ptPipeType)
	{
		dwState = READING_STATE;
	}
	else if (UiReporter == ptPipeType)
	{
		dwState = WRITING_STATE;
	}

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
		dwState;     // ready to read / write
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