#include "StdAfx.h"
#include "ServiceWrapper.h"


ServiceWrapper* ServiceWrapper::m_pThis = NULL;

ServiceWrapper::ServiceWrapper(
	_In_ CONST PWCHAR szServiceName,
	_In_ CONST PWCHAR szServiceDescription
) : m_bDebugging(FALSE)
{
	// copy the address of the current object so we can access it from
	// the static member callback functions. 
	// WARNING: This limits the application to only one ServiceWrapper object. 
	m_pThis = this;

	//Set the default service name and version
	memset(m_szServiceName, 0, sizeof(m_szServiceName));
	StringCchCopy(m_szServiceName, sizeof(m_szServiceName), szServiceName);
	memset(m_szServiceDescription, 0, sizeof(m_szServiceDescription));
	StringCchCopy(m_szServiceDescription, sizeof(m_szServiceDescription), szServiceDescription);
	m_iMajorVersion = 1;
	m_iMinorVersion = 0;
	m_hEventLog = NULL;

	// set up the initial service bStatus 
	m_hServiceStatus = NULL;
	m_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	m_Status.dwCurrentState = SERVICE_STOPPED;
	m_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	m_Status.dwWin32ExitCode = 0;
	m_Status.dwServiceSpecificExitCode = 0;
	m_bIsRunning = FALSE;
}

ServiceWrapper::~ServiceWrapper()
{
	DebugMsg(TEXT("ServiceWrapper::~ServiceWrapper()"));
	if (NULL != m_hEventLog)
	{
		DeregisterEventSource(m_hEventLog);
	}
}

BOOL ServiceWrapper::ParseStandardArgs(
	_In_ CONST INT	  argc,
	_In_ CONST PWCHAR argv[]
)
{
	if (argc <= 1)
	{
		return FALSE;
	}

	if (_wcsicmp(argv[1], TEXT("-v")) == 0)
	{
		// Spit out version info
		wprintf(TEXT("%ls Version %d.%d\n"),
			&m_szServiceName[0], m_iMajorVersion, m_iMinorVersion);
		wprintf(TEXT("The service is %s installed\n"),
			IsInstalled() ? TEXT("currently") : TEXT("not"));
		return TRUE; // say we processed the argument

	}
	else if (0 == _wcsicmp(argv[1], TEXT("-i")))
	{
		// Request to install.
		if (TRUE == IsInstalled())
		{
			wprintf(TEXT("%ls is already installed\n"), &m_szServiceName[0]);
		}
		else
		{
			// Try and install the copy that's running
			if (TRUE == Install())
			{
				wprintf(TEXT("%ls installed\n"), &m_szServiceName[0]);
			}
			else
			{
				wprintf(TEXT("%ls failed to install. GLE=%d\n"), &m_szServiceName[0], GetLastError());
			}
		}
		return TRUE; // say we processed the argument
	}
	else if (0 == _wcsicmp(argv[1], TEXT("-u")))
	{
		// Request to uninstall.
		if (FALSE == IsInstalled())
		{
			wprintf(TEXT("%ls is not installed\n"), &m_szServiceName[0]);
		}
		else
		{
			// Try and remove the copy that's installed
			if (TRUE == Uninstall()) {
				// Get the executable file path
				WCHAR szFilePath[_MAX_PATH];
				GetModuleFileName(NULL, szFilePath, sizeof(szFilePath));
				wprintf(TEXT("%ls removed. (You must delete the file (%s) yourself.)\n"),
					&m_szServiceName[0], szFilePath);
			}
			else
			{
				wprintf(TEXT("Could not remove %ls. GLE=%d\n"), &m_szServiceName[0], GetLastError());
			}
		}
		return TRUE; // say we processed the argument
	}

	// Don't recognise the args
	return FALSE;
}

BOOL ServiceWrapper::IsInstalled()
{
	BOOL bResult = FALSE;

	SC_HANDLE SCManager = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS
	);
	if (NULL != SCManager) 
	{
		SC_HANDLE hService = OpenService(
			SCManager,
			m_szServiceName,
			SERVICE_QUERY_CONFIG
		);
		if (NULL != hService)
		{
			bResult = TRUE;
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(SCManager);
	}

	return bResult;
}

BOOL ServiceWrapper::Install()
{
	SC_HANDLE SCManager = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS
	); // full access
	if (NULL == SCManager)
	{
		return FALSE;
	}

	WCHAR pszFilePath[MAX_PATH] = { NULL };
	GetModuleFileName(NULL, pszFilePath, sizeof(pszFilePath));

	SC_HANDLE hService = CreateService(
		SCManager,
		m_szServiceName,
		m_szServiceName,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		pszFilePath,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);
	if (NULL == hService)
	{
		CloseServiceHandle(SCManager);
		return FALSE;
	}

	// make registry entries to support logging messages
	// Add the source name as a subkey under the Application
	// key in the EventLog service portion of the registry.

	WCHAR szKeyName[MAX_PATH] = { 0 };
	WCHAR szKeyNameEventLog[] = TEXT("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\");
	HKEY hKey = NULL;
	StringCchCopy(szKeyName, MAX_PATH, szKeyNameEventLog);
	StringCchCat(szKeyName, MAX_PATH, m_szServiceName);
	if (ERROR_SUCCESS != RegCreateKey(HKEY_LOCAL_MACHINE, szKeyName, &hKey))
	{
		CloseServiceHandle(hService);
		CloseServiceHandle(SCManager);
		return FALSE;
	}

	// Add the Event ID message-file name to the 'EventMessageFile' subkey.
	RegSetValueEx(
		hKey,
		TEXT("EventMessageFile"),
		0,
		REG_EXPAND_SZ,
		(CONST PBYTE)pszFilePath,
		wcslen(pszFilePath) + sizeof(WCHAR)
	);

	// Set the supported types flags.
	DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
	RegSetValueEx(
		hKey,
		TEXT("TypesSupported"),
		0,
		REG_DWORD,
		(CONST PBYTE)&dwData,
		sizeof(DWORD)
	);
	RegCloseKey(hKey);

	LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_INSTALLED, m_szServiceName);

	// Add our description
	WCHAR szKeyNameService[] = TEXT("SYSTEM\\CurrentControlSet\\Services\\");
	StringCchCopy(szKeyName, MAX_PATH, szKeyNameService);
	StringCchCat(szKeyName, MAX_PATH, m_szServiceName);

	if (ERROR_SUCCESS == RegOpenKey(HKEY_LOCAL_MACHINE, szKeyName, &hKey))
	{
		RegSetValueEx(
			hKey,
			TEXT("Description"),
			0,
			REG_SZ,
			(CONST PBYTE)m_szServiceDescription,
			(wcslen(m_szServiceDescription) * sizeof(WCHAR)) + sizeof(WCHAR)
		);
		RegCloseKey(hKey);
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(SCManager);
	return TRUE;
}

BOOL ServiceWrapper::Uninstall()
{
	SC_HANDLE SCManager = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS
	);
	if (NULL == SCManager)
	{
		return FALSE;
	}

	BOOL bResult = FALSE;
	SC_HANDLE hService = OpenService(
		SCManager,
		m_szServiceName,
		DELETE
	);
	if (NULL != hService) {
		if (TRUE == DeleteService(hService))
		{
			LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_REMOVED, m_szServiceName);
			bResult = TRUE;
		}
		else
		{
			LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_NOTREMOVED, m_szServiceName);
		}
		CloseServiceHandle(hService);
	}

	CloseServiceHandle(SCManager);
	return bResult;
}

VOID ServiceWrapper::LogEvent(
	_In_ CONST WORD	  wType,
	_In_ CONST DWORD  dwEventID,
	_In_ CONST PWCHAR pszString1,
	_In_ CONST PWCHAR pszString2,
	_In_ CONST PWCHAR pszString3
)
{
	CONST PWCHAR lpStrings[3] = { pszString1, pszString2, pszString3 };

	WORD wNumStrings = 0;
	for (UINT uiIndex = 0; uiIndex < 3; uiIndex++)
	{
		if (lpStrings[uiIndex] != NULL)
		{
			wNumStrings++;
		}
	}

	// Check the event source has been registered and if
	// not then register it now
	if (NULL == m_hEventLog)
	{
		m_hEventLog = RegisterEventSource(
			NULL,
			m_szServiceName
		); 
	}

	if (NULL != m_hEventLog)
	{
		ReportEvent(
			m_hEventLog,
			wType,
			0,
			dwEventID,
			NULL,
			wNumStrings,
			0,
			(LPCWSTR*)lpStrings,
			NULL
		);
	}
}

BOOL ServiceWrapper::StartService()
{
	SERVICE_TABLE_ENTRYW pServiceTableEntry[] = {
		{ (LPWSTR)m_szServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
		{ NULL, NULL }
	};

	DebugMsg(TEXT("Calling StartServiceCtrlDispatcher()"));
	BOOL bServiceStarted = StartServiceCtrlDispatcherW(pServiceTableEntry);
	if (FALSE == bServiceStarted)
	{
		DebugMsg(TEXT("Error starting service GLE=%d."), GetLastError());
	}
	DebugMsg(TEXT("Returned from StartServiceCtrlDispatcher()"));

	return bServiceStarted;
}

VOID ServiceWrapper::ServiceMain(
	_In_ DWORD	 dwArgc,
	_In_ LPTSTR* lpszArgv
)
{
	ServiceWrapper* pService = m_pThis;

	UNREFERENCED_PARAMETER(dwArgc);
	UNREFERENCED_PARAMETER(lpszArgv);

	pService->DebugMsg(TEXT("Entering ServiceWrapper::ServiceMain()"));
	pService->m_Status.dwCurrentState = SERVICE_START_PENDING;

#ifndef HANDLEREX
	pService->m_hServiceStatus = RegisterServiceCtrlHandler(pService->m_szServiceName,
		Handler);
#else   HANDLEREX
	pService->m_hServiceStatus = RegisterServiceCtrlHandlerEx(pService->m_szServiceName, HandlerEx, NULL);
#endif  HANDLEREX

	if (NULL == pService->m_hServiceStatus) 
	{
		pService->DebugMsg(TEXT("ServiceWrapper::ServiceMain() Service Not Registered"));
		pService->LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_CTRLHANDLERNOTINSTALLED);
		return;
	}

	pService->DebugMsg(TEXT("ServiceWrapper::ServiceMain() Service Registered"));

	if (pService->Initialize()) 
	{
		pService->m_bIsRunning = TRUE;
		pService->m_Status.dwWin32ExitCode = 0;
		pService->Run();
	}

	pService->SetStatus(SERVICE_STOPPED);
	pService->DebugMsg(TEXT("Leaving ServiceWrapper::ServiceMain()"));
}

#ifndef HANDLEREX
VOID ServiceWrapper::Handler(
	_In_ DWORD dwOpcode
)
#else   HANDLEREX
DWORD ServiceWrapper::HandlerEx(
	_In_ CONST DWORD  dwOpcode,
	_In_ CONST DWORD  dwEventType,
	_In_ CONST LPVOID lpEventData,
	_In_ CONST LPVOID lpContext
)
#endif  HANDLEREX
{
	ServiceWrapper* pService = m_pThis;

	UNREFERENCED_PARAMETER(lpContext);

	pService->DebugMsg(TEXT("ServiceWrapper::Handler(%lu)"), dwOpcode);
	switch (dwOpcode) 
	{
	case SERVICE_CONTROL_STOP: // 1
		pService->SetStatus(SERVICE_STOP_PENDING);
		pService->OnStop();
		pService->m_bIsRunning = FALSE;
		SetEvent(pService->m_hAlertHandle); // race condition?
		pService->LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_STOPPED);
		break;

	case SERVICE_CONTROL_PAUSE: // 2
		pService->OnPause();
		break;

	case SERVICE_CONTROL_CONTINUE: // 3
		pService->OnContinue();
		break;

	case SERVICE_CONTROL_INTERROGATE: // 4
		pService->OnInterrogate();
		break;

	case SERVICE_CONTROL_SHUTDOWN: // 5
		pService->OnShutdown();
		break;

	case SERVICE_CONTROL_DEVICEEVENT:
		pService->OnDeviceEvent(dwEventType, lpEventData);
		break;

	default:
		if (dwOpcode >= SERVICE_CONTROL_USER)
		{
			if (FALSE == pService->OnUserControl(dwOpcode)) 
			{
				pService->LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_BADREQUEST);
			}
		}
		else 
		{
			pService->LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_BADREQUEST);
		}
		break;
	}

	pService->DebugMsg(TEXT("Updating bStatus (%lu, %lu)"),
		pService->m_hServiceStatus,
		pService->m_Status.dwCurrentState
	);
	SetServiceStatus(pService->m_hServiceStatus, &pService->m_Status);

#ifdef HANDLEREX
	return NO_ERROR;
#endif HANDLEREX
}

VOID ServiceWrapper::SetStatus(
	_In_ DWORD dwState
)
{
	DebugMsg(TEXT("ServiceWrapper::SetStatus(%lu, %lu)"), m_hServiceStatus, dwState);
	m_Status.dwCurrentState = dwState;
	SetServiceStatus(m_hServiceStatus, &m_Status);
}

BOOL ServiceWrapper::Initialize()
{
	DebugMsg(TEXT("Entering ServiceWrapper::Initialize()"));

	// Start the initialization
	SetStatus(SERVICE_START_PENDING);

	// Perform the actual initialization
	BOOL bResult = OnInit();

	// Set final state
	m_Status.dwWin32ExitCode = GetLastError();
	if (FALSE == bResult) {
		LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_FAILEDINIT);
		SetStatus(SERVICE_STOPPED);
		return FALSE;
	}

	LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_STARTED);
	SetStatus(SERVICE_RUNNING);

	DebugMsg(TEXT("Leaving ServiceWrapper::Initialize()"));
	return TRUE;
}

VOID ServiceWrapper::Run()
{
	DebugMsg(TEXT("Entering ServiceWrapper::Run()"));

	while (TRUE == m_bIsRunning) 
	{
		DebugMsg(TEXT("Sleeping..."));
		Sleep(5000);
	}

	// nothing more to do
	DebugMsg(TEXT("Leaving ServiceWrapper::Run()"));
}

BOOL ServiceWrapper::OnInit()
{
	DebugMsg(TEXT("ServiceWrapper::OnInit()"));
	return TRUE;
}

VOID ServiceWrapper::OnStop()
{
	DebugMsg(TEXT("ServiceWrapper::OnStop()"));
}

VOID ServiceWrapper::OnInterrogate()
{
	DebugMsg(TEXT("ServiceWrapper::OnInterrogate()"));
}

VOID ServiceWrapper::OnPause()
{
	DebugMsg(TEXT("ServiceWrapper::OnPause()"));
}

VOID ServiceWrapper::OnContinue()
{
	DebugMsg(TEXT("ServiceWrapper::OnContinue()"));
}

VOID ServiceWrapper::OnShutdown()
{
	DebugMsg(TEXT("ServiceWrapper::OnShutdown()"));
}

VOID ServiceWrapper::OnDeviceEvent(
	_In_ CONST DWORD  dwEventType,
	_In_ CONST LPVOID lpEventData
)
{
	UNREFERENCED_PARAMETER(dwEventType);
	UNREFERENCED_PARAMETER(lpEventData);
	DebugMsg(TEXT("ServiceWrapper::OnDeviceEvent(DWORD dwEventType,LPVOID lpEventData)"));
}

BOOL ServiceWrapper::OnUserControl(
	_In_ CONST DWORD dwOpcode
)
{
	DebugMsg(TEXT("ServiceWrapper::OnUserControl(%8.8lXH)"), dwOpcode);
	return FALSE;
}

VOID ServiceWrapper::DebugMsg(
	CONST WCHAR* pszFormat,
	...
)
{
	WCHAR pBuffer[1024];
	swprintf_s(pBuffer, 1024, TEXT("[%ls](%lu): "), m_szServiceName, GetCurrentThreadId());
	va_list arglist;
	va_start(arglist, pszFormat);
	// Check the pBuffer size calculation
	StringCchVPrintf(&pBuffer[wcslen(pBuffer)], 1024 - wcslen(pBuffer), pszFormat, arglist);
	va_end(arglist);
	StringCchCat(pBuffer, 1024, TEXT("\n"));
	OutputDebugString(pBuffer);
}