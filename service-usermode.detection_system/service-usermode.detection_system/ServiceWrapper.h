#ifndef _SERVICE_WRAPPER_H_
#define _SERVICE_WRAPPER_H_

#include "NtServMsg.h"

#define SERVICE_CONTROL_USER     128
#define SERVICE_NAME_SIZE        64
#define SERVICE_DESCRIPTION_SIZE 256

#define HANDLEREX 1


class ServiceWrapper
{
public:
	ServiceWrapper(
		_In_ CONST PWCHAR szServiceName,
		_In_ CONST PWCHAR szServiceDescription
	);

	virtual ~ServiceWrapper();

	BOOL ParseStandardArgs(
		_In_ CONST INT	  argc,
		_In_ CONST PWCHAR argv[]
	);

	BOOL IsInstalled();
	BOOL Install();
	BOOL Uninstall();

	VOID LogEvent(
		_In_ CONST WORD	  wType,
		_In_ CONST DWORD  dwEventID,
		_In_ CONST PWCHAR pszString1 = NULL,
		_In_ CONST PWCHAR pszString2 = NULL,
		_In_ CONST PWCHAR pszString3 = NULL
	);

	BOOL StartService();

	// static member functions
	static VOID WINAPI ServiceMain(
		_In_ DWORD   dwArgc,
		_In_ LPTSTR* lpszArgv
	);

#ifndef HANDLEREX
	static VOID WINAPI Handler(
		_In_ CONST DWORD dwOpcode
	);
#else   HANDLEREX
	static DWORD WINAPI HandlerEx(
		_In_ CONST DWORD  dwOpcode,
		_In_ CONST DWORD  dwEventType,
		_In_ CONST LPVOID lpEventData,
		_In_ CONST LPVOID lpContext
	);
#endif  HANDLEREX

	VOID SetStatus(
		_In_ DWORD dwState
	);

	BOOL Initialize();
	virtual VOID Run();
	virtual BOOL OnInit();
	virtual VOID OnStop();
	virtual VOID OnInterrogate();
	virtual VOID OnPause();
	virtual VOID OnContinue();
	virtual VOID OnShutdown();
	virtual VOID OnDeviceEvent(
		_In_ CONST DWORD  dwEventType,
		_In_ CONST LPVOID lpEventData
	);
	virtual BOOL OnUserControl(
		_In_ CONST DWORD dwOpcode
	);
	VOID DebugMsg(
		CONST WCHAR* pszFormat, 
		...
	);

	WCHAR m_szServiceName[SERVICE_NAME_SIZE];
	WCHAR m_szServiceDescription[SERVICE_DESCRIPTION_SIZE];
	INT m_iMajorVersion;
	INT m_iMinorVersion;
	SERVICE_STATUS_HANDLE m_hServiceStatus;
	SERVICE_STATUS m_Status;
	BOOL m_bIsRunning;
	BOOL m_bDebugging;

	static ServiceWrapper * m_pThis;
	HANDLE m_hAlertHandle;
private:
	HANDLE m_hEventLog;
};

#endif // _SERVICE_WRAPPER_H_
