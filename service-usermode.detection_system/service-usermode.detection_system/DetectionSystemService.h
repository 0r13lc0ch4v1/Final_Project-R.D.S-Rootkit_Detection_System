#pragma once 

#include "ServiceWrapper.h"

#define PIPE_BUFFER_SIZE (1 << 10)
#define PIPE_ERROR_FAILURE 1
#define UNDEFINE_PIPE_STATE 0xbaadf00d
#define CONNECTING_STATE 0 
#define READING_STATE 1 
#define WRITING_STATE 2 
#define DLL_PIPE_INSTANCES 4
#define UI_PIPE_INSTANCES 1
#define PIPE_TIMEOUT 5000

typedef enum { 
	DllListener, 
	UiReporter
}	PipeType;

typedef struct _PIPE_INSTANCE
{
	OVERLAPPED olOverlap;
	HANDLE hPipeInst;
	WCHAR pbuffer[PIPE_BUFFER_SIZE];
	DWORD dwNumberOfBytes;
	DWORD dwState;
	BOOL bPendingIO;
}	PIPE_INSTANCE, *PPIPE_INSTANCE;

class DetectionSystemService : public ServiceWrapper
{
public:
	DetectionSystemService();
	~DetectionSystemService();

	virtual VOID Run();

	virtual BOOL OnUserControl(
		_In_ CONST DWORD dwOpcode
	);

	virtual VOID OnDeviceEvent(
		_In_ CONST DWORD  dwEventType,
		_In_ CONST LPVOID lpEventData
	);

	BOOL CreateNamedMutex(
		_In_ CONST LPCWSTR pszMutexName,
		_In_ PHANDLE hMutex
	);

	BOOL PushMsgFromDllToQueue(
		_In_ CONST PWCHAR pszMessage
	);

	BOOL PopMsgFromDllToQueue(
		_Out_ std::wstring *pszMessage
	);

	DWORD static WINAPI RdsDllListenerThread(
		_In_ LPVOID lpParameter
	);

	DWORD static WINAPI RdsUiReporterThread(
		_In_ LPVOID lpParameter
	);

	DWORD CreatePipes(
		_In_ CONST LPCWSTR lpszPipeName,
		_In_ CONST DWORD dwNumberOfInstances,
		_In_ CONST DWORD dwState,
		_Out_ PHANDLE hEvents,
		_Out_ PPIPE_INSTANCE piPipe
	);

	VOID DisconnectAndReconnect(
		_Inout_ PPIPE_INSTANCE piPipeInstance,
		_In_ CONST PipeType ptPipeType
	);

	BOOL ConnectToNewClient(
		_In_ CONST HANDLE hNamedPipe,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

	BOOL CreateSecurityDescriptor(
		_Out_ LPSECURITY_ATTRIBUTES  lpSecurityAttributes
	);

	static DetectionSystemService * m_pDssThis;
	std::vector<std::wstring> vMsgQueue;
	HANDLE hRWMsgFromDllMutex;
	SECURITY_ATTRIBUTES SecurityAttributes;
};