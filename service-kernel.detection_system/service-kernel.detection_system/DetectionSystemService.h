#pragma once 

#ifdef __cplusplus
extern "C" {
#endif

//
// DriverAndServiceCommonDefinitions.h header file is a common file to the service and driver.
//
#include "..\..\kernel.detection_driver\kernel.detection_driver\DriverAndServiceCommonDefinitions.h"

#define COMMUNICATION_BUFFER_SIZE INFORMATION_BUFFER_LENGTH

	typedef KDD_INFORMATION_BUFFER  DSS_INFORMATION_STRUCT, 
		DSS_DETECTION_INFORMATION_REQUEST, 
		DSS_DETECTION_INFORMATION_RESPONSE,
		DSS_DETECTION_DRIVER_REQUEST,
		DSS_DETECTION_DRIVER_RESPONSE;
	typedef PKDD_INFORMATION_BUFFER PDSS_INFORMATION_STRUCT, 
		PDSS_DETECTION_INFORMATION_REQUEST, 
		PDSS_DETECTION_INFORMATION_RESPONSE,
		PDSS_DETECTION_DRIVER_REQUEST,
		PDSS_DETECTION_DRIVER_RESPONSE;

#ifdef __cplusplus
}
#endif

#include "ServiceWrapper.h"

#define PIPE_BUFFER_SIZE (1 << 10)
#define PIPE_ERROR_FAILURE 1
#define UNDEFINE_PIPE_STATE 0xbaadf00d
#define CONNECTING_STATE 0 
#define WRITING_STATE 1
#define UI_PIPE_INSTANCES 1
#define PIPE_TIMEOUT 5000

typedef struct _PIPE_INSTANCE
{
	OVERLAPPED olOverlap;
	HANDLE hPipeInst;
	WCHAR pbuffer[PIPE_BUFFER_SIZE];
	DWORD dwNumberOfBytes;
	DWORD dwState;
	BOOL bPendingIO;
}	PIPE_INSTANCE, *PPIPE_INSTANCE;

#define MAX_THREADS 3
static DWORD dwThreadIdArray[MAX_THREADS];
static HANDLE hThreadArray[MAX_THREADS];

class DetectionSystemService : public ServiceWrapper
{
public:
	DetectionSystemService();
	~DetectionSystemService();

	virtual BOOL OnInit();

	virtual VOID Run();

	virtual BOOL OnUserControl(
		_In_ CONST DWORD dwOpcode
	);

	virtual VOID OnDeviceEvent(
		_In_ CONST DWORD  dwEventType,
		_In_ CONST LPVOID lpEventData
	);

	static DWORD WINAPI KernelDetectionThread(
		_In_ LPVOID lpParam
	);

	static DWORD WINAPI HandleKernelRequestThread(
		_In_ LPVOID lpParam
	);

	static DWORD RdsUiReporterThread(
		_In_ LPVOID lpParameter
	);

	BOOL PushMsgFromKernelToQueue(
		_In_ CONST PWCHAR pszMessage
	);

	BOOL PopMsgFromKernelToQueue(
		_Out_ std::wstring *pszMessage
	);

	BOOL CreateNamedMutex(
		_In_ CONST LPCWSTR pszMutexName,
		_In_ PHANDLE hMutex
	);

	DWORD CreatePipes(
		_In_ CONST LPCWSTR lpszPipeName,
		_In_ CONST DWORD dwNumberOfInstances,
		_In_ CONST DWORD dwState,
		_Out_ PHANDLE hEvents,
		_Out_ PPIPE_INSTANCE piPipe
	);

	BOOL GetInformationFromKernel(
		_In_ CONST PDSS_DETECTION_INFORMATION_REQUEST pRequest,
		_In_ CONST LPOVERLAPPED                       pOverlapped
	);

	VOID DisconnectAndReconnect(
		_Inout_ PPIPE_INSTANCE piPipeInstance
	);

	BOOL ConnectToNewClient(
		_In_ CONST HANDLE hNamedPipe,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

	BOOL GetRequestFromKernel(
		_In_ CONST PDSS_DETECTION_DRIVER_REQUEST pRequest,
		_In_ CONST LPOVERLAPPED                  pOverlapped
	);

	BOOL SendResponseToKernel(
		_In_ CONST PDSS_DETECTION_DRIVER_RESPONSE pResponse,
		_In_ CONST LPOVERLAPPED                   pOverlapped
	);

	BOOL CreateSecurityDescriptor(
		_Out_ LPSECURITY_ATTRIBUTES  lpSecurityAttributes
	);

	BOOL   m_DetectionDriverConnected;
	HANDLE m_RdsKernelInfoHandle;
	BOOL   m_RequestDriverConnected;
	HANDLE m_RdsKernelRequestHandle;

	std::vector<std::wstring> vMsgQueue;
	HANDLE hRWMsgFromKernelMutex;
	SECURITY_ATTRIBUTES SecurityAttributes;
};