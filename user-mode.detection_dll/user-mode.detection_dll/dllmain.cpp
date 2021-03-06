// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "Utils.h"
#include "DetectionModule.h"

HANDLE DetectionThreadHandle = NULL;
DWORD pDetectionThreadId = 0;

BOOL APIENTRY DllMain(
	_In_ HMODULE hModule,
	_In_ DWORD   ul_reason_for_call,
	_In_ LPVOID  lpReserved
)
{
	BOOL bReturn = TRUE;
	DWORD dwWaitObjRet = WAIT_FAILED;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		if (FALSE == StartDetectionThreadRoutine(&DetectionThreadHandle, &pDetectionThreadId))
		{
			//Report to service
			bReturn = FALSE;
			break;
		}
		bReturn = TRUE;
		break;
    case DLL_PROCESS_DETACH:
		if (NULL != DetectionThreadHandle)
		{
			bKeepRunnig = TRUE;
			dwWaitObjRet = WaitForSingleObject(DetectionThreadHandle, 1000);
			if (WAIT_OBJECT_0 == dwWaitObjRet)
			{
				DebugMsg(TEXT("DetectionThread terminated"));
				CloseHandle(DetectionThreadHandle);
				bReturn = TRUE;
				break;
			}
		}
		bReturn = FALSE;
    }

    return bReturn;
}

