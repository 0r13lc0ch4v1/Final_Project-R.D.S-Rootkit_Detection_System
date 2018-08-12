/*++

	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
	KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
	PURPOSE.

Module Name:

	RootkitDetection.h

Abstract:

	Header file for the Rootkit detection driver

Environment:

	Kernel mode only

--*/

#pragma once

#include <NtIfs.h>
#include <NtStrSafe.h>
#pragma comment(lib, "NtStrSafe.lib")
#include <Wdm.h>

#include "DriverAndServiceCommonDefinitions.h"

//
// Macro to compile string as Unicode.
//
#define UNICODE(quote) L##quote

//
// For KeDelayExecutionThread time.
// 100 nanoseconds * 10,000 = 1ms.
// Minus means relative time

#define MILLISECOND			 10000
#define RELATIVE_MILLISECOND (-MILLISECOND)

//
// Logging macros
//

#define InfoPrint(str, ...)                 \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_INFO_LEVEL,           \
               "%S: "##str"\n",             \
               DRIVER_NAME,                 \
               __VA_ARGS__)

#define ErrorPrint(str, ...)                \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_ERROR_LEVEL,          \
               "%S: Line %d: "##str"\n",    \
               DRIVER_NAME,                 \
               __LINE__,                    \
               __VA_ARGS__)

//
// Maximum length of full path to file.
//
#define MAX_PATH 256

//
// Maximum length of message from function
//
#define MAX_FUNC_MSG_SIZE 1024

//
// *HANDLE definition for void*.
//
typedef void * HANDLE;

//
// *HMODULE definition for void*.
//
typedef void *HMODULE;

//
// WORD definition for unsigned shot.
//
typedef unsigned short WORD;

//
// PWORD definition for WORD*.
//
typedef WORD* PWORD;

//
// UINT definition for unsigned int. 
//
typedef unsigned int UINT;

//
// Name for boolean variables.
//
typedef UINT BOOL;

//
// Name for byte pointer.
//
typedef PUCHAR PBYTE;

//
// Name for byte variable.
//
typedef UCHAR BYTE;

//
// LPBYTE definition for BYTE*. 
//
typedef BYTE* LPBYTE;

//
// Name for DWORD pointer.
//
typedef DWORD* PDWORD;

//
// Name for LPVOID pointer.
//
typedef void *LPVOID;

//
// To count the number of detection threads, should be only one.
//
static UINT uiDetectionThreadCounter = 0;

//
// To check if the detection thread is dead.
//
static BOOL bIsDetectionThreadAlive = FALSE;

//
// Pointer to the device object used to detect Rootkit in the kernel. 
//
extern PDEVICE_OBJECT g_KddInfoDeviceObject;

//
// Pointer to the device object used to request from service.
// e.g: request the md5 for a chunk of bytes.
//
extern PDEVICE_OBJECT g_KddRequestDeviceObject;

//
// The fast mutex 'fmInformationMutex' guarding the detection process is done writing
// to the "detection information buffer", and the device can write the 
// information from the "detection information buffer" to the "service buffer". 
//
extern FAST_MUTEX fmInformationMutex;

//
// The fast mutex 'fmSendRequestMutex' guarding the "driver request buffer".
// 
extern FAST_MUTEX fmSendRequestMutex;

//
// The fast mutex 'fmGetResponseMutex' guarding the "driver response buffer".
// 
extern FAST_MUTEX fmGetResponseMutex;

//
// The fast mutex 'fmDetectionThreadMutex' guarding the "uiDetectionThreadCounter".
// 
extern FAST_MUTEX fmDetectionThreadMutex;

//
// The object referenced to the detection thread.
// 
extern PETHREAD ptRootkitDetectionObject;

//
// Boolean flag to stop the thread on driver unload.
// 
extern INT bStopDetectionThread;

//
// Names for KDD_INFORMATION_BUFFER.
// 
typedef KDD_INFORMATION_BUFFER  KDD_DETECTION_REQUEST, KDD_DETECTION_RESPONSE;
typedef PKDD_INFORMATION_BUFFER PKDD_DETECTION_REQUEST, PKDD_DETECTION_RESPONSE;

//
// The detection module will write the information to this buffer.
// 
extern KDD_DETECTION_REQUEST KddInformationBuffer;

static KDD_DETECTION_RESPONSE KddRequestBuffer = {
	{ 'r', 'e', 's', 'p', 'o', 'n', 's', 'e', ' ', 'f', ' ', 'k', 'e', 'r', 'n', 'e', 'l' },
	17,
	KDD_RT_NO_TYPE
};

static KDD_DETECTION_RESPONSE KddResponseBuffer = {
	{ 'r', 'e', 's', 'p', 'o', 'n', 's', 'e', ' ', 'f', ' ', 'k', 'e', 'r', 'n', 'e', 'l' },
	17,
	KDD_RT_NO_TYPE
};