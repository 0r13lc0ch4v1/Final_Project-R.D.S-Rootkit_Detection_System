/*++

	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
	KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
	PURPOSE.

Module Name:

	Entry.c

Abstract:

	Driver used to run the kernel mode Rootkit detection methods, to 
	detect kernel mode Rootkit.

Environment:

	Kernel mode only

--*/

#include "RootkitDetection.h"
#include "MajorFunctions.h"
#include "RootkitDetectorModule.h"
#include "Entry.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DeviceUnload;

_Dispatch_type_(IRP_MJ_CREATE)         DRIVER_DISPATCH KddCreateDevice;
_Dispatch_type_(IRP_MJ_CLOSE)          DRIVER_DISPATCH KddCloseDevice;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH KddDeviceControl;
_Dispatch_type_(IRP_MJ_READ)		   DRIVER_DISPATCH KddReadWrite;
_Dispatch_type_(IRP_MJ_WRITE)		   DRIVER_DISPATCH KddReadWrite;
_Dispatch_type_(IRP_MJ_CLEANUP)        DRIVER_DISPATCH KddCleanup;

NTSTRSAFE_PCWSTR pszInfoDeviceName = (NTSTRSAFE_PCWSTR)UNICODE("\\Device\\RdsDetectionDriver");
UNICODE_STRING usInfoDeviceName = { 0 };

NTSTRSAFE_PCWSTR pszInfoDosDeviceName = (NTSTRSAFE_PCWSTR)UNICODE("\\DosDevices\\RdsDetectionDriver");
UNICODE_STRING usInfoDosDeviceName = { 0 };

PDEVICE_OBJECT g_KddInfoDeviceObject = NULL;

NTSTRSAFE_PCWSTR pszRequestDeviceName = (NTSTRSAFE_PCWSTR)UNICODE("\\Device\\RdsRequestDriver");
UNICODE_STRING usRequestDeviceName = { 0 };

NTSTRSAFE_PCWSTR pszRequestDosDeviceName = (NTSTRSAFE_PCWSTR)UNICODE("\\DosDevices\\RdsRequestDriver");
UNICODE_STRING usRequestDosDeviceName = { 0 };

PDEVICE_OBJECT g_KddRequestDeviceObject = NULL;

FAST_MUTEX fmInformationMutex = { 0 };
FAST_MUTEX fmSendRequestMutex = { 0 };
FAST_MUTEX fmGetResponseMutex = { 0 };
FAST_MUTEX fmDetectionThreadMutex = { 0 };

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT	 pDriverObject,
	_In_ PUNICODE_STRING pRegistryPath
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pRegistryPath);

	InfoPrint("DriverEntry Called.");

	ExInitializeFastMutex(&fmInformationMutex);
	ExInitializeFastMutex(&fmSendRequestMutex); 
	ExInitializeFastMutex(&fmGetResponseMutex);
	ExInitializeFastMutex(&fmDetectionThreadMutex);

	InfoPrint("Starting detection thread.");

	ntStatus = InitializeRootkitDetection(&KddInformationBuffer);
	if (!NT_SUCCESS(ntStatus))
	{
		InfoPrint("Error Starting detection thread, NTSTATUS: 0x%8x.", ntStatus);
		return ntStatus;
	}

	ntStatus = InitUnicodeStrings();
	if (!NT_SUCCESS(ntStatus))
	{
		InfoPrint("InitUnicodeStrings for %ws failed.", usInfoDeviceName.Buffer);
		return ntStatus;
	}

	ntStatus = SetupInfoDevice(
		pDriverObject
	);
	if (!NT_SUCCESS(ntStatus))
	{
		InfoPrint("SetupInfoDevice failed to setup control device.");
		return ntStatus;
	}

	ntStatus = SetupRequestDevice(
		pDriverObject
	);
	if (!NT_SUCCESS(ntStatus))
	{
		InfoPrint("SetupRequestDevice failed to setup control device.");
		return ntStatus;
	}

	SetMajorFunctions(pDriverObject);

	ExInitializeFastMutex(&fmInformationMutex);
	ExInitializeFastMutex(&fmSendRequestMutex);

	InfoPrint("Driver loaded.");
	return ntStatus;
}

NTSTATUS InitUnicodeStrings()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	ntStatus = RtlUnicodeStringInit((&usInfoDeviceName), pszInfoDeviceName);
	if (STATUS_SUCCESS != ntStatus)
	{
		InfoPrint("RtlUnicodeStringInit failed to initializes a UNICODE_STRING %ws.", pszInfoDeviceName);
		return ntStatus;
	}

	ntStatus = RtlUnicodeStringInit((&usInfoDosDeviceName), pszInfoDosDeviceName);
	if (STATUS_SUCCESS != ntStatus)
	{
		InfoPrint("RtlUnicodeStringInit failed to initializes a UNICODE_STRING %ws.", pszInfoDosDeviceName);
		return ntStatus;
	}

	ntStatus = RtlUnicodeStringInit((&usRequestDeviceName), pszRequestDeviceName);
	if (STATUS_SUCCESS != ntStatus)
	{
		InfoPrint("RtlUnicodeStringInit failed to initializes a UNICODE_STRING %ws.", pszRequestDeviceName);
		return ntStatus;
	}

	ntStatus = RtlUnicodeStringInit((&usRequestDosDeviceName), pszRequestDosDeviceName);
	if (STATUS_SUCCESS != ntStatus)
	{
		InfoPrint("RtlUnicodeStringInit failed to initializes a UNICODE_STRING %ws.", pszRequestDosDeviceName);
		return ntStatus;
	}

	return ntStatus;
}

VOID SetMajorFunctions(
	_In_ PDRIVER_OBJECT pDriverObject
)
{
	UINT32 uiIndex = 0;

	for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
	{
		pDriverObject->MajorFunction[uiIndex] = (PDRIVER_DISPATCH)KddUnsupportedFunctions;
	}
	pDriverObject->MajorFunction[IRP_MJ_CREATE] =		  (PDRIVER_DISPATCH)KddCreateDevice;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =		  (PDRIVER_DISPATCH)KddCloseDevice;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)KddDeviceControl;
	pDriverObject->MajorFunction[IRP_MJ_READ] =			  (PDRIVER_DISPATCH)KddReadWrite;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] =		  (PDRIVER_DISPATCH)KddReadWrite;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] =		  (PDRIVER_DISPATCH)KddCleanup;

	pDriverObject->DriverUnload = (PDRIVER_UNLOAD)DeviceUnload;
}  

NTSTATUS SetupInfoDevice(
	_In_ PDRIVER_OBJECT	pDriverObject
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	InfoPrint("Creating Information device named: %ws.", usInfoDeviceName.Buffer);

	ntStatus = IoCreateDevice(
		pDriverObject,
		0,
		(&usInfoDeviceName),
		KDD_INFORMATION_TYPE,
		FILE_DEVICE_SECURE_OPEN,
		TRUE,
		&g_KddInfoDeviceObject
	);
	if (!NT_SUCCESS(ntStatus))
	{
		InfoPrint("Error Creating KddInfoDevice Device, NTSTATUS: 0x%8x.", ntStatus);
		return ntStatus;
	}

	InfoPrint("Device Created.");

	ClearFlag(g_KddInfoDeviceObject->Flags, DO_DEVICE_INITIALIZING);

	ntStatus = IoCreateSymbolicLink(
		(&usInfoDosDeviceName),
		(&usInfoDeviceName)
	);
	if (!NT_SUCCESS(ntStatus))
	{
		InfoPrint("Error creating symbolic link to %ws, named: %ws.", 
			usInfoDosDeviceName.Buffer, 
			usInfoDeviceName.Buffer
		);
		IoDeleteDevice(g_KddInfoDeviceObject);
		g_KddInfoDeviceObject = NULL;
		return ntStatus;
	}

	InfoPrint("Created symbolic link to %ws, named: %ws.", 
		usInfoDosDeviceName.Buffer, 
		usInfoDeviceName.Buffer
	);

	return ntStatus;
}

NTSTATUS SetupRequestDevice(
	_In_ PDRIVER_OBJECT	pDriverObject
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	InfoPrint("Creating Information device named: %ws.", usRequestDeviceName.Buffer);

	ntStatus = IoCreateDevice(
		pDriverObject,
		0,
		(&usRequestDeviceName),
		KDD_DRIVER_REQUEST_TYPE,
		FILE_DEVICE_SECURE_OPEN,
		TRUE,
		&g_KddRequestDeviceObject
	);
	if (!NT_SUCCESS(ntStatus))
	{
		InfoPrint("Error Creating KddRequestDevice Device, NTSTATUS: 0x%8x.", ntStatus);
		return ntStatus;
	}

	InfoPrint("Device Created.");

	ClearFlag(g_KddRequestDeviceObject->Flags, DO_DEVICE_INITIALIZING);

	ntStatus = IoCreateSymbolicLink(
		(&usRequestDosDeviceName),
		(&usRequestDeviceName)
	);
	if (!NT_SUCCESS(ntStatus))
	{
		InfoPrint("Error creating symbolic link to %ws, named: %ws.",
			usRequestDosDeviceName.Buffer,
			usRequestDeviceName.Buffer
		);
		IoDeleteDevice(g_KddRequestDeviceObject);
		g_KddRequestDeviceObject = NULL;
		return ntStatus;
	}

	InfoPrint("Created symbolic link to %ws, named: %ws.",
		usRequestDosDeviceName.Buffer,
		usRequestDeviceName.Buffer
	);

	return ntStatus;
}

VOID DeviceUnload(
	_In_ PDRIVER_OBJECT pDriverObject
)
{
	LARGE_INTEGER liTimeOut;
	liTimeOut.QuadPart = 20000 * RELATIVE_MILLISECOND;

	UNREFERENCED_PARAMETER(pDriverObject);

	InfoPrint("Unloading driver.");
	
	if (NULL != ptRootkitDetectionObject)
	{
		bStopDetectionThread = TRUE;

		KeWaitForSingleObject(
			(PVOID)ptRootkitDetectionObject,
			Executive,
			KernelMode,
			FALSE,
			(&liTimeOut));
		ObDereferenceObject((PVOID)ptRootkitDetectionObject);
		ptRootkitDetectionObject = NULL;
	}

	if (NULL != g_KddInfoDeviceObject)
	{
		IoDeleteSymbolicLink((&usInfoDosDeviceName));
		IoDeleteDevice(g_KddInfoDeviceObject);
		g_KddInfoDeviceObject = NULL;
	}

	if (NULL != g_KddRequestDeviceObject)
	{
		IoDeleteSymbolicLink((&usRequestDosDeviceName));
		IoDeleteDevice(g_KddRequestDeviceObject);
		g_KddRequestDeviceObject = NULL;
	}

	InfoPrint("My Driver is unloaded.");
}

NTSTATUS InitializeRootkitDetection(
	_In_ PKDD_INFORMATION_BUFFER pInformationBuffer
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	HANDLE hRootkitDetectionThread = NULL;

	InfoPrint("InitializeRootkitDetection entered.");

	//OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	//InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	ntStatus = PsCreateSystemThread(
		&hRootkitDetectionThread,
		(ACCESS_MASK)0, NULL,
		(HANDLE)0, NULL,
		RootkitDetectionRoutine,
		(PVOID)pInformationBuffer
	);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	InfoPrint("InitializeRootkitDetection thread created.");

	ntStatus = ObReferenceObjectByHandle(
		hRootkitDetectionThread,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		(PVOID*)&ptRootkitDetectionObject,
		NULL
	);
	if (!NT_SUCCESS(ntStatus))
	{
		bStopDetectionThread = TRUE;
		ptRootkitDetectionObject = NULL;
		return ntStatus;
	}

	InfoPrint("InitializeRootkitDetection object referenced created.");

	return ntStatus;
}