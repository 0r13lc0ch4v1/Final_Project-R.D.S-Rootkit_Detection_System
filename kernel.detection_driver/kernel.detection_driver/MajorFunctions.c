#include "RootkitDetection.h"
#include "MajorFunctions.h"
#include "HelpingFunctions.h"


NTSTATUS KddCreateDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	//InfoPrint("KddCreateDevice is called.");

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = FILE_OPENED;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS KddCloseDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	//InfoPrint("KddCommunicationCloseDevice is called.");

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS KddUnsupportedFunctions(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
)
{
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	//InfoPrint("KddUnsupportedFunctions - Unsupported Major Function Requested. Returning STATUS_NOT_SUPPORTED.");

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS KddDeviceControl(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
)
{
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pIrpStackLocation = NULL;
	ULONG ulNumberOfBytes = 0;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	//InfoPrint("KddDeviceControl Entered.");

	pIrpStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	if (NULL != pIrpStackLocation)
	{
		switch (pIrpStackLocation->Parameters.DeviceIoControl.IoControlCode)
		{
		case KDD_COMMUNICATION_GET_INFORMATION:
			//InfoPrint("KddDeviceControl GET_INFORMATION received.");

			if (KDD_INFORMATION_TYPE != pDeviceObject->DeviceType)
			{
				ulNumberOfBytes = 0;
				ntStatus = STATUS_INVALID_DEVICE_REQUEST;
				goto CompleteRequest;
			}

			IoMarkIrpPending(pIrp);
			ntStatus = SendDetectionInformation(
				pIrp,
				pIrpStackLocation,
				&KddInformationBuffer,
				&fmInformationMutex,
				&ulNumberOfBytes
			);
			break;
		case KDD_COMMUNICATION_GET_REQUEST:
			//InfoPrint("KddDeviceControl GET_REQUEST received.");

			if (KDD_DRIVER_REQUEST_TYPE != pDeviceObject->DeviceType)
			{
				ulNumberOfBytes = 0;
				ntStatus = STATUS_INVALID_DEVICE_REQUEST;
				goto CompleteRequest;
			}

			IoMarkIrpPending(pIrp);
			ntStatus = SendRequest(
				pIrp,
				pIrpStackLocation,
				&KddResponseBuffer,
				&fmSendRequestMutex,
				&ulNumberOfBytes
			);
			break;
		case KDD_COMMUNICATION_SEND_RESPONSE:

			//InfoPrint("KddDeviceControl SEND_RESPONSE received.");

			if (KDD_DRIVER_REQUEST_TYPE != pDeviceObject->DeviceType)
			{
				ulNumberOfBytes = 0;
				ntStatus = STATUS_INVALID_DEVICE_REQUEST;
				goto CompleteRequest;
			}

			IoMarkIrpPending(pIrp);
			ntStatus = GetResponse(
				pIrp,
				pIrpStackLocation,
				&KddRequestBuffer,
				&fmGetResponseMutex,
				&ulNumberOfBytes
			);
			break;
		default:
			//InfoPrint("KddDeviceControl default.");
			ulNumberOfBytes = 0;
			ntStatus = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}

CompleteRequest:
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = ulNumberOfBytes;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS KddReadWrite(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP pIrp
)
{
	NTSTATUS ntStatus = STATUS_INVALID_DEVICE_REQUEST;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	//InfoPrint("KddReadWrite Entered.");

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS KddCleanup(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);

	PAGED_CODE();

	InfoPrint("KddCleanup entered.");

	//clean the detection buffer?

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}