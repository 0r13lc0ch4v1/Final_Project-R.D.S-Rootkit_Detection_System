#include "RootkitDetection.h"
#include "HelpingFunctions.h"


NTSTATUS WriteDataToOutputBuffer(
	_In_  PIRP					  pIrp,
	_In_  PIO_STACK_LOCATION      pIrpStackLocation,
	_In_  PKDD_INFORMATION_BUFFER pKddDeviceBuffer,
	_In_  PFAST_MUTEX			  pfmMutex,
	_Out_ PULONG                  pulDataWritten
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PKDD_DETECTION_REQUEST pInformationRequest = NULL;
	ULONG ulOutputBufferLength = 0;

	//InfoPrint("WriteDataToOutputBuffer Entered.");

	//NT_ASSERT(pIrp->AssociatedIrp.SystemBuffer != NULL);

	pInformationRequest = (PKDD_DETECTION_REQUEST)(pIrp->AssociatedIrp).SystemBuffer;
	ulOutputBufferLength = ((pIrpStackLocation->Parameters).DeviceIoControl).OutputBufferLength;
	if (NULL == pInformationRequest ||
		ulOutputBufferLength != sizeof(KDD_DETECTION_REQUEST) ||
		ulOutputBufferLength - sizeof(ULONG) + sizeof(USHORT) < pInformationRequest->ulInformationBufferLength)
	{
		ntStatus = STATUS_INVALID_BUFFER_SIZE;
		(*pulDataWritten) = 0;
		goto EndRequest;
	}
	
	//LARGE_INTEGER liSleepTime;
	//liSleepTime.QuadPart = 1000000;
	//KeDelayExecutionThread(KernelMode, FALSE, (&liSleepTime)); // Give the detection module a chance to write information.
	if (TRUE == ExTryToAcquireFastMutex(pfmMutex))
	{
		if (pKddDeviceBuffer->ulInformationBufferLength <= pInformationRequest->ulInformationBufferLength)
		{
			(*pulDataWritten) = pKddDeviceBuffer->ulInformationBufferLength;
		}
		else
		{
			(*pulDataWritten) = pInformationRequest->ulInformationBufferLength;
		}

		if ((0 != (*pulDataWritten)) &&
			('\0' != (pKddDeviceBuffer->pszInformationBuffer)[0]))
		{
			//InfoPrint("WriteDataToOutputBuffer writing detection information memory %d bytes.", (*pulDataWritten));
			RtlCopyMemory((PVOID)(pInformationRequest->pszInformationBuffer), (PVOID)(pKddDeviceBuffer->pszInformationBuffer), (*pulDataWritten));
		}
		ExReleaseFastMutex(pfmMutex);
		ntStatus = STATUS_SUCCESS;
	}
	else
	{
		(*pulDataWritten) = 0;
		ntStatus = STATUS_SUCCESS;
	}

EndRequest:
	return ntStatus;
}

NTSTATUS SendDetectionInformation(
	_In_  PIRP					  pIrp,
	_In_  PIO_STACK_LOCATION      pIrpStackLocation,
	_In_  PKDD_INFORMATION_BUFFER pKddDeviceBuffer,
	_In_  PFAST_MUTEX			  pfmMutex,
	_Out_ PULONG                  pulDataWritten
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	//InfoPrint("SendDetectionInformation Entered.");

	ntStatus = WriteDataToOutputBuffer(
		pIrp,
		pIrpStackLocation,
		pKddDeviceBuffer,
		pfmMutex,
		pulDataWritten
	);

	return ntStatus;
}

NTSTATUS SendRequest(
	_In_  PIRP					  pIrp,
	_In_  PIO_STACK_LOCATION      pIrpStackLocation,
	_In_  PKDD_INFORMATION_BUFFER pKddDeviceBuffer,
	_In_  PFAST_MUTEX			  pfmMutex,
	_Out_ PULONG                  pulDataWritten
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	//InfoPrint("SendRequest Entered.");

	ntStatus = WriteDataToOutputBuffer(
		pIrp, 
		pIrpStackLocation, 
		pKddDeviceBuffer, 
		pfmMutex, 
		pulDataWritten
	);

	return ntStatus;
}

NTSTATUS GetResponse(
	_In_  PIRP					  pIrp,
	_In_  PIO_STACK_LOCATION      pIrpStackLocation,
	_In_  PKDD_INFORMATION_BUFFER pKddDeviceBuffer,
	_In_  PFAST_MUTEX			  pfmMutex,
	_Out_ PULONG                  pulDataReaden
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PKDD_DETECTION_RESPONSE pInformationResponse = NULL;
	ULONG ulInputBufferLength = 0;

	//InfoPrint("GetResponse Entered.");

	//NT_ASSERT(pIrp->AssociatedIrp.SystemBuffer != NULL);

	pInformationResponse = (PKDD_DETECTION_RESPONSE)(pIrp->AssociatedIrp).SystemBuffer;
	ulInputBufferLength = ((pIrpStackLocation->Parameters).DeviceIoControl).InputBufferLength;
	if (NULL == pInformationResponse ||
		ulInputBufferLength != sizeof(KDD_DETECTION_RESPONSE) ||
		ulInputBufferLength - sizeof(ULONG) + sizeof(USHORT) < pInformationResponse->ulInformationBufferLength)
	{
		ntStatus = STATUS_INVALID_BUFFER_SIZE;
		(*pulDataReaden) = 0;
		goto EndRequest;
	}

	if (TRUE == ExTryToAcquireFastMutex(pfmMutex))
	{
		if (pInformationResponse->ulInformationBufferLength <= (sizeof(pKddDeviceBuffer->pszInformationBuffer) - 1))
		{
			(*pulDataReaden) = pInformationResponse->ulInformationBufferLength;
		}
		else
		{
			(*pulDataReaden) = pKddDeviceBuffer->ulInformationBufferLength;
		}

		if ((0 != (*pulDataReaden)) &&
			('\0' != (pKddDeviceBuffer->pszInformationBuffer)[0]))
		{
			//InfoPrint("GetResponse writing detection information buffer %d bytes.", (*pulDataReaden));
			RtlCopyMemory((PVOID)(pKddDeviceBuffer->pszInformationBuffer), (PVOID)(pInformationResponse->pszInformationBuffer), (*pulDataReaden));
			//InfoPrint("GetResponse got \"%s\" from service.", pKddDeviceBuffer->pszInformationBuffer);
		}
		ExReleaseFastMutex(pfmMutex);
	}
	else
	{
		(*pulDataReaden) = 0;
		ntStatus = STATUS_SUCCESS;
	}

	ntStatus = STATUS_SUCCESS;

EndRequest:
	return ntStatus;
}