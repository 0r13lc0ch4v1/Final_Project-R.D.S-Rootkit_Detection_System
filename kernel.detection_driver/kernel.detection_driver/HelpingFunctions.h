#ifndef HELPING_FUNCTIONS_H_
#define HELPING_FUNCTIONS_H_

NTSTATUS WriteDataToOutputBuffer(
	_In_  PIRP					  pIrp,
	_In_  PIO_STACK_LOCATION      pIrpStackLocation,
	_In_  PKDD_INFORMATION_BUFFER pKddDeviceBuffer,
	_In_  PFAST_MUTEX			  pfmMutex,
	_Out_ PULONG                  pulDataWritten
);

NTSTATUS SendDetectionInformation(
	_In_  PIRP					  pIrp,
	_In_  PIO_STACK_LOCATION      pIrpStackLocation,
	_In_  PKDD_INFORMATION_BUFFER pKddDeviceBuffer,
	_In_  PFAST_MUTEX			  pfmMutex,
	_Out_ PULONG                  pulDataWritten
);

NTSTATUS SendRequest(
	_In_  PIRP					  pIrp,
	_In_  PIO_STACK_LOCATION      pIrpStackLocation,
	_In_  PKDD_INFORMATION_BUFFER pKddDeviceBuffer,
	_In_  PFAST_MUTEX			  pfmMutex,
	_Out_ PULONG                  pulDataWritten
);

NTSTATUS GetResponse(
	_In_  PIRP					  pIrp,
	_In_  PIO_STACK_LOCATION      pIrpStackLocation,
	_In_  PKDD_INFORMATION_BUFFER pKddDeviceBuffer,
	_In_  PFAST_MUTEX			  pfmMutex,
	_Out_ PULONG                  pulDataWritten
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, WriteDataToOutputBuffer)
#pragma alloc_text(PAGE, SendDetectionInformation)
#pragma alloc_text(PAGE, SendRequest)
#pragma alloc_text(PAGE, GetResponse)
#endif // ALLOC_PRAGMA

#endif // !HELPING_FUNCTIONS_H_
