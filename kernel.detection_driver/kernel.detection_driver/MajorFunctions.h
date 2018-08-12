#ifndef MAJOR_FUNCTIONS_H_
#define MAJOR_FUNCTIONS_H_


NTSTATUS KddCreateDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
);

NTSTATUS KddCloseDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
);

NTSTATUS KddUnsupportedFunctions(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
);

NTSTATUS KddDeviceControl(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
);

NTSTATUS KddReadWrite(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp
);

NTSTATUS KddCleanup(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KddCreateDevice)
#pragma alloc_text(PAGE, KddCloseDevice)
#pragma alloc_text(PAGE, KddUnsupportedFunctions)
#pragma alloc_text(PAGE, KddDeviceControl)
#pragma alloc_text(PAGE, KddReadWrite)
#pragma alloc_text(PAGE, KddCleanup)
#endif // ALLOC_PRAGMA

#endif // !MAJOR_FUNCTIONS_H_