#ifndef ENTRY_H_
#define ENTRY_H_

/*++

Routine Description:

	This routine is called by the operating system to initialize the driver.
	It allocates two device objects, initialize the detection thread, and 
	creates a symbolic link to make the device accessible to Win32.

Arguments:

DriverObject - Supplies the system control object for this test driver.

RegistryPath - The string location of the driver's corresponding services
key in the registry.

Return value:

Success or appropriate failure code.

--*/
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  pDriverObject,
	_In_ PUNICODE_STRING pRegistryPath
);

NTSTATUS InitUnicodeStrings();

VOID SetMajorFunctions(
	_In_ PDRIVER_OBJECT pDriverObject
);

NTSTATUS SetupInfoDevice(
	_In_ PDRIVER_OBJECT pDriverObject
);

NTSTATUS SetupRequestDevice(
	_In_ PDRIVER_OBJECT	pDriverObject
);

VOID DeviceUnload(
	_In_ PDRIVER_OBJECT pDriverObject
);

NTSTATUS InitializeRootkitDetection(
	_In_ PKDD_INFORMATION_BUFFER pInformationBuffer
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, InitUnicodeStrings)
#pragma alloc_text(PAGE, SetMajorFunctions)
#pragma alloc_text(PAGE, SetupInfoDevice)
#pragma alloc_text(PAGE, SetupRequestDevice)
#pragma alloc_text(PAGE, DeviceUnload)
#pragma alloc_text(PAGE, InitializeRootkitDetection)
#endif // ALLOC_PRAGMA

#endif // !ENTRY_H_