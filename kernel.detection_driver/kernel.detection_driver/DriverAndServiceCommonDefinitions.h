/*++

	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
	KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
	PURPOSE.

Module Name:

	DriverAndServiceCommonDefinitions.h

Abstract:

	Definitions common to both the driver and the service.

Environment:

	User and kernel mode

--*/

#pragma once

//
// Macro to compile string as Unicode.
//
#ifndef UNICODE
#define UNICODE(quote) L##quote
#endif // !UNICODE



//
// Driver and device names.
//

#define DRIVER_NAME			 UNICODE("RootkitDetectionDriver")
#define DRIVER_NAME_WITH_EXT UNICODE("RootkitDetectionDriver.sys")

#define NT_DETECTION_DEVICE_NAME		UNICODE("\\Device\\RdsDetectionDriver")
#define DOS_DETECTION_DEVICES_LINK_NAME UNICODE("\\DosDevices\\RdsDetectionDriver")
#define WIN32_DETECTION_DEVICE_NAME		UNICODE("\\\\.\\RdsDetectionDriver")

#define NT_REQUEST_DEVICE_NAME		  UNICODE("\\Device\\RdsRequestDriver")
#define DOS_REQUEST_DEVICES_LINK_NAME UNICODE("\\DosDevices\\RdsRequestDriver")
#define WIN32_REQUEST_DEVICE_NAME	  UNICODE("\\\\.\\RdsRequestDriver")

//
// Devices types 
//
#define KDD_INFORMATION_TYPE	0xD02E
#define KDD_DRIVER_REQUEST_TYPE 0xD02F

//
// IOCTLs exposed by the driver.
//

//
// Ask from the kernel driver for information.
//
#define KDD_COMMUNICATION_GET_INFORMATION	CTL_CODE(KDD_INFORMATION_TYPE, 0xBBA, METHOD_BUFFERED, FILE_READ_ACCESS)

//
// Ask the kernel driver if it needs something.
//
#define KDD_COMMUNICATION_GET_REQUEST		CTL_CODE(KDD_DRIVER_REQUEST_TYPE, 0xBBB, METHOD_BUFFERED, FILE_READ_ACCESS)

//
// Replay to the kernel driver request.
//
#define KDD_COMMUNICATION_SEND_RESPONSE		CTL_CODE(KDD_DRIVER_REQUEST_TYPE, 0xBBC, METHOD_BUFFERED, FILE_READ_ACCESS)

//
// KDD_RT - To state the type of the request (Request Type).
//
#define KDD_RT_NO_TYPE 0x0
#define KDD_RT_GET_INFORMATION 0x1 // KDD_COMMUNICATION_GET_INFORMATION
#define KDD_RT_GET_REQUEST     0x2 // KDD_COMMUNICATION_GET_REQUEST
#define KDD_RT_SEND_RESPONSE   0x3 // KDD_COMMUNICATION_SEND_RESPONSE

//
// The buffer length for the kernel-service communication.
//
#define INFORMATION_BUFFER_LENGTH 0x10000

//
// The convention for data transfer format.
//
typedef struct _KDD_INFORMATION_BUFFER {
	CHAR	pszInformationBuffer[INFORMATION_BUFFER_LENGTH];
	ULONG	ulInformationBufferLength;
	USHORT  usInformationType;
}	KDD_INFORMATION_BUFFER, *PKDD_INFORMATION_BUFFER;