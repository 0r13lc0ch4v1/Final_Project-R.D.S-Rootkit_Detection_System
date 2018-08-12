/*++

	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
	KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
	PURPOSE.

Module Name:

	RootkitDetectorModule.h

Abstract:

	Header file for the Rootkit detection module

Environment:

	Kernel mode only

--*/

#pragma once


typedef struct _SYSTEM_SERVICE_TABLE {
	PDWORD			ServiceTable;
	PDWORD			CounterTable;
	DWORD			ServiceLimit;
	PBYTE			ArgumentTable;
}	SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

VOID FormatString(
	_Out_ NTSTRSAFE_PSTR	  pszBuffer,
	_In_ CONST ULONG		  ulBufferSize,
	_In_ CONST NTSTRSAFE_PSTR pszFormat,
	...
);

BOOL ScanSsdtForHooks(
	_Out_ NTSTRSAFE_PSTR pszBuffer,
	_In_ CONST ULONG	 ulBufferSize,
	_In_ CONST BOOLEAN   bCheckInline
);

VOID RootkitDetectionRoutine(
	_In_ PVOID pInformationBuffer
);