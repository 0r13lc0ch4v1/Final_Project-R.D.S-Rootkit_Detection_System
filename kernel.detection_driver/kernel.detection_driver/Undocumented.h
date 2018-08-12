#pragma once

BOOLEAN StringToStringStruct(
	_In_ CONST PCHAR pszString,
	_Out_ PSTRING strStringStruct
);

PVOID KernelGetModuleBase(
	_In_ CONST PCHAR pModuleName,
	_Out_ PULONG ulImageSize
);