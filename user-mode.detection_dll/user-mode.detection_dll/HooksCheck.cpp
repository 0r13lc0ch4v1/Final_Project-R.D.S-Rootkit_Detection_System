#include "stdafx.h"
#include "HooksCheck.h"
#include "DetectionModule.h"

BOOL IsAddressInLegitModule(
	_In_ CONST LPVOID lpProcAddr
)
{
	BOOL bIsLegit = FALSE;

	if (IsAddressInModuleRange((PCHAR)"ntdll.dll", lpProcAddr))
	{
		bIsLegit = TRUE;
	}
	else if (IsAddressInModuleRange((PCHAR)"KernelBase.dll", lpProcAddr))
	{
		bIsLegit = TRUE;
	}
	else if (IsAddressInModuleRange((PCHAR)"kernel32.dll", lpProcAddr))
	{
		bIsLegit = TRUE;
	}

	return bIsLegit;
}

BOOL IsHookedJmpOutOfModule(
	_In_ CONST LPVOID lpProcAddr,
	_In_ CONST DWORD dwModuleLowRange,
	_In_ CONST DWORD dwModuleHighRange
)
{
	if ((dwModuleLowRange >= dwModuleHighRange) || (NULL == lpProcAddr))
	{
		return FALSE;
	}
	__try {
		if (NEAR_JMP_OPCODE == *(PBYTE)lpProcAddr)
		{
			return IsHookedJmpOutOfModule(
				GetRelativeJmpAddress(lpProcAddr),
				dwModuleLowRange,
				dwModuleHighRange
			);
		}
		else if (FAR_JMP_OPCODE == *(PWORD)lpProcAddr)
		{
			return IsHookedJmpOutOfModule(
				GetFarJmpAddress(lpProcAddr),
				dwModuleLowRange,
				dwModuleHighRange
			);
		}
	}
	__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		return TRUE;
	}

	BOOLEAN bIsInRange = (((DWORD)lpProcAddr >= dwModuleLowRange) && ((DWORD)lpProcAddr <= dwModuleHighRange));

	if (FALSE == bIsInRange)
	{
		// If the address is inside a legit module
		if (TRUE == IsAddressInLegitModule(lpProcAddr))
		{
			// Not hooked
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}
	else
	{
		// The function is inside the calling module - Not hooked
		return FALSE;
	}
}