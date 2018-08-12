#include "RootkitDetection.h"
#include "HooksChecker.h"

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

	if (dwModuleLowRange >= dwModuleHighRange)
	{
		return FALSE;
	}
	try {
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
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}

	return (((DWORD)lpProcAddr >= dwModuleLowRange) &&
		((DWORD)lpProcAddr <= dwModuleHighRange)) ?
		FALSE : TRUE;
}