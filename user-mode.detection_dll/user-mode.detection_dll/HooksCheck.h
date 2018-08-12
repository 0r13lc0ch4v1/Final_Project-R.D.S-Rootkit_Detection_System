#pragma once

#define FAR_JMP_OPCODE 0x25ff
#define NEAR_JMP_OPCODE 0xe9

#define GetRelativeJmpAddress(InstructionAddr) (LPVOID)(((DWORD)*(PDWORD)((PBYTE)InstructionAddr + 1)) + ((DWORD)InstructionAddr) + 5)
#define GetFarJmpAddress(InstructionAddr) (LPVOID)(*(PDWORD)(*(PDWORD)((PBYTE)InstructionAddr + 2)))

BOOL IsHookedJmpOutOfModule(
	_In_ CONST LPVOID lpProcAddr,
	_In_ CONST DWORD dwModuleLowRange,
	_In_ CONST DWORD dwModuleHighRange
);