// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "test.hook_iat.h"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	HMODULE _hModule = NULL;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "Hooking InitializeCriticalSectionAndSpinCount in IAT...", "IAT hooking dll", MB_OK);
		_hModule = GetModuleHandleA(NULL);
		if (FALSE == HookIAT(_hModule, "InitializeCriticalSectionAndSpinCount", 0xbaadf00d, NULL))
		{
			MessageBoxA(NULL, "Failed to hook InitializeCriticalSectionAndSpinCount in IAT", "IAT hooking dll", MB_OK);
			return FALSE;
		}
		else
		{
			MessageBoxA(NULL, "InitializeCriticalSectionAndSpinCount in IAT is hooked", "IAT hooking dll", MB_OK);
		}
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

