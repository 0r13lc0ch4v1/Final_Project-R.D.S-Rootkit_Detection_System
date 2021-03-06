// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "test.hook_inline.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "Hooking InitializeCriticalSectionAndSpinCount Inline...", "Inline hooking dll", MB_OK);
		if (FALSE == HookInline("Kernel32.dll", "InitializeCriticalSectionAndSpinCount", (DWORD)MyFunction, NULL))
		{
			MessageBoxA(NULL, "Failed to hook InitializeCriticalSectionAndSpinCount in IAT", "IAT hooking dll", MB_OK);
			return FALSE;
		}
		else
		{
			MessageBoxA(NULL, "InitializeCriticalSectionAndSpinCount is Inline hooked", "Inline hooking dll", MB_OK);
		}
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

