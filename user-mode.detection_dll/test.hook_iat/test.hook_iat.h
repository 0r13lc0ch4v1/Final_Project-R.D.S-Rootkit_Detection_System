#pragma once

BOOL HookIAT(
	HMODULE hInstance,
	LPCSTR targetFunction,
	DWORD newFunc,
	DWORD *oldFunc
);