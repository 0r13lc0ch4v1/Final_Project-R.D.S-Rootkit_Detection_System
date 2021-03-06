// test.target_process.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int main(int argc, char *argv[])
{
	if (argc < 2) 
	{
		printf("Usage: test.target_process <PATH_TO_HOOKING_DLL>\n");
		return 0;
	}

	HMODULE hDllHandle = NULL;
	
	printf("test.target_process loading %s\n", argv[1]);

	hDllHandle = LoadLibraryA(argv[1]);
	if (NULL == hDllHandle)
	{
		printf("LoadLibraryA failed to load %s. GLE=%d", argv[1],GetLastError());
		return 0;
	}

	//HMODULE hDllHandle2 = NULL;
	//hDllHandle2 = LoadLibraryA("user-mode.detection_dll.dll");

	printf("Press ENTER to exit process!");
	getchar();
	FreeLibrary(hDllHandle);

	//FreeLibrary(hDllHandle2);


    return 0;
}

