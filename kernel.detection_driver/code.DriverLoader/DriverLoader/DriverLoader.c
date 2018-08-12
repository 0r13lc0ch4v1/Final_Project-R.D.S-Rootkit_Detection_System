#include <Windows.h>
#include <tchar.h>

#define DRIVER_NAME _T("RootkitDetectionDriver")
#define DRIVER_DESCRIPTION _T("RootkitDetection Driver")
#define DRIVER_PATH _T("C:\\Users\\Windows7-x86\\Desktop\\kernel.detection_driver.sys")


int wmain(int argc, wchar_t ** argv)
{
	HANDLE service_manager;
	HANDLE service;
	SERVICE_STATUS status;

#ifndef DRIVER_NAME
	wchar_t * DRIVER_NAME = NULL;
	wchar_t * DRIVER_DESCRIPTION = NULL;
	wchar_t * DRIVER_PATH = NULL;
	if (argc < 4)
	{
		_tprintf(_T("Usage: DriverLoader <DRIVER_NAME> <DRIVER_DESCRIPTION> <DRIVER_PATH>\n"));
		return 0;
	}
	else
	{
		DRIVER_NAME = argv[1];
		DRIVER_DESCRIPTION = argv[2];
		DRIVER_PATH = argv[3];
	}
#endif
		_tprintf(_T("Driver Name: %s\n"), DRIVER_NAME);
		_tprintf(_T("Driver Description: %s\n"), DRIVER_DESCRIPTION);
		_tprintf(_T("Driver Path: %s\n\n"), DRIVER_PATH);


	service_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	_tprintf(_T("Driver Loader:\n\n"));

	if (service_manager)
	{
		_tprintf(_T("Press Enter to create kernel service driver %s\n"), DRIVER_NAME);
		getchar();
		service = CreateService(service_manager, DRIVER_NAME, DRIVER_DESCRIPTION,
			SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
			DRIVER_PATH, NULL, NULL, NULL, NULL, NULL);

		if (!service)
		{
			_tprintf(_T("%s service already exists\n"), DRIVER_NAME);
			service = OpenService(service_manager, DRIVER_NAME, SERVICE_START | DELETE | SERVICE_STOP);
		}

		if (NULL == service || INVALID_HANDLE_VALUE == service)
		{
			_tprintf(_T("Failed to Create/Open %s - GLE: %d\n"), DRIVER_NAME, GetLastError());
			goto cleanup;
		}

		_tprintf(_T("Press Enter to start %s service\n"), DRIVER_NAME);
		getchar();
		if (StartService(service, 0, NULL))
		{
			_tprintf(_T("%s service started\n"), DRIVER_NAME);
		}
		else
		{
			_tprintf(_T("StartService failed to start %s - GLE: %d\n"), DRIVER_NAME, GetLastError());
		}
		_tprintf(_T("\nPress Enter to close %s service\n"), DRIVER_NAME);
		getchar();
		if (ControlService(service, SERVICE_CONTROL_STOP, &status))
		{
			_tprintf(_T("%s driver stoped\n"), DRIVER_NAME);
		}
		else
		{
			_tprintf(_T("ControlService failed to stop %s driver - GLE: %d\n"), DRIVER_NAME, GetLastError());
		}
		_tprintf(_T("Press Enter to delete %s service\n"), DRIVER_NAME);
		getchar();
		if (DeleteService(service))
		{
			_tprintf(_T("%s driver deleted\n"), DRIVER_NAME);
		}
		else
		{
			_tprintf(_T("DeleteService failed to delete %s driver - GLE: %d\n"), DRIVER_NAME, GetLastError());
		}
		CloseServiceHandle(service);
	cleanup:
		CloseServiceHandle(service_manager);
	}
	getchar();

	return 0;
}
