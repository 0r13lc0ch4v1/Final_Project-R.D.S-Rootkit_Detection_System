// ui.rds_notification_icon.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "IpcPipeClient.h"
#include "ui.rds_notification_icon.h"

#define MAX_LOADSTRING 100

// Use a guid to uniquely identify our icon
class __declspec(uuid("478b349a-4070-4821-bb73-cdfc8a75feb6")) RdsIcon;

// Global Variables:
HINSTANCE g_hInst;                               // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

UINT const WMAPP_NOTIFYCALLBACK = WM_APP + 1;
UINT const WMAPP_HIDEFLYOUT = WM_APP + 2;

UINT_PTR const HIDEFLYOUT_TIMER_ID = 1;

wchar_t const szFlyoutWindowClass[] = L"RdsNotificationFlyout";

// Forward declarations of functions included in this code module:
ATOM                RegisterWindowClass(HINSTANCE hInstance, PCWSTR pszClassName, LPWSTR pszMenuName, WNDPROC lpfnWndProc);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
BOOL				AddNotificationIcon(HWND);
BOOL				DeleteNotificationIcon();
HWND                ShowFlyout(HWND hwnd);
void                HideFlyout(HWND hwndMainWindow, HWND hwndFlyout);
void                PositionFlyout(HWND hwnd, REFGUID guidIcon);
void                ShowContextMenu(HWND hwnd, POINT pt);
BOOL ShowUsermodeDetectionBalloon();
BOOL ShowKernelmodeDetectionBalloon();
BOOL                RestoreTooltip();
void FlyoutPaint(HWND hwnd, HDC hdc);
LRESULT CALLBACK FlyoutWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
DWORD WINAPI UserspaceListenerThread(
	_In_ LPVOID lpParameter
);
DWORD WINAPI KernelpaceListenerThread(
	_In_ LPVOID lpParameter
);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	// TODO: Place code here.

	// Try to open the mutex.
	HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, 0, TEXT("RdsNotificationApp"));
	if (!hMutex)
	{
		hMutex = CreateMutex(0, 0, TEXT("RdsNotificationApp"));
	}
	else
	{
		MessageBox(NULL,
			L"One instance of this application is already running",
			L"Error open application", MB_OK);
		return 0;
	}


	// Initialize global strings
	LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadStringW(hInstance, IDC_UIRDSNOTIFICATIONICON, szWindowClass, MAX_LOADSTRING);

	RegisterWindowClass(hInstance, szWindowClass, MAKEINTRESOURCEW(IDC_UIRDSNOTIFICATIONICON), WndProc);
	RegisterWindowClass(hInstance, szFlyoutWindowClass, NULL, FlyoutWndProc);

	// Perform application initialization:
	//if (!InitInstance(hInstance, nCmdShow))
	if (!InitInstance(hInstance, SW_HIDE))
	{
		return FALSE;
	}

	HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_UIRDSNOTIFICATIONICON));

	
	HANDLE hUserspaceThread = NULL;
	DWORD dwUserspaceThreadId = 0;

	hUserspaceThread = CreateThread(
		NULL,
		0,
		LPTHREAD_START_ROUTINE(UserspaceListenerThread),
		NULL,
		0,
		(&dwUserspaceThreadId)
	);
	if (NULL == hUserspaceThread)
	{
		//TO-DO
	}

	HANDLE hKernelspaceThread = NULL;
	DWORD dwKernelspaceThreadId = 0;

	hKernelspaceThread = CreateThread(
		NULL,
		0,
		LPTHREAD_START_ROUTINE(KernelpaceListenerThread),
		NULL,
		0,
		(&dwKernelspaceThreadId)
	);
	if (NULL == hKernelspaceThread)
	{
		//TO-DO
	}

	MSG msg;
	// Main message loop:
	while (GetMessage(&msg, nullptr, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	CloseHandle(hUserspaceThread);
	ReleaseMutex(hMutex);
	return (int)msg.wParam;
}

ATOM RegisterWindowClass(HINSTANCE hInstance, PCWSTR pszClassName, LPWSTR pszMenuName, WNDPROC lpfnWndProc)
{
	WNDCLASSEXW wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = lpfnWndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_UIRDSNOTIFICATIONICON));
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = pszMenuName;
	wcex.lpszClassName = pszClassName;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	g_hInst = hInstance; // Store instance handle in our global variable

	HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

	if (!hWnd)
	{
		return FALSE;
	}

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	static HWND s_hwndFlyout = NULL;
	static BOOL s_fCanShowFlyout = TRUE;

	switch (message)
	{
	case WM_CREATE:
		// add the notification icon
		if (!AddNotificationIcon(hWnd))
		{
			MessageBox(hWnd,
				L"Please read the ReadMe.txt file for troubleshooting",
				L"Error adding icon", MB_OK);
			return -1;
		}
		break;
	case WM_COMMAND:
	{
		int wmId = LOWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(g_hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
	}
	break;

	case WM_DESTROY:
		DeleteNotificationIcon();
		PostQuitMessage(0);
		break;

	case WMAPP_NOTIFYCALLBACK:
		switch (LOWORD(lParam))
		{
		case NIN_SELECT:
			// for NOTIFYICON_VERSION_4 clients, NIN_SELECT is prerable to listening to mouse clicks and key presses
			// directly.
			if (IsWindowVisible(s_hwndFlyout))
			{
				HideFlyout(hWnd, s_hwndFlyout);
				s_hwndFlyout = NULL;
				s_fCanShowFlyout = FALSE;
			}
			else if (s_fCanShowFlyout)
			{
				s_hwndFlyout = ShowFlyout(hWnd);
			}
			break;

		case NIN_BALLOONTIMEOUT:
			RestoreTooltip();
			break;

		case NIN_BALLOONUSERCLICK:
			RestoreTooltip();
			// placeholder for the user clicking on the balloon.
			MessageBox(hWnd, L"The user clicked on the balloon.", L"User click", MB_OK);
			break;

		case WM_CONTEXTMENU:
		{
			POINT const pt = { LOWORD(wParam), HIWORD(wParam) };
			ShowContextMenu(hWnd, pt);
		}
		break;
		}
		break;

	case WMAPP_HIDEFLYOUT:
		HideFlyout(hWnd, s_hwndFlyout);
		s_hwndFlyout = NULL;
		s_fCanShowFlyout = FALSE;
		break;
	case WM_TIMER:
		if (wParam == HIDEFLYOUT_TIMER_ID)
		{
			// please see the comment in HideFlyout() for an explanation of this code.
			KillTimer(hWnd, HIDEFLYOUT_TIMER_ID);
			s_fCanShowFlyout = TRUE;
		}
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

BOOL AddNotificationIcon(HWND hwnd)
{
	NOTIFYICONDATA nid = { sizeof(nid) };
	nid.hWnd = hwnd;
	// add the icon, setting the icon, tooltip, and callback message.
	// the icon will be identified with the GUID
	nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_SHOWTIP | NIF_GUID;
	nid.guidItem = __uuidof(RdsIcon);
	nid.uCallbackMessage = WMAPP_NOTIFYCALLBACK;
	LoadIconMetric(g_hInst, MAKEINTRESOURCE(IDI_SMALL), LIM_SMALL, &nid.hIcon);
	LoadString(g_hInst, IDS_TOOLTIP, nid.szTip, ARRAYSIZE(nid.szTip));
	Shell_NotifyIcon(NIM_ADD, &nid);

	// NOTIFYICON_VERSION_4 is prefered
	nid.uVersion = NOTIFYICON_VERSION_4;
	return Shell_NotifyIcon(NIM_SETVERSION, &nid);
}

BOOL DeleteNotificationIcon()
{
	NOTIFYICONDATA nid = { sizeof(nid) };
	nid.uFlags = NIF_GUID;
	nid.guidItem = __uuidof(RdsIcon);
	return Shell_NotifyIcon(NIM_DELETE, &nid);
}

void PositionFlyout(HWND hwnd, REFGUID guidIcon)
{
	// find the position of our printer icon
	NOTIFYICONIDENTIFIER nii = { sizeof(nii) };
	nii.guidItem = guidIcon;
	RECT rcIcon;
	HRESULT hr = Shell_NotifyIconGetRect(&nii, &rcIcon);
	if (SUCCEEDED(hr))
	{
		// display the flyout in an appropriate position close to the printer icon
		POINT const ptAnchor = { (rcIcon.left + rcIcon.right) / 2, (rcIcon.top + rcIcon.bottom) / 2 };

		RECT rcWindow;
		GetWindowRect(hwnd, &rcWindow);
		SIZE sizeWindow = { rcWindow.right - rcWindow.left, rcWindow.bottom - rcWindow.top };

		if (CalculatePopupWindowPosition(&ptAnchor, &sizeWindow, TPM_VERTICAL | TPM_VCENTERALIGN | TPM_CENTERALIGN | TPM_WORKAREA, &rcIcon, &rcWindow))
		{
			// position the flyout and make it the foreground window
			SetWindowPos(hwnd, HWND_TOPMOST, rcWindow.left, rcWindow.top, 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW);
		}
	}
}

HWND ShowFlyout(HWND hwndMainWindow)
{
	// size of the bitmap image (which will be the client area of the flyout window).
	RECT rcWindow = {};
	rcWindow.right = 309;
	rcWindow.bottom = 163;
	DWORD const dwStyle = WS_POPUP | WS_THICKFRAME;
	// adjust the window size to take the frame into account
	AdjustWindowRectEx(&rcWindow, dwStyle, FALSE, WS_EX_TOOLWINDOW);

	HWND hwndFlyout = CreateWindowEx(WS_EX_TOOLWINDOW, szFlyoutWindowClass, NULL, dwStyle,
		CW_USEDEFAULT, 0, rcWindow.right - rcWindow.left, rcWindow.bottom - rcWindow.top, hwndMainWindow, NULL, g_hInst, NULL);
	if (hwndFlyout)
	{
		PositionFlyout(hwndFlyout, __uuidof(RdsIcon));
		SetForegroundWindow(hwndFlyout);
	}
	return hwndFlyout;
}

void HideFlyout(HWND hwndMainWindow, HWND hwndFlyout)
{
	DestroyWindow(hwndFlyout);

	// immediately after hiding the flyout we don't want to allow showing it again, which will allow clicking
	// on the icon to hide the flyout. If we didn't have this code, clicking on the icon when the flyout is open
	// would cause the focus change (from flyout to the taskbar), which would trigger hiding the flyout
	// (see the WM_ACTIVATE handler). Since the flyout would then be hidden on click, it would be shown again instead
	// of hiding.
	SetTimer(hwndMainWindow, HIDEFLYOUT_TIMER_ID, GetDoubleClickTime(), NULL);
}

void ShowContextMenu(HWND hwnd, POINT pt)
{
	HMENU hMenu = LoadMenu(g_hInst, MAKEINTRESOURCE(IDC_CONTEXTMENU));
	if (hMenu)
	{
		HMENU hSubMenu = GetSubMenu(hMenu, 0);
		if (hSubMenu)
		{
			// our window must be foreground before calling TrackPopupMenu or the menu will not disappear when the user clicks away
			SetForegroundWindow(hwnd);

			// respect menu drop alignment
			UINT uFlags = TPM_RIGHTBUTTON;
			if (GetSystemMetrics(SM_MENUDROPALIGNMENT) != 0)
			{
				uFlags |= TPM_RIGHTALIGN;
			}
			else
			{
				uFlags |= TPM_LEFTALIGN;
			}

			TrackPopupMenuEx(hSubMenu, uFlags, pt.x, pt.y, hwnd, NULL);
		}
		DestroyMenu(hMenu);
	}
}

BOOL ShowUsermodeDetectionBalloon()
{
	// Display a detection balloon message. This is a warning, so show the appropriate system icon.
	NOTIFYICONDATA nid = { sizeof(nid) };
	nid.uFlags = NIF_INFO | NIF_GUID;
	nid.guidItem = __uuidof(RdsIcon);
	// respect quiet time since this balloon did not come from a direct user action.
	nid.dwInfoFlags = NIIF_WARNING | NIIF_RESPECT_QUIET_TIME;
	LoadString(g_hInst, IDS_RDS_TITLE, nid.szInfoTitle, ARRAYSIZE(nid.szInfoTitle));
	LoadString(g_hInst, IDS_USERMODE_TEXT, nid.szInfo, ARRAYSIZE(nid.szInfo));
	return Shell_NotifyIcon(NIM_MODIFY, &nid);
}

BOOL ShowKernelmodeDetectionBalloon()
{
	// Display a detection balloon message. This is a warning, so show the appropriate system icon.
	NOTIFYICONDATA nid = { sizeof(nid) };
	nid.uFlags = NIF_INFO | NIF_GUID;
	nid.guidItem = __uuidof(RdsIcon);
	// respect quiet time since this balloon did not come from a direct user action.
	nid.dwInfoFlags = NIIF_WARNING | NIIF_RESPECT_QUIET_TIME;
	LoadString(g_hInst, IDS_RDS_TITLE, nid.szInfoTitle, ARRAYSIZE(nid.szInfoTitle));
	LoadString(g_hInst, IDS_KERNELMODE_TEXT, nid.szInfo, ARRAYSIZE(nid.szInfo));
	return Shell_NotifyIcon(NIM_MODIFY, &nid);
}

BOOL RestoreTooltip()
{
	// After the balloon is dismissed, restore the tooltip.
	NOTIFYICONDATA nid = { sizeof(nid) };
	nid.uFlags = NIF_SHOWTIP | NIF_GUID;
	nid.guidItem = __uuidof(RdsIcon);
	return Shell_NotifyIcon(NIM_MODIFY, &nid);
}

void FlyoutPaint(HWND hwnd, HDC hdc)
{
	// Since this is a DPI aware application (see DeclareDPIAware.manifest), if the flyout window
	// were to show text we would need to increase the size. We could also have multiple sizes of
	// the bitmap image and show the appropriate image for each DPI, but that would complicate the
	// sample.
	static HBITMAP hbmp = NULL;
	if (hbmp == NULL)
	{
		hbmp = (HBITMAP)LoadImage(g_hInst, MAKEINTRESOURCE(IDB_RDS), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);
	}
	if (hbmp)
	{
		RECT rcClient;
		GetClientRect(hwnd, &rcClient);
		HDC hdcMem = CreateCompatibleDC(hdc);
		if (hdcMem)
		{
			HGDIOBJ hBmpOld = SelectObject(hdcMem, hbmp);
			BitBlt(hdc, 0, 0, rcClient.right, rcClient.bottom, hdcMem, 0, 0, SRCCOPY);
			SelectObject(hdcMem, hBmpOld);
			DeleteDC(hdcMem);
		}
	}
}

LRESULT CALLBACK FlyoutWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_PAINT:
	{
		// paint a pretty picture
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);
		FlyoutPaint(hwnd, hdc);
		EndPaint(hwnd, &ps);
	}
	break;
	case WM_ACTIVATE:
		if (LOWORD(wParam) == WA_INACTIVE)
		{
			// when the flyout window loses focus, hide it.
			PostMessage(GetParent(hwnd), WMAPP_HIDEFLYOUT, 0, 0);
		}
		break;
	default:
		return DefWindowProc(hwnd, message, wParam, lParam);
	}
	return 0;
}

DWORD WINAPI UserspaceListenerThread(
	_In_ LPVOID lpParameter
)
{
	WCHAR pszMessage[MSG_BUFFER_SIZE];
	CONST LPCTSTR pszPipeName = (LPTSTR)TEXT("\\\\.\\pipe\\RDS_UI_pipe");

	while (true)
	{
		if (ERROR_FAILURE == ReceiveMessageFromPipe(pszPipeName, (PWCHAR)pszMessage))
		{
			//MessageBoxA(NULL, "UserspaceListenerThread didn't received any message", "Rootkit user UI detector", MB_OK);
		}
		else
		{
			//MessageBox(NULL, pszMessage, _T("Rootkit user UI detector"), MB_OK);
			ShowUsermodeDetectionBalloon();
		}
		Sleep(5000);
	}
}

DWORD WINAPI KernelpaceListenerThread(
	_In_ LPVOID lpParameter
)
{
	WCHAR pszMessage[MSG_BUFFER_SIZE];
	CONST LPCTSTR pszPipeName = (LPTSTR)TEXT("\\\\.\\pipe\\RDS_Kernel_UI_pipe");

	while (true)
	{
		if (ERROR_FAILURE == ReceiveMessageFromPipe(pszPipeName, (PWCHAR)pszMessage))
		{
			//MessageBoxA(NULL, "KernelpaceListenerThread didn't received any message", "Rootkit kernel UI detector", MB_OK);
		}
		else
		{
			//MessageBox(NULL, pszMessage, _T("Rootkit kernel UI detector"), MB_OK);
			ShowKernelmodeDetectionBalloon();
		}
		Sleep(5000);
	}
}