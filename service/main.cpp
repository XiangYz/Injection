#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

#define SVCNAME _T("SvcTest")

void InstallService(LPCTSTR szSvcName, LPCTSTR szPath);
void UninstallService(LPCTSTR szSvcName);
void WINAPI SvcMain(DWORD argc, LPCTSTR* argv);
void WINAPI SvcCtrlHandler(DWORD dwCtrl);


SERVICE_STATUS_HANDLE g_hServiceStatusHandle = NULL;
SERVICE_STATUS g_ServiceStatus = { SERVICE_WIN32_OWN_PROCESS, 0, 0xFF, 0, 0, 0, 0 };


void _tmain(int argc, TCHAR* argv[])
{
	TCHAR szPath[MAX_PATH] = { 0 };
	SERVICE_TABLE_ENTRY DispatchTable[] = 
	{
		{SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain},
		{NULL, NULL}
	};

	if (argc == 1)
	{
		if (!StartServiceCtrlDispatcher(DispatchTable))
		{
			_tprintf(_T("StartServiceCtrlDispatcher() failed!!! [%d]\n"), GetLastError());
		}
	}
	else if (argc == 2)
	{
		if (!GetModuleFileName(NULL, szPath, MAX_PATH))
		{
			_tprintf(_T("GetModuleFileName() failed!!! [%d]\n"),
				GetLastError());
			return;
		}

		if (_tcsicmp(argv[1], _T("install")) == 0)
		{
			InstallService(SVCNAME, szPath);
		}
		else if (_tcsicmp(argv[1], _T("uninstall")) == 0)
		{
			UninstallService(SVCNAME);
			return;
		}
		else
		{
			_tprintf(_T("Illegal parameters!!!\n"));
		}
	}

	_tprintf(_T("\nUSAGE : %s <install | uninstall>\n"), argv[0]);
}


void InstallService(LPCTSTR szSvcName, LPCTSTR szPath)
{
	SC_HANDLE schSCManager = NULL;
	SC_HANDLE schService = NULL;
	DWORD dwError = 0;

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		_tprintf(_T("InstallService(): OpenSCManager() failed (%d)\n"), GetLastError());
		return;
	}

	schService = CreateService(
		schSCManager,
		szSvcName,
		szSvcName,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		szPath,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);
	if (NULL == schService)
	{
		dwError = GetLastError();
		_tprintf(_T("InstallService(): CreateService() failed (%d)\n"), dwError);
		if (ERROR_SERVICE_EXISTS == dwError)
			_tprintf(_T(" -> The specified service already exists.\n"));
		goto L_EXIT;
	}

	_tprintf(_T("InstallService(): Service installed successfully\n"));

L_EXIT:
	if (schService) CloseServiceHandle(schService);
	if (schSCManager) CloseServiceHandle(schSCManager);
}


void UninstallService(LPCTSTR szSvcName)
{
	SC_HANDLE schSCManager = NULL;
	SC_HANDLE schService = NULL;
	SERVICE_STATUS ss = { 0 };
	DWORD dwError = 0;

	schSCManager = OpenSCManager(
		NULL, NULL,
		SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		_tprintf(_T("UninstallService(): OpenSCManager() failed (%d)\n"), GetLastError());
		return;
	}

	schService = OpenService(
		schSCManager,
		szSvcName,
		SERVICE_INTERROGATE | DELETE);
	if (NULL == schService)
	{
		dwError = GetLastError();
		if (dwError != ERROR_SERVICE_DOES_NOT_EXIST)
			_tprintf(_T("UninstallService(): OpenSCManager() failed (%d)\n"), dwError);
		goto L_EXIT;
	}
	
	ControlService(schService, SERVICE_CONTROL_INTERROGATE, &ss);
	if (ss.dwCurrentState != SERVICE_STOPPED)
	{
		_tprintf(_T(" -> Service is running! Stop the service!\n"));
		goto L_EXIT;
	}

	if (!DeleteService(schService))
		_tprintf(_T("UninstallService(): DeleteService() failed (%d)\n"), GetLastError());
	else
		_tprintf(_T("Service uninstalled successfully\n"));

L_EXIT:
	if (schService) CloseServiceHandle(schService);
	if (schSCManager) CloseServiceHandle(schSCManager);

}

void WINAPI SvcMain(DWORD argc, LPCTSTR* argv)
{
	__asm
	{
		nop 
		nop
		nop
		nop
	}

	g_hServiceStatusHandle = RegisterServiceCtrlHandler(
		SVCNAME,
		SvcCtrlHandler);
	if (!g_hServiceStatusHandle)
	{
		OutputDebugString(_T("RegisterServiceCtrlHandler() failed!!!"));
		return;
	}

	g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(g_hServiceStatusHandle, &g_ServiceStatus);

	while (true)
	{
		OutputDebugString(_T("[SvcTest] service is running..."));
		Sleep(3 * 1000);
	}
}


void WINAPI SvcCtrlHandler(DWORD dwCtrl)
{
	switch (dwCtrl)
	{
	case SERVICE_CONTROL_STOP:
		g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(g_hServiceStatusHandle, &g_ServiceStatus);
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(g_hServiceStatusHandle, &g_ServiceStatus);

		OutputDebugString(_T("[SvcTest] service is stopped..."));
		break;
	default:
		break;
	}
}