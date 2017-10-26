#include <iostream>
#include <string>
#include <cmath>
#include <Windows.h>
#include <tlhelp32.h>

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		std::cout << "OpenProcessToken error: " << GetLastError() << std::endl;
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,
		lpszPrivilege, &luid))
	{
		std::cout << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;


	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		NULL, NULL))
	{
		std::cout << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		std::cout << "The token does not have the specified privilege." << std::endl;
		return FALSE;
	}

	return TRUE;
}


DWORD GetProcessIDFromName(LPCWSTR szName)
{
	DWORD id = 0;       // 进程ID
	PROCESSENTRY32 pe;  // 进程信息
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 获取系统进程列表
	if (Process32First(hSnapshot, &pe))      // 返回系统中第一个进程的信息
	{
		do
		{
			if (0 == _wcsicmp(pe.szExeFile, szName)) // 不区分大小写比较
			{
				id = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));      // 下一个进程
	}
	CloseHandle(hSnapshot);     // 删除快照
	return id;
}

std::wstring ANSIToUnicode(const std::string& str)
{
	int len = str.length();
	int unicode_len = ::MultiByteToWideChar(CP_ACP, 0, str.c_str()
		, -1, NULL, 0);
	wchar_t* pUnicode;
	pUnicode = new wchar_t[unicode_len + 1];
	memset(pUnicode, 0, (unicode_len + 1) * sizeof(wchar_t));
	::MultiByteToWideChar(CP_ACP, 0, str.c_str()
		, -1, (LPWSTR)pUnicode, unicode_len);
	std::wstring ret(pUnicode);

	delete[] pUnicode;

	return ret;
}

std::string UnicodeToANSI(const std::wstring& wstr)
{
	int len = ::WideCharToMultiByte(CP_ACP, 0, wstr.c_str()
		, -1, NULL, 0, NULL, NULL);
	char* pANSI = new char[len + 1];
	memset(pANSI, 0, sizeof(char) * (len + 1));
	::WideCharToMultiByte(CP_ACP, 0, wstr.c_str()
		, -1, pANSI, len, NULL, NULL);
	std::string str(pANSI);
	delete[] pANSI;

	return str;

}


HANDLE GetRemoteModuleHandle(LPCWSTR module_name, DWORD pid)
{
	BOOL bFound = FALSE;
	MODULEENTRY32 me = { sizeof(me) };
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	BOOL bMore = Module32First(hSnap, &me);
	for (; bMore; bMore = Module32Next(hSnap, &me))
	{
		if (!wcsicmp(me.szModule, module_name) ||
			!wcsicmp(me.szExePath, module_name))
		{
			bFound = TRUE;
			break;
		}
	}

	HANDLE ret = (HANDLE)me.modBaseAddr;

	CloseHandle(hSnap);

	if (!bFound)
	{
		return NULL;
	}

	return ret;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	DWORD dwCurProcessId = *((DWORD*)lParam);
	DWORD dwProcessId = 0;

	GetWindowThreadProcessId(hwnd, &dwProcessId);
	if (dwProcessId == dwCurProcessId && GetParent(hwnd) == NULL)
	{
		*((HWND *)lParam) = hwnd;
		return FALSE;
	}
	return TRUE;
}


HWND GetMainWindow()
{
	DWORD dwCurrentProcessId = GetCurrentProcessId();
	if (!EnumWindows(EnumWindowsProc, (LPARAM)&dwCurrentProcessId))
	{
		return (HWND)dwCurrentProcessId;
	}
	return NULL;
}

typedef HMODULE(WINAPI *PFN_LOADLIBRARYW)(LPCWSTR);
typedef FARPROC(WINAPI *PFN_GETPROCADDRESS)(HMODULE hModule,LPCSTR lpProcName);

typedef int (WINAPI *PFN_MESSAGEBOXW)
(HWND hWnd,LPCWSTR lpText,LPCWSTR lpCaption,UINT uType);

typedef struct stParam
{
	PFN_LOADLIBRARYW pfn_loadlibraryw;
	PFN_GETPROCADDRESS pfn_getproc;

	WCHAR szDllName[32];
	char szProcName[32];

	WCHAR szCaption[128];
	WCHAR szContent[128];

}THREAD_PARAM, *PTHREAD_PARAM;




DWORD WINAPI RemoteThreadProc(LPVOID pParam)
{
	THREAD_PARAM param = *(PTHREAD_PARAM)pParam;

	HMODULE hUser32 = param.pfn_loadlibraryw(param.szDllName);
	PFN_MESSAGEBOXW pfn_msgboxw = (PFN_MESSAGEBOXW)param.pfn_getproc(hUser32, param.szProcName);

	pfn_msgboxw(NULL, param.szCaption, param.szContent, MB_OK);

	
	
	return 1;
}


int main(int argc, char* argv[])
{
	if (argc != 2) exit(-1);

	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
	{
		std::cout << "SetPrivilege failed!" << std::endl;
		exit(-1);
	}

	std::wstring w_name = ANSIToUnicode(argv[1]);
	DWORD pid = GetProcessIDFromName(w_name.c_str());
	if (pid == 0)
	{
		std::cout << "No such process: " << argv[1] << std::endl;
		exit(-1);
	}

	// 打开远程进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		std::cout << "OpenProcess failed!" << std::endl;
		exit(-1);
	}

	// 分配参数内存空间
	PTHREAD_PARAM mem_param = (PTHREAD_PARAM)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_PARAM), MEM_COMMIT, PAGE_READWRITE);
	if (mem_param == NULL)
	{
		std::cout << "VirtualAllocEx mem_param failed!" << std::endl;
		exit(-1);
	}

	THREAD_PARAM param;

	// 
	HMODULE hKernelMod = GetModuleHandleW(L"Kernel32.dll");
	param.pfn_loadlibraryw = (PFN_LOADLIBRARYW)GetProcAddress(hKernelMod, "LoadLibraryW");
	param.pfn_getproc = (PFN_GETPROCADDRESS)GetProcAddress(hKernelMod, "GetProcAddress");

	wchar_t dllname[] = { L"User32.dll" };
	char procname[] = { "MessageBoxW" };
	wchar_t cap[] = { L"codeinject" };
	wchar_t con[] = { L"Hello" };

	wcscpy(param.szDllName, dllname);
	strcpy(param.szProcName, procname);
	wcscpy(param.szCaption, cap);
	wcscpy(param.szContent, con);

	WriteProcessMemory(hProcess, mem_param, &param, sizeof(param), NULL);


	// 分配代码空间
	ULONG main_addr = (ULONG)&main;
	ULONG thr_addr = (ULONG)&RemoteThreadProc;
	SIZE_T code_size = main_addr - thr_addr;
	void* code_mem = VirtualAllocEx(hProcess, NULL, code_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (code_mem == NULL)
	{
		std::cout << "VirtualAllocEx code_mem failed: " << GetLastError() << std::endl;
		exit(-1);
	}
	WriteProcessMemory(hProcess, code_mem, &RemoteThreadProc, code_size, NULL);


	// 创建远程线程
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)code_mem, mem_param, 0, 0);
	if (hRemoteThread == NULL)
	{
		std::cout << "CreateRemoteThread failed!" << std::endl;
		exit(-1);
	}

	WaitForSingleObject(hRemoteThread, INFINITE);



	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
	
	return 0;
}