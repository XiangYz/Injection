/*
����������unicode������ע�뽫����Ŀ����̱�������֪��Ϊʲô
����mbcs֮�󣬾ͺ���
*/


#include <iostream>
#include <string>
#include <cmath>
#include <Windows.h>
#include <tlhelp32.h>


DWORD GetProcessIDFromName(LPCTSTR szName)
{
	DWORD id = 0;       // ����ID
	PROCESSENTRY32 pe;  // ������Ϣ
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // ��ȡϵͳ�����б�
	if (Process32First(hSnapshot, &pe))      // ����ϵͳ�е�һ�����̵���Ϣ
	{
		do
		{
			if (0 == stricmp(pe.szExeFile, szName)) // �����ִ�Сд�Ƚ�
			{
				id = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));      // ��һ������
	}
	CloseHandle(hSnapshot);     // ɾ������
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


HANDLE GetRemoteModuleHandle(LPCTSTR module_name, DWORD pid)
{
	BOOL bFound = FALSE;
	MODULEENTRY32 me = { sizeof(me) };
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	BOOL bMore = Module32First(hSnap, &me);
	for (; bMore; bMore = Module32Next(hSnap, &me))
	{
		if (!stricmp(me.szModule, module_name) ||
			!stricmp(me.szExePath, module_name))
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

typedef HMODULE(WINAPI *PFN_LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI *PFN_GETPROCADDRESS)(HMODULE hModule,LPCSTR lpProcName);

typedef int (WINAPI *PFN_MESSAGEBOXA)
(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);

typedef struct stParam
{
	PFN_LOADLIBRARYA pfn_loadlibrarya;
	PFN_GETPROCADDRESS pfn_getproc;

	char szDllName[128];
	char szProcName[128];

	char szCaption[128];
	char szContent[128];

}THREAD_PARAM, *PTHREAD_PARAM;




DWORD WINAPI RemoteThreadProc(LPVOID pParam)
{
	PTHREAD_PARAM param = (PTHREAD_PARAM)pParam;

	HMODULE hUser32 = param->pfn_loadlibrarya(param->szDllName);
	if (!hUser32) return 1;
	PFN_MESSAGEBOXA pfn_msgboxa = (PFN_MESSAGEBOXA)param->pfn_getproc(hUser32, param->szProcName);
	if (!pfn_msgboxa) return 1;

	pfn_msgboxa(NULL, param->szCaption, param->szContent, MB_OK);
	
	return 0;
}


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


int main(int argc, char* argv[])
{
	if (argc != 2) exit(-1);

	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
	{
		std::cout << "SetPrivilege failed!" << std::endl;
		exit(-1);
	}

	
	DWORD pid = GetProcessIDFromName(argv[1]);
	if (pid == 0)
	{
		std::cout << "No such process: " << argv[1] << std::endl;
		exit(-1);
	}

	// ��Զ�̽���
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		std::cout << "OpenProcess failed!" << std::endl;
		exit(-1);
	}

	// ��������ڴ�ռ�
	PTHREAD_PARAM mem_param = (PTHREAD_PARAM)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_PARAM), MEM_COMMIT, PAGE_READWRITE);
	if (mem_param == NULL)
	{
		std::cout << "VirtualAllocEx mem_param failed!" << std::endl;
		exit(-1);
	}

	THREAD_PARAM param;

	// 
	HMODULE hKernelMod = GetModuleHandleA("Kernel32.dll");
	param.pfn_loadlibrarya = (PFN_LOADLIBRARYA)GetProcAddress(hKernelMod, "LoadLibraryA");
	param.pfn_getproc = (PFN_GETPROCADDRESS)GetProcAddress(hKernelMod, "GetProcAddress");

	char dllname[] = { "User32.dll" };
	char procname[] = { "MessageBoxA" };
	char cap[] = { "codeinject" };
	char con[] = { "Hello" };

	strcpy(param.szDllName, dllname);
	strcpy(param.szProcName, procname);
	strcpy(param.szCaption, cap);
	strcpy(param.szContent, con);

	WriteProcessMemory(hProcess, mem_param, &param, sizeof(param), NULL);


	// �������ռ�

	SIZE_T code_size = (ULONG)&SetPrivilege - (ULONG)&RemoteThreadProc;
	void* code_mem = VirtualAllocEx(hProcess, NULL, code_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (code_mem == NULL)
	{
		std::cout << "VirtualAllocEx code_mem failed: " << GetLastError() << std::endl;
		exit(-1);
	}
	WriteProcessMemory(hProcess, code_mem, &RemoteThreadProc, code_size, NULL);


	// ����Զ���߳�
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