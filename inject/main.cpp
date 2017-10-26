#include <iostream>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>

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
	if (argc != 3) exit(-1);

	// 不需要SetPrivilege也可以成功
	/*
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
	{
		std::cout << "SetPrivilege failed!" << std::endl;
		exit(-1);
	}
	*/

	std::string process_name(argv[1]);
	std::wstring w_name = ANSIToUnicode(process_name);
	DWORD pid = GetProcessIDFromName(w_name.c_str());

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (NULL == hProcess)
	{
		std::cout << "OpenProcess failed!" << std::endl;
		exit(-1);
	}

	void* mem1 = VirtualAllocEx(hProcess, NULL, 256, MEM_COMMIT, PAGE_READWRITE);
	std::wstring w_dllpath = ANSIToUnicode(std::string(argv[2]));
	WriteProcessMemory(hProcess, mem1, w_dllpath.c_str(), w_dllpath.length() * 2 + 2, NULL);

	HMODULE hKernelMod = GetModuleHandleW(L"kernel32.dll");
	if (hKernelMod == NULL)
	{
		std::cout << "Get Kernel Module Handle error!" << std::endl;
		exit(-1);
	}
	// 此处使用LoadLibraryA就不行，不知道为什么
	FARPROC pfn_LoadLib = GetProcAddress(hKernelMod, "LoadLibraryW");
	if (pfn_LoadLib == NULL)
	{
		exit(-1);
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pfn_LoadLib, mem1, 0, 0);
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