#include <iostream>
#include <string>
#include <Windows.h>
#include <tchar.h>
#include <tlhelp32.h>

//#define NOTEPAD_WRITEFILE
#define CALC_SETWINDOWTEXT


DWORD GetProcessIDFromName(LPCTSTR szName)
{
	DWORD id = 0;       // 进程ID
	PROCESSENTRY32 pe;  // 进程信息
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 获取系统进程列表
	if (Process32First(hSnapshot, &pe))      // 返回系统中第一个进程的信息
	{
		do
		{
			if (0 == _tcsicmp(pe.szExeFile, szName)) // 不区分大小写比较
			{
				id = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));      // 下一个进程
	}
	CloseHandle(hSnapshot);     // 删除快照
	return id;
}


HMODULE GetRemoteModuleHandle(LPCTSTR module_name, DWORD pid)
{
	BOOL bFound = FALSE;
	MODULEENTRY32 me = { sizeof(me) };
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	BOOL bMore = Module32First(hSnap, &me);
	for (; bMore; bMore = Module32Next(hSnap, &me))
	{
		if (!_tcsicmp(me.szModule, module_name) ||
			!_tcsicmp(me.szExePath, module_name))
		{
			bFound = TRUE;
			break;
		}
	}

	HMODULE ret = (HMODULE)me.modBaseAddr;

	CloseHandle(hSnap);

	if (!bFound)
	{
		return NULL;
	}

	return ret;
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


void* g_pf_target = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
#ifdef NOTEPAD_WRITEFILE
	HMODULE hKernel32 = LoadLibrary(_T("Kernel32.dll"));
	g_pf_target = GetProcAddress(hKernel32, "WriteFile");
#endif

#ifdef CALC_SETWINDOWTEXT
	HMODULE hKernel32 = LoadLibrary(_T("User32.dll"));
	g_pf_target = GetProcAddress(hKernel32, "SetWindowTextW");
#endif

	if (NULL == g_pf_target) return FALSE;

	ReadProcessMemory(g_cpdi.hProcess, g_pf_target, &g_chOrgByte, sizeof(BYTE), NULL);
	WriteProcessMemory(g_cpdi.hProcess, g_pf_target, &g_chINT3, sizeof(BYTE), NULL);

	return TRUE;
}


BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{

	CONTEXT ctx;
	PBYTE lpBuffer = NULL;
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;

	if (EXCEPTION_BREAKPOINT == per->ExceptionCode)
	{
		if (g_pf_target == per->ExceptionAddress)
		{
			// 恢复代码
			WriteProcessMemory(g_cpdi.hProcess, g_pf_target,
				&g_chOrgByte, sizeof(BYTE), NULL);

			ctx.ContextFlags = CONTEXT_CONTROL;
			GetThreadContext(g_cpdi.hThread, &ctx);

#ifdef NOTEPAD_WRITEFILE
			DWORD arg3_buf, arg2_buf;
			DWORD* arg3 = (DWORD*)(ctx.Esp + 0x0C);
			DWORD* arg2 = (DWORD*)(ctx.Esp + 0x08);
			ReadProcessMemory(g_cpdi.hProcess, arg3, &arg3_buf, sizeof(DWORD), NULL);
			ReadProcessMemory(g_cpdi.hProcess, arg2, &arg2_buf, sizeof(DWORD), NULL);
			DWORD new_len = arg3_buf + 28;
			BYTE* arg2_new = new BYTE[new_len]{ 
				0xe5, 0xa4, 0xa9, 0xe7, 0xa5, 0x9e, 0xe7, 0x9a
				, 0x84, 0xe6, 0x8c, 0x87, 0xe7, 0xa4, 0xba, 0xe9
				, 0x99, 0x8d, 0xe4, 0xb8, 0xb4, 0xe4, 0xba, 0x86
				, 0x0d, 0x0a, 0x0d, 0x0a };
			ReadProcessMemory(g_cpdi.hProcess, (void*)arg2_buf, arg2_new + new_len - arg3_buf, arg3_buf, NULL);

			void* remote_buf = VirtualAllocEx(g_cpdi.hProcess, NULL, new_len, MEM_COMMIT, PAGE_READWRITE);
			WriteProcessMemory(g_cpdi.hProcess, remote_buf, arg2_new, new_len, NULL);

			WriteProcessMemory(g_cpdi.hProcess, arg2, &remote_buf, sizeof(void*), NULL);
			WriteProcessMemory(g_cpdi.hProcess, arg3, &new_len, sizeof(DWORD), NULL);
#endif

#ifdef CALC_SETWINDOWTEXT

			wchar_t han_num[] = {L"零一二三四五六七八九"};

			DWORD arg2_local;
			DWORD* arg2 = (DWORD*)(ctx.Esp + 0x08);
			ReadProcessMemory(g_cpdi.hProcess, arg2, &arg2_local, sizeof(DWORD), NULL);
			wchar_t arg2_buf[256] = { 0 };
			ReadProcessMemory(g_cpdi.hProcess, (void*)arg2_local, arg2_buf, 512, NULL);
			DWORD text_len = 0;
			for (int i = 0; TRUE; ++i)
			{
				wchar_t wch = arg2_buf[i];
				if (wch == 0x0000)
				{
					text_len = i;
					break;
				}
				else if (arg2_buf[i] <= L'9' && arg2_buf[i] >= L'0')
				{
					arg2_buf[i] = han_num[arg2_buf[i] - L'0'];
				}
			} // for
			WriteProcessMemory(g_cpdi.hProcess, (void*)arg2_local, arg2_buf, text_len * 2 + 2, NULL);

#endif
			ctx.Eip = (DWORD)g_pf_target;
			SetThreadContext(g_cpdi.hThread, &ctx);

			ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
			Sleep(0);

			// 恢复断点
			WriteProcessMemory(g_cpdi.hProcess, g_pf_target, &g_chINT3, sizeof(BYTE), NULL);


			return TRUE;
		}
	}

	return FALSE;
}



void DebugLoop()
{
	DEBUG_EVENT de;
	DWORD dwContinueStatus;

	while (WaitForDebugEvent(&de, INFINITE))
	{
		dwContinueStatus = DBG_CONTINUE;

		if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			if (!OnCreateProcessDebugEvent(&de))
				break;
		}
		else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)
		{
			if (OnExceptionDebugEvent(&de))
				continue;
		}
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			break;
		}

		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}



int main(int argc, char* argv[])
{

	// attach到目标进程
#ifdef NOTEPAD_WRITEFILE
	TCHAR target_proc[] = _T("notepad.exe");
#endif

#ifdef CALC_SETWINDOWTEXT
	TCHAR target_proc[] = _T("calc.exe");
#endif

	DWORD dwPID = GetProcessIDFromName(target_proc);
	if (dwPID == 0)
	{
		std::cout << "No such process: " << target_proc << std::endl;
		exit(-1);
	}
	if (!DebugActiveProcess(dwPID))
	{
		std::cout << "DebugActiveProcess failed: " << GetLastError() << std::endl;
		exit(-1);
	}

	DebugLoop();

	return 0;
}