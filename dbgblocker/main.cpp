#include <Windows.h>
#include <tchar.h>
#include <iostream>

#define DEF_MUTEX_NAME _T("ReverseCore:DebugMe4")

void DoParentProcess();
void DoChildProcess();

int _tmain(int argc, TCHAR* argv[])
{
	HANDLE hMutex = NULL;

	if (!(hMutex = CreateMutex(NULL, FALSE, DEF_MUTEX_NAME)))
	{
		std::cout << "CreateMutex failed: " << GetLastError() << std::endl;
		exit(-1);
	}

	if (ERROR_ALREADY_EXISTS != GetLastError())
		DoParentProcess();
	else
		DoChildProcess();

	return 0;
}

void DoChildProcess()
{
	__asm nop
	__asm nop

	::MessageBox(NULL, _T("ChildProcess"), _T("dbgblocker"), MB_OK);
}

void DoParentProcess()
{
	TCHAR szPath[MAX_PATH];
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	::GetModuleFileName(GetModuleHandle(NULL), szPath, MAX_PATH);
	if (!::CreateProcess(
		NULL, szPath, NULL, NULL, FALSE,
		DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
		NULL, NULL,
		&si, &pi))
	{
		std::cout << "CreateProcess failed: " << GetLastError() << std::endl;
		exit(-1);
	}

	std::cout << "Parent Process" << std::endl;

	DEBUG_EVENT de = { 0, };
	DWORD dwExcpAddr = 0, dwExcpCode = 0;
	while(TRUE)
	{
		::ZeroMemory(&de, sizeof(DEBUG_EVENT));

		if (!WaitForDebugEvent(&de, INFINITE))
		{
			std::cout << "WaitForDebugEvent failed: " << GetLastError() << std::endl;
			break;
		}

		if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			dwExcpAddr = (DWORD)de.u.Exception.ExceptionRecord.ExceptionAddress;
			dwExcpCode = de.u.Exception.ExceptionRecord.ExceptionCode;

			unsigned char pBuf[2] = { 0 };
			if (dwExcpCode == EXCEPTION_ILLEGAL_INSTRUCTION)
			{
				ReadProcessMemory(pi.hProcess, LPCVOID(dwExcpAddr),
					pBuf, 2, NULL);
				std::cout << std::hex << (int)pBuf[0] << ' ' << std::hex << (int)pBuf[1]
					<< std::endl;
				pBuf[0] = 0x90;
				pBuf[1] = 0x90;
				WriteProcessMemory(pi.hProcess, (LPVOID)dwExcpAddr, pBuf, 2, NULL);


			}
		}
		else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
			break;

		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
	}

}