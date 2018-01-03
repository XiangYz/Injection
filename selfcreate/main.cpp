#include <iostream>
#include <Windows.h>
#include <tchar.h>

void ChildProcess(void)
{
	::MessageBox(NULL, _T("Child Process"), _T("selfcreate"), MB_OK);
	::ExitProcess(0);
}


int main(int argc, char* argv[])
{
	std::cout << "selfcreate: Parent Process" << std::endl;

	TCHAR szPath[MAX_PATH] = { 0 };
	::GetModuleFileName(NULL, szPath, sizeof(TCHAR) * MAX_PATH);

	STARTUPINFO stinfo = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	BOOL bRet = ::CreateProcess(szPath, NULL, NULL, NULL, FALSE,
					CREATE_SUSPENDED, NULL, NULL, &stinfo, &pi);
	if (!bRet)
	{
		std::cout << "CreateProcess failed!" << std::endl;
		exit(-1);
	}

	CONTEXT ctx;
	bRet = ::GetThreadContext(pi.hThread, &ctx);
	if (!bRet)
	{
		std::cout << "GetThreadContext failed!" << std::endl;
		exit(-1);
	}

	ctx.ContextFlags = CONTEXT_FULL;
	ctx.Eip = (DWORD)&ChildProcess;

	bRet = ::SetThreadContext(pi.hThread, &ctx);
	if (!bRet)
	{
		std::cout << "SetThreadContext failed!" << std::endl;
		exit(-1);
	}

	::ResumeThread(pi.hThread);

	::WaitForSingleObject(pi.hProcess, INFINITE);

	return 0;
}