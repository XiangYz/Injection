#include <iostream>
#include <Windows.h>
#include <tchar.h>

void ChildProcess(void)
{
	::MessageBox(NULL, _T("Child Process"), _T("selfcreate2"), MB_OK);
	::ExitProcess(0);
}


int main(int argc, char* argv[])
{
	HANDLE hMtx = ::CreateMutex(NULL, FALSE, _T("selfcreate2_mtx"));
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		ChildProcess();

	std::cout << "selfcreate2: Parent Process" << std::endl;

	TCHAR szPath[MAX_PATH] = { 0 };
	::GetModuleFileName(NULL, szPath, sizeof(TCHAR) * MAX_PATH);

	STARTUPINFO stinfo = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	BOOL bRet = ::CreateProcess(szPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &stinfo, &pi);
	if (!bRet)
	{
		std::cout << "CreateProcess failed!" << std::endl;
		exit(-1);
	}

	::WaitForSingleObject(pi.hProcess, INFINITE);

	return 0;
}