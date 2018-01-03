#include <iostream>
#include <fstream>
#include <Windows.h>
#include <tchar.h>

char* ReadRealFile(LPCTSTR path)
{
	HANDLE hFile = ::CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (!hFile) return NULL;

	DWORD dwFileSize = ::GetFileSize(hFile, 0);

	char* file_buf = new char[dwFileSize];
	DWORD dwRead;
	::ReadFile(hFile, file_buf, dwFileSize, &dwRead, NULL);
	CloseHandle(hFile);

	return file_buf;

}

int _tmain(int argc, TCHAR* argv[])
{
 	if (argc != 3)
	{
		std::cout << "USAGE: peswitch fake real" << std::endl;
		exit(-1);
	}

	// 读实际要运行的文件
	char* real = ReadRealFile(argv[2]);
	if (!real)
	{
		std::cout << "read real file failed!" << std::endl;
		exit(-1);
	}

	// 挂起模式创建假进程
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	BOOL bRet = ::CreateProcess(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, 
					NULL, NULL,
					&si, &pi);
	if (!bRet)
	{
		std::cout << "CreateProcess failed!" << std::endl;
		exit(-1);
	}

	// Unmap假进程
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &ctx))
	{
		std::cout << "GetThreadContext failed!" << std::endl;
		exit(-1);
	}

	DWORD fake_imgbase;
	if (!ReadProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + 8), &fake_imgbase, sizeof(DWORD), NULL))
	{
		std::cout << "ReadProcessMemory failed!" << std::endl;
		exit(-1);
	}

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)real;
	PIMAGE_OPTIONAL_HEADER pioh = (PIMAGE_OPTIONAL_HEADER)(real + pidh->e_lfanew + 0x18);

	//if (pioh->ImageBase == fake_imgbase)
	{
		FARPROC pfunc =
			GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "ZwUnmapViewOfSection");
		typedef NTSTATUS(WINAPI *PFZWUNMAPVIEWOFSECTION)(
			HANDLE      ProcessHandle,
			PVOID       BaseAddress);
		if (0 != ((PFZWUNMAPVIEWOFSECTION)pfunc)(pi.hProcess, (LPVOID)fake_imgbase))
		{
			std::cout << "ZwUnmapViewOfSection() failed" << std::endl;
			exit(-1);
		}
	}
	//else
	{
		// 修改ImageBase的值
		WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + 8), &pioh->ImageBase, sizeof(DWORD), NULL);
	}

	// map真进程

	PIMAGE_FILE_HEADER pifh = (PIMAGE_FILE_HEADER)(real + pidh->e_lfanew + 4);
	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)(real + pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	unsigned char* pRealImage =
		(unsigned char*)
		VirtualAllocEx(pi.hProcess
			, (LPVOID)pioh->ImageBase, pioh->SizeOfImage
			, MEM_RESERVE | MEM_COMMIT
			, PAGE_EXECUTE_READWRITE);
	if (!pRealImage)
	{
		std::cout << "VirtualAllocEx failed!" << std::endl;
		exit(-1);
	}

	WriteProcessMemory(pi.hProcess, pRealImage, real, pioh->SizeOfHeaders, NULL);

	for (int i = 0; i < pifh->NumberOfSections; ++i, pish++)
	{
		if (pish->SizeOfRawData != 0)
		{
			if (!WriteProcessMemory(
				pi.hProcess,
				pRealImage + pish->VirtualAddress,
				real + pish->PointerToRawData,
				pish->SizeOfRawData,
				NULL
			))
			{
				std::cout << "WriteProcessMemory failed: "
					<< pRealImage + pish->VirtualAddress << std::endl;
				exit(-1);
			}
		}
	} // for

	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &ctx))
	{
		std::cout << "GetThreadContext() failed!" << std::endl;
		exit(-1);
	}

	ctx.Eax = pioh->AddressOfEntryPoint + pioh->ImageBase;

	if (!SetThreadContext(pi.hThread, &ctx))
	{
		std::cout << "SetThreadContext() failed!" << std::endl;
		exit(-1);
	}

	::ResumeThread(pi.hThread);

	::WaitForSingleObject(pi.hProcess, INFINITE);

	delete[] real;
	return 0;
}