#include <iostream>
#include <Windows.h>


int main(int argc, char* argv[])
{
	HMODULE hMod = LoadLibraryW(L"D:\\xiang\\prj\\vs_prj\\Injection\\Debug\\hookmsgdll.dll");
	if (hMod == NULL)
	{
		std::cout << "LoadLibraryW error: " << GetLastError() << std::endl;
		exit(-1);
	}
	
	void(*pfn_HookStart)() = (void(*)())GetProcAddress(hMod, "HookStart");
	void(*pfn_HookStop)() = (void(*)())GetProcAddress(hMod, "HookStop");
	
	pfn_HookStart();

	while (char ch = getchar())
	{
		if (ch == 'q')
			break;
	}

	pfn_HookStop();

	FreeLibrary(hMod);

	return 0;
}