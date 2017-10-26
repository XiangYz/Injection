#include <iostream>
#include <Windows.h>

HINSTANCE g_hinstDLL;
HHOOK g_hHook;


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		g_hinstDLL = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}



__declspec(dllexport)
LRESULT __stdcall msg_proc(int code, WPARAM wParam, LPARAM lParam)
{

	if (code == HC_ACTION)
	{
		if (wParam == 0x41)
			return 1;
	}

	return CallNextHookEx(g_hHook, code, wParam, lParam);
}


__declspec(dllexport)
void HookStart()
{
	g_hHook = SetWindowsHookEx(WH_KEYBOARD, msg_proc, g_hinstDLL, 0);
}



__declspec(dllexport)
void HookStop()
{
	UnhookWindowsHookEx(g_hHook);
}