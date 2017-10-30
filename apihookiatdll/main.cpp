#include <iostream>
#include <Windows.h>

HINSTANCE g_hinstDLL = NULL;

typedef BOOL(WINAPI *PF_SETWINDOWTEXTW)(HWND hWnd, LPWSTR lpString);

FARPROC g_pfOrgFunc = NULL;

BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString)
{
	wchar_t* pNum = L"零一二三四五六七八九";
	wchar_t temp[2] = { 0, };
	int i = 0, nLen = 0, nIndex = 0;

	nLen = wcslen(lpString);
	for (i = 0; i < nLen; ++i)
	{
		if (L'0' <= lpString[i] && lpString[i] <= L'9')
		{
			temp[0] = lpString[i];
			nIndex = _wtoi(temp);
			lpString[i] = pNum[nIndex];
		}
	}

	// 参数修改后要调用原来的函数处理
	return ((PF_SETWINDOWTEXTW)g_pfOrgFunc)(hWnd, lpString);
}


BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
	HMODULE hMod = GetModuleHandle(NULL);
	PBYTE pAddr = (PBYTE)hMod;

	pAddr += *((DWORD*)&pAddr[0x3C]); // 执行后pAddr是IMAGE_FILE_HEADER的地址
	DWORD dwRVA = *((DWORD*)&pAddr[0x80]); // 是导入表的RVA

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);

	for (; pImportDesc->Name; pImportDesc++)
	{
		LPCSTR szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
		if (0 == stricmp(szLibName, szDllName))
		{
			PIMAGE_THUNK_DATA pThunk =
				(PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);
			for (; pThunk->u1.Function; pThunk++)
			{
				if (pThunk->u1.Function == (DWORD)pfnOrg)
				{
					DWORD dwOldProtect;
					VirtualProtect((LPVOID)&pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
					pThunk->u1.Function = (DWORD)pfnNew;
					VirtualProtect((LPVOID)&pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);

					return TRUE;
				}
			}
		}
	}

	return FALSE;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		g_hinstDLL = hinstDLL;
		g_pfOrgFunc = GetProcAddress(GetModuleHandle(L"User32.dll"), "SetWindowTextW");
		hook_iat("User32.dll", g_pfOrgFunc, (PROC)MySetWindowTextW);
		break;
	case DLL_PROCESS_DETACH:
		hook_iat("User32.dll", (PROC)MySetWindowTextW, g_pfOrgFunc);
		break;
	}


	return TRUE;
}