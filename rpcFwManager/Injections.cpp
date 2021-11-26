#include "stdafx.h"

// 远程注入DLL到指定进程
void hookProcessLoadLibrary(DWORD processID, WCHAR* dllToInject) 
{
	WCHAR wszOutMsg[MAX_PATH] = { 0 };
 	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, processID);
	if (hProcess == NULL)
	{
		_tprintf(TEXT("OpenProcess failed for pid %u: [%d]\n"), processID,GetLastError());
		return;
	}

	
	std::wstring wstrTmp;
	wstrTmp = dllToInject;
	std::string strTmp(wstrTmp.begin(), wstrTmp.end());
	const char* szInjectionDLLName = strTmp.c_str();

	void* LLParam = (LPVOID)VirtualAllocEx(hProcess, NULL, MAX_PATH*2, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (LLParam == NULL)
	{
		_tprintf(TEXT("Error when calling WriteProcessMemory %d \n"), GetLastError());
		return;
	}

	if (WriteProcessMemory(hProcess, LLParam, szInjectionDLLName, strlen(szInjectionDLLName), 0) == 0)
	{
		_tprintf(TEXT("Error when calling WriteProcessMemory %d \n"), GetLastError());
		return;
	}
	
	FARPROC pLoadLib = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (pLoadLib == NULL)
	{
		_tprintf(TEXT("Error when calling GetProcAddress %d \n"), GetLastError());
		return;
	}
	
	// 由于会话空间的问题，在vista及win7以后的系统上可能会失败，错误码返回8
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, LLParam, 0, NULL);
	if (hRemoteThread == NULL)
	{
		_snwprintf_s(wszOutMsg, MAX_PATH, MAX_PATH-1, TEXT("to pid :%d, Error when calling CreateRemoteThread %d \n"), processID, GetLastError());
		OutputDebugStringW(wszOutMsg);
		_tprintf(TEXT("to pid :%d, Error when calling CreateRemoteThread %d \n"), processID, GetLastError());
		return;
	}

	CloseHandle(hRemoteThread);
}

// 确定进程中是否加载了RPC模块和是否加载了RPCFW模块
std::pair<BOOL,BOOL> containsRPCModules(DWORD dwPID)
{
	BOOL containsRpcRuntimeModule = FALSE;
	BOOL containsRpcFirewallModule = FALSE;

	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("Error when calling CreateToolhelp32Snapshot for pid %u: %d\n"), dwPID,GetLastError());
		return std::make_pair(containsRpcRuntimeModule, containsRpcFirewallModule);;
	}

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32))
	{
		_tprintf(TEXT("Error when calling Module32First: %d"),GetLastError()); 
		CloseHandle(hModuleSnap);     
		return std::make_pair(containsRpcRuntimeModule, containsRpcFirewallModule);;
	}

	while (Module32Next(hModuleSnap, &me32))
	{
		if (_tcsstr(me32.szModule, _T("rpcrt4.dll")) || _tcsstr(me32.szModule, _T("RPCRT4.dll")))
		{
			_tprintf(TEXT("Process %d contains RPC module!\n"), dwPID);
			containsRpcRuntimeModule = TRUE;
		}

		if (_tcsstr(me32.szModule, RPC_FW_DLL_NAME))
		{
			_tprintf(TEXT("Process %d contains RPCFW module!\n"), dwPID);
			containsRpcFirewallModule = TRUE;
		}
	};

	CloseHandle(hModuleSnap);
	return std::make_pair(containsRpcRuntimeModule, containsRpcFirewallModule);;
}

void classicHookRPCProcesses(DWORD processID, TCHAR* dllToInject)
{
	std::pair<BOOL,BOOL> containsModules = containsRPCModules(processID);
	BOOL containsRPC = containsModules.first;
	BOOL containsRPCFW = containsModules.second;

	if ( containsRPC && !containsRPCFW) 
	{
		hookProcessLoadLibrary(processID, dllToInject);
	}
}
