#include "stdafx.h"
#include "elevation.h"

// 获取指定进程ID的访问令牌
HANDLE getAccessToken(DWORD pid, DWORD desiredAccess)
{
	/* Retrieves an access token for a process */
	HANDLE currentProcess = {};
	HANDLE AccessToken = {};
	DWORD LastError;
	try {
		if (pid == 0)
		{
			currentProcess = GetCurrentProcess();
		}
		else
		{
			currentProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
			if (!currentProcess)
			{
				LastError = GetLastError();
				_tprintf(TEXT("ERROR: OpenProcess %d(): %d\n"), pid,LastError);
				return (HANDLE)NULL;
			}
		}
		if (!OpenProcessToken(currentProcess, desiredAccess, &AccessToken))
		{
			LastError = GetLastError();
			_tprintf(TEXT("ERROR: OpenProcessToken %d: %d\n"), pid ,LastError);
			return (HANDLE)NULL;
		}
		return AccessToken;
	}
	catch (...) 
	{
		LastError = GetLastError();
		_tprintf(TEXT("Exception during GetAccessToken(): %d\n"), GetLastError());
	}
	return (HANDLE)NULL;
}

DWORD getProcessIDFromName(wchar_t* procName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	DWORD pid = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, procName) == 0)
			{
				pid = entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return pid;

}

// 当前进程是否拥有SYSTEM权限
BOOL amISYSTEM()
{
	BOOL amisystem = FALSE;

	HANDLE hToken;
	HANDLE hProcess;

	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel;

	hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken))
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,dwLengthNeeded);
				if (pTIL != NULL)
				{
					if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

						if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
						{
							// High Integrity
							amisystem = TRUE;
						}
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);
	}
	return amisystem;
}

BOOL setPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		_tprintf(TEXT("LookupPrivilegeValue error: %u\n"), GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		_tprintf(TEXT("AdjustTokenPrivileges error: %u\n"), GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		_tprintf(TEXT("The token does not have the specified privilege. \n"));
		return FALSE;
	}

	return TRUE;
}

// pid -- 运行于SYSTEM帐户的进程的ID
void tryAndRunElevated(DWORD pid)
{
	// Enable core privileges  当前进程增加SeDebugPrivilege权限
	if (!setPrivilege(getAccessToken(0, TOKEN_ADJUST_PRIVILEGES), TEXT("SeDebugPrivilege"), TRUE))
	{
		return;
	}
	
	if (!amISYSTEM())
	{
		// Retrieves the remote process token.
		HANDLE pToken = getAccessToken(pid, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);
		if (pToken)
		{
			//These are required to call DuplicateTokenEx.
			SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;

			if (!ImpersonateLoggedOnUser(pToken))
			{
				_tprintf(TEXT("ERROR: Could not impersonate SYSTEM [%d]\n"), GetLastError());
				return;
			}

			TCHAR Imp_usrename[200];
			DWORD name_len = 200;
			GetUserName(Imp_usrename, &name_len);
			_tprintf(TEXT("Running as: %s\n"), Imp_usrename);
		}
	}	
}

// 把当前进程提权为SYSTEM权限
void elevateCurrentProcessToSystem()
{
	TCHAR sysProcessName[] = TEXT("winlogon.exe");
	tryAndRunElevated(getProcessIDFromName(sysProcessName));
}
