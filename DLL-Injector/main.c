/*
############# [DLL-Injector] #############
	Created By: Raz Kissos (@covertivy)
*/

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

void printLastError();
int parseArguments(int argc, char** argv, char** dllPath, int* processId, int* dllPathLen);

int main(int argc, char** argv) {
	char* dllPath = NULL;
	int processId = 0;
	int dllPathLen = 0;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	HMODULE hK32 = NULL;
	LPVOID loadLibraryAAddr = NULL;
	LPVOID memAddr = NULL;
	SIZE_T written = 0;

	// Print banner ;)
	printf("\n############# [DLL-Injector] #############\n   Created By: Raz Kissos (@covertivy)\n\n");

	// Parse arguments.
	if (!parseArguments(argc, argv, &dllPath, &processId, &dllPathLen)) { return 1; }
	printf("Injecting DLL: \"%s\"\nTo Process (PID): %d\n\n", dllPath, processId);

	printf("[?] Creating handle to process (PID): %d\n", processId);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!hProcess) {
		printf("[-] Couldn't open process for injection!\n\tGot Handle: %p\n", hProcess);
		printLastError();
		return 1;
	}
	printf("[+] Got process handle: %p\n\n", hProcess);
	
	printf("[?] Finding address of 'LoadLibraryA'...\n");
	printf("\tCreating handle to 'kernel32.dl' module...\n");
	hK32 = GetModuleHandle(L"kernel32.dll");
	if (NULL == hK32) {
		printf("[-] Couldn't get handle to \'kernel32.dll\'!\n\tGot Handle: %p\n", hK32);
		printLastError();
		CloseHandle(hProcess);
		return 1;
	}

	printf("\tGetting address of 'LoadLibraryA' from 'kernel32.dl' module...\n");
	loadLibraryAAddr = (LPVOID)GetProcAddress(hK32, "LoadLibraryA");
	if (NULL == loadLibraryAAddr) {
		printf("[-] Couldn't get address of \'LoadLibraryA\'!\n\tGot Address: %p\n", loadLibraryAAddr);
		printLastError();
		CloseHandle(hProcess);
		return 1;
	}
	printf("[+] Got address of 'LoadLibraryA': %p\n\n", loadLibraryAAddr);

	printf("[?] Allocating memory for DLL Path on remote process...\n");
	memAddr = VirtualAllocEx(
		hProcess, 
		NULL, 
		dllPathLen, 
		MEM_COMMIT, 
		PAGE_READWRITE
	);

	if (NULL == memAddr) {
		printf("[-] Couldn't allocate remote process memory!\n\tGot Address: %p\n", memAddr);
		printLastError();
		CloseHandle(hProcess);
		return 1;
	}
	printf("[+] Memory was allocated on address: %p\n\n", memAddr);

	printf("[?] Writing DLL Path to newly allocated memory on remote process...\n");
	if (!WriteProcessMemory(hProcess, memAddr, dllPath, dllPathLen, &written)) {
		printf("[-] Couldn't write to remote process memory!\n\tGot Address: %p\n", memAddr);
		printLastError();
		CloseHandle(hProcess);
		return 1;
	}
	printf("[+] Successfully written DLL Path to remote process memory!\n\n");

	printf("[?] Creating remote thread with start address of 'LoadLibraryA' and Injected DLL Path as the argument...\n");
	hThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		loadLibraryAAddr,
		memAddr,
		NULL,
		NULL
	);

	if (NULL == hThread) {
		printf("[-] Couldn't create remote process thread!\n\tGot Handle: %p\n", hThread);
		printLastError();
		CloseHandle(hProcess);
		return 1;
	}
	printf("[+] Successfully created remote thread!\n\n");
	printf("[!] Successfully injected process with dll!\n[?] Cleaning up...\n");

	CloseHandle(hThread);
	CloseHandle(hProcess);

	printf("[*] See ya later ;)\n");

	return 0;
}

void printLastError()
{
	LPSTR messageBuffer = NULL;
	DWORD errCode = GetLastError();
	size_t size = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, 
		errCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
		(LPSTR)&messageBuffer, 
		0, 
		NULL
	);
	printf("[Error (%d)] %s\n", errCode, messageBuffer);
}

int parseArguments(int argc, char** argv, char** dllPath, int* processId, int* dllPathLen)
{
	if (3 != argc) {
		printf("Usage:\n\t%s <FullDLLPath> <ProcessID>\n", argv[0]);
		if (1 == argc) { // No arguments given.
			printf("Please enter a full-path to a DLL file to inject!\n");
			return FALSE;
		}
		else { // Only 1 argument given.
			printf("Please enter the Process ID of the process to inject!\n");
			return FALSE;
		}
	}

	*dllPath = argv[1];
	*dllPathLen = strlen(*dllPath) + 1; // Append nullbyte.
	*processId = atoi(argv[2]);
	return TRUE;
}
