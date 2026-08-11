st = _NtCreateUserProcess(&hProcess, &hThread, ..., params, NULL, NULL); --> 
PS_CREATE_INFO createInfo = {0};
PS_ATTRIBUTE_LIST attrList = {0};
st = _NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
                           NULL, NULL, 0, 0, params, &createInfo, &attrList);

                           Kỹ thuật sử dụng trong Loader (C, x64)
1. Direct System Call (Syscall)

Tự động xây dựng stub syscall từ export của ntdll.dll (tìm syscall number và tạo code assembly mov eax, ssn; syscall; ret).

Gọi trực tiếp các hàm Native API như NtCreateUserProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtGetContextThread, NtSetContextThread, NtResumeThread.

Ưu điểm: Bypass hoàn toàn user‑mode hook của AV/EDR (không đi qua API wrapper bị hook).

2. Mã hóa payload bằng RC4

Dùng key 16 byte cố định (0x00..0x0F).

Cả builder (mã hóa payload.bin thành config.dat) và loader (giải mã khi chạy) đều sử dụng cùng một key.

Ưu điểm: RC4 mạnh hơn XOR, tránh signature dễ dàng.

3. Process Hollowing (Inject vào Notepad)

Tạo tiến trình notepad.exe ở trạng thái suspended.

Cấp phát bộ nhớ trong tiến trình đích (PAGE_READWRITE), ghi shellcode đã giải mã, sau đó đổi sang PAGE_EXECUTE_READ.

Chỉnh sửa RIP (context) để trỏ vào shellcode, sau đó resume thread.

Ưu điểm: Chạy dưới vỏ bọc tiến trình hợp pháp, không hiển thị cửa sổ (SW_HIDE).

4. Anti‑Sandbox / Anti‑VM

Kiểm tra RAM tổng (>= 2 GB), số CPU cores (>= 2), uptime hệ thống (>= 10 phút).

Dò tên máy tính chứa từ khóa (SANDBOX, VIRUS, MALWARE, SAMPLE, TEST).

Kiểm tra debugger (IsDebuggerPresent).

Nếu phát hiện môi trường phân tích, loader thoát ngay mà không thực thi payload.

5. Tối ưu bảo mật bộ nhớ

Không sử dụng PAGE_EXECUTE_READWRITE cho vùng chứa shellcode; chỉ dùng RW khi ghi, sau đó đổi sang RX khi chạy.

Giải phóng buffer chứa shellcode đã giải mã sau khi ghi vào tiến trình đích.

6. Không xuất ra bất kỳ dấu hiệu nào

Không comment, không printf, không MessageBox, không log.

Chỉ trả về mã thoát khi lỗi (không hiển thị). Giúp giảm khả năng bị phát hiện.

7. Builder tự động

Nhận đầu vào là payload.bin (raw shellcode), mã hóa RC4, xuất ra config.dat.

Đảm bảo tính nhất quán giữa builder và loader.

Ưu điểm tổng thể
Bypass AV/EDR user‑mode hiệu quả nhờ direct syscall và không sử dụng API dễ bị hook.

Che giấu hành vi qua process hollowing và ẩn cửa sổ.

Tránh phân tích tự động nhờ các biện pháp anti‑sandbox.

Tăng độ khó phân tích tĩnh nhờ mã hóa RC4 và không có output/debug.

Độ tin cậy cao trên Windows 10 x64 (kiểm thử trong môi trường được cấp phép)

Lưu ý: Loader yêu cầu quyền PROCESS_ALL_ACCESS (thường cần admin) để thực hiện inject.
