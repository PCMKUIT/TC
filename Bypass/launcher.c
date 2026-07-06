#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main() {
    const char *filename = "443.exe.bin";
    FILE *file = fopen(filename, "rb");
    
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    // Determine file size
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory with Read, Write, and Execute permissions
    // VirtualAlloc is necessary because modern OS memory pages are non-executable by default
    unsigned char *buffer = (unsigned char *)VirtualAlloc(NULL, filesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (buffer == NULL) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return 1;
    }

    // Read the shellcode into the allocated buffer
    fread(buffer, 1, filesize, file);
    fclose(file);

    // Execute the shellcode
    printf("Executing shellcode from %s...\n", filename);
    
    // Cast the buffer to a function pointer and call it
    int (*func)() = (int (*)())buffer;
    func();

    // Cleanup
    VirtualFree(buffer, 0, MEM_RELEASE);

    return 0;
}