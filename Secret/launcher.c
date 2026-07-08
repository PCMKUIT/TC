#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main() {
    const char *filename = "sushi.exe.bin";
    FILE *file = fopen(filename, "rb"); 
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char *buffer = (unsigned char *)VirtualAlloc(NULL, filesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    if (buffer == NULL) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return 1;
    }
    fread(buffer, 1, filesize, file);
    fclose(file);
    printf("Executing shellcode from %s...\n", filename);
    int (*func)() = (int (*)())buffer;
    func();
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}
