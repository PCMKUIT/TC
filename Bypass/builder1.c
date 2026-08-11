#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE* fIn = fopen("payload.bin", "rb");
    if (!fIn) return 1;
    fseek(fIn, 0, SEEK_END);
    long size = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);
    unsigned char* buf = (unsigned char*)malloc(size);
    if (!buf) { fclose(fIn); return 2; }
    if (fread(buf, 1, size, fIn) != size) { free(buf); fclose(fIn); return 3; }
    fclose(fIn);
    unsigned char key[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    int keyLen = sizeof(key);
    for (long i = 0; i < size; i++) {
        buf[i] ^= key[i % keyLen];
    }
    FILE* fOut = fopen("config.dat", "wb");
    if (!fOut) { free(buf); return 4; }
    if (fwrite(buf, 1, size, fOut) != size) { free(buf); fclose(fOut); return 5; }
    fclose(fOut);
    free(buf);
    return 0;
}
