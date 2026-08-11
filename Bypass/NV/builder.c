// builder.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void RC4(unsigned char *data, long len, unsigned char *key, long keylen) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) % 256;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int i = 0; j = 0;
    for (long n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
        data[n] ^= S[(S[i] + S[j]) % 256];
    }
}

int main(void) {
    unsigned char key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    FILE *fIn = fopen("payload.bin", "rb");
    if (!fIn) return 1;
    fseek(fIn, 0, SEEK_END);
    long size = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);
    unsigned char *buf = (unsigned char*)malloc(size);
    if (!buf) { fclose(fIn); return 2; }
    if (fread(buf, 1, size, fIn) != size) { free(buf); fclose(fIn); return 3; }
    fclose(fIn);
    RC4(buf, size, key, 16);
    FILE *fOut = fopen("config.dat", "wb");
    if (!fOut) { free(buf); return 4; }
    if (fwrite(buf, 1, size, fOut) != size) { free(buf); fclose(fOut); return 5; }
    fclose(fOut);
    free(buf);
    return 0;
}
