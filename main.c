#include <stdlib.h>

#include "aes.h"
#include "io.h"

int main(int argc, char **argv) {
    const unsigned Nk = 4;
    const char *key = "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f";
    const char *in =
        "00112233445566778899aabbccddeeff"
        "ffeeddccbbaa99887766554433221100";
    char *out = cipher_hex_multiblock(Nk, key, in);
    char *dec = inv_cipher_hex_multiblock(Nk, key, out);
    print_multiline(dec, '\n');
    free(dec);
    free(out);

    cipher_file(Nk, key, "main.c", "main-encrypted.aes");
    inv_cipher_file(Nk, key, "main-encrypted.aes", "main-decrypted.txt");
}
