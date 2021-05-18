#include <stdlib.h>

#include "aes.h"
#include "io.h"

int main(int argc, char **argv) {
    const unsigned Nk = 4, Nr = 10, Nb = 4;
    const char *key = "000102030405060708090a0b0c0d0e0f";
    const char *in = "00112233445566778899aabbccddeeff";
    char *out = cipher_hex(Nk, key, in);
    char *dec = inv_cipher_hex(Nk, key, out);
    print_multiline(dec, '\n');
    free(dec);
    free(out);
}
