#include <stdio.h>   // for printf
#include <stdlib.h>  // for free

#include "aes.h"
#include "debug.h"

int main(int argc, char **argv) {
    const unsigned Nk = 4, Nr = 10, Nb = 4;
    word key_orig[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};

    word *w = KeyExpansion(Nb, Nr, key_orig, Nk);
    word **key = wrap_key(Nb, Nr, w, Nk);
    free(w);

    byte in[] = {0x32, 0x88, 0x31, 0xe0,
                 0x43, 0x5a, 0x31, 0x37,
                 0xf6, 0x30, 0x98, 0x07,
                 0xa8, 0x8d, 0xa2, 0x34};
    printf("Input:\n");
    print_state(in);

    byte *enc = Cipher(4, Nr, in, key);
    printf("Encrypted:\n");
    print_state(enc);

    byte *dec = InvCipher(4, Nr, enc, key);
    printf("Decrypted:\n");
    print_state(dec);

    free(key);
    free(enc);
    free(dec);
}
