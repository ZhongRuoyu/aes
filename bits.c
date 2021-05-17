#include <stdlib.h>  // for malloc

#include "aes.h"

byte *to_bytes(word w) {
    byte *bytes = (byte *)malloc(4 * sizeof(byte));
    for (unsigned i = 0; i < 4; ++i) {
        bytes[i] = (w >> (8 * i)) & 0xff;
    }
    return bytes;
}

word to_word(byte b3, byte b2, byte b1, byte b0) {
    return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
}

byte *to_bytes_array(unsigned Nb, const word w[]) {
    byte *bytes = (byte *)malloc(4 * Nb * sizeof(byte));
    for (unsigned j = 0; j < Nb; ++j) {
        word x = w[j];
        for (unsigned i = 0; i < 4; ++i) {
            bytes[i * Nb + j] = (x >> (8 * (3 - i))) & 0xff;
        }
    }
    return bytes;
}
