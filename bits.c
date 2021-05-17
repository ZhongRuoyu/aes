#include <stdlib.h>  // for malloc

#include "aes.h"

byte *to_bytes(unsigned Nb, const word w[]) {
    byte *bytes = (byte *)malloc(4U * Nb * sizeof(byte));
    for (unsigned j = 0; j < Nb; ++j) {
        word x = w[j];
        for (unsigned i = 0; i < 4; ++i) {
            bytes[i * Nb + j] = (x >> (8 * i)) & 0xff;
        }
    }
    return bytes;
}
