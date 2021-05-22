#include <stdio.h>
#include <stdlib.h>

#include "aes.h"

void change_endianness(unsigned Nb, word block[]) {
    for (unsigned j = 0; j < Nb; ++j) {
        const uword w = {block[j]};
        block[j] = w.bytes[3] << 0 ^
                   w.bytes[2] << 8 ^
                   w.bytes[1] << 16 ^
                   w.bytes[0] << 24;
    }
}

char *block_to_string(unsigned Nb, word block[]) {
    char *str = (char *)malloc((8 * Nb + 1) * sizeof(char));
    for (unsigned j = 0; j < Nb; ++j) {
        snprintf(str + j * 8, 9, "%08x", block[j]);
    }
    // the terminating null character is handled by the last snprintf() call
    return str;
}
