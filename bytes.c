#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void transpose_block(unsigned Nb, byte block[]) {
    byte *new_block = (byte *)malloc(4 * Nb * sizeof(byte));
    for (unsigned pos = 0, i = 0, j = 0; pos < 4 * Nb; ++pos) {
        new_block[i * Nb + j] = block[pos];
        if (++j == 4) j = 0, ++i;
    }
    memcpy(block, new_block, 4 * Nb * sizeof(byte));
    free(new_block);
}

char *block_to_string(unsigned Nb, byte block[]) {
    char *str = (char *)malloc((8 * Nb + 1) * sizeof(char));
    for (unsigned j = 0; j < Nb; ++j) {
        for (unsigned i = 0; i < 4; ++i) {
            char buffer[3];
            snprintf(buffer, 3, "%02x", block[i * Nb + j]);
            memcpy(str + j * 8 + i * 2, buffer, 2 * sizeof(char));
        }
    }
    str[8 * Nb] = '\0';
    return str;
}
