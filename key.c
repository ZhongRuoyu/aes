#include <stdlib.h>

#include "aes.h"
#include "debug.h"
#include "lookup.h"

word *KeyExpansion(unsigned Nb, unsigned Nr, const word key[], unsigned Nk) {
    word *w = (word *)malloc(Nb * (Nr + 1) * sizeof(word));

    for (unsigned i = 0; i < Nk; ++i) {
        w[i] = key[i];
    }

    for (unsigned i = Nk; i < Nb * (Nr + 1); ++i) {
        word temp = w[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = SubWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }

#ifdef DEBUG
    printf("Key Expansion\n");
    for (unsigned i = 0; i < Nr + 1; ++i) {
        printf("%2d ", i);
        for (unsigned j = 0; j < Nb; ++j) {
            printf("%8x ", w[i * Nb + j]);
        }
        printf("\n");
    }
    printf("\n");
#endif

    return w;
}

word SubWord(word in) {
    byte *bytes = to_bytes(in);
    for (unsigned i = 0; i < 4; ++i) {
        bytes[i] = s_box[bytes[i]];
    }
    word out = to_word(bytes[3], bytes[2], bytes[1], bytes[0]);
    free(bytes);
    return out;
}

word RotWord(word w) {
    return (w << 8) | (w >> 24);
}

word **wrap_key(unsigned Nb, unsigned Nr, const word *w, unsigned Nk) {
    word **out = (word **)malloc((Nr + 1) * sizeof(const word *));
    for (unsigned i = 0; i < Nr + 1; ++i) {
        out[i] = (word *)malloc(Nb * sizeof(word));
        for (unsigned j = 0; j < Nb; ++j) {
            out[i][j] = w[i * Nb + j];
        }
    }
    return out;
}