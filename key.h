#ifndef KEY_H_
#define KEY_H_

#include <stdlib.h>

#include "aes.h"
#include "lookup.h"

static word SubWord(word w);
static word RotWord(word w);

static word **wrap_key(unsigned Nb, unsigned Nr, const word w[], unsigned Nk);

static word SubWord(word in) {
    byte *bytes = to_bytes(in);
    for (unsigned i = 0; i < 4; ++i) {
        bytes[i] = s_box[bytes[i]];
    }
    word out = to_word(bytes[3], bytes[2], bytes[1], bytes[0]);
    free(bytes);
    return out;
}

static word RotWord(word w) {
    return (w << 8) | (w >> 24);
}

static word **wrap_key(unsigned Nb, unsigned Nr, const word w[], unsigned Nk) {
    word **out = (word **)malloc((Nr + 1) * sizeof(const word *));
    for (unsigned i = 0; i < Nr + 1; ++i) {
        out[i] = (word *)malloc(Nb * sizeof(word));
        for (unsigned j = 0; j < Nb; ++j) {
            out[i][j] = w[i * Nb + j];
        }
    }
    return out;
}
#endif  // KEY_H_
