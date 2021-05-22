#include <stdlib.h>
#include <string.h>

#include "aes.h"

static inline word SubWord(word w);
static inline word RotWord(word w);

word **KeyExpansion(unsigned Nb, unsigned Nr, const word key[], unsigned Nk) {
    word *w = (word *)malloc(Nb * (Nr + 1) * sizeof(word));

    memcpy(w, key, Nk * sizeof(word));

    for (unsigned i = Nk; i < Nb * (Nr + 1); ++i) {
        w[i] = w[i - Nk] ^
               ((i % Nk == 0)             ? (SubWord(RotWord(w[i - 1])) ^ Rcon[i / Nk])
                : (Nk > 6 && i % Nk == 4) ? SubWord(w[i - 1])
                                          : w[i - 1]);
    }

    word **out = (word **)malloc((Nr + 1) * sizeof(word *));
    for (unsigned i = 0; i <= Nr; ++i) {
        out[i] = (word *)malloc(Nb * sizeof(word));
        memcpy(out[i], w + i * Nb, Nb * sizeof(word));
    }

    free(w);
    
    return out;
}

static inline word SubWord(word w) {
    const uword temp = {w};
    return s_box[0][temp.bytes[0]] ^
           s_box[1][temp.bytes[1]] ^
           s_box[2][temp.bytes[2]] ^
           s_box[3][temp.bytes[3]];
}

static inline word RotWord(word w) {
    return (w << 8) | (w >> 24);
}
