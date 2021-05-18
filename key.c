#include "key.h"

#include <stdio.h>
#include <stdlib.h>

#include "aes.h"
#include "io.h"
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

    return w;
}
