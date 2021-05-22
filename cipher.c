#include <stdlib.h>

#include "aes.h"

word *Cipher(unsigned Nb, unsigned Nr, const word in[], word **key) {
    word *state = (word *)malloc(Nb * sizeof(word));
    uword *prev = (uword *)malloc(Nb * sizeof(uword));

    for (unsigned j = 0; j < Nb; ++j) {
        prev[j].word = state[j] = in[j] ^ key[0][j];
    }

    for (unsigned round = 1; round < Nr; ++round) {
        for (unsigned j = 0; j < Nb; ++j) {
            state[j] =
                cipher_table[0][prev[(j + 0) % Nb].bytes[3]] ^
                cipher_table[1][prev[(j + 1) % Nb].bytes[2]] ^
                cipher_table[2][prev[(j + 2) % Nb].bytes[1]] ^
                cipher_table[3][prev[(j + 3) % Nb].bytes[0]] ^
                key[round][j];
        }
        for (unsigned j = 0; j < Nb; ++j) {
            prev[j].word = state[j];
        }
    }

    for (unsigned j = 0; j < Nb; ++j) {
        state[j] =
            s_box[3][prev[(j + 0) % Nb].bytes[3]] ^
            s_box[2][prev[(j + 1) % Nb].bytes[2]] ^
            s_box[1][prev[(j + 2) % Nb].bytes[1]] ^
            s_box[0][prev[(j + 3) % Nb].bytes[0]] ^
            key[Nr][j];
    }

    free(prev);

    return state;
}

word *InvCipher(unsigned Nb, unsigned Nr, const word in[], word **key) {
    word *state = (word *)malloc(Nb * sizeof(word));
    uword *prev = (uword *)malloc(Nb * sizeof(uword));

    for (unsigned j = 0; j < Nb; ++j) {
        prev[j].word = state[j] = in[j] ^ key[Nr][j];
    }

    for (unsigned round = Nr - 1; round > 0; --round) {
        for (unsigned j = 0; j < Nb; ++j) {
            state[j] =
                inv_cipher_table[0][prev[(j + 4) % Nb].bytes[3]] ^
                inv_cipher_table[1][prev[(j + 3) % Nb].bytes[2]] ^
                inv_cipher_table[2][prev[(j + 2) % Nb].bytes[1]] ^
                inv_cipher_table[3][prev[(j + 1) % Nb].bytes[0]] ^
                key[round][j];
        }
        for (unsigned j = 0; j < Nb; ++j) {
            prev[j].word = state[j];
        }
    }

    for (unsigned j = 0; j < Nb; ++j) {
        state[j] =
            inverse_s_box[3][prev[(j + 4) % Nb].bytes[3]] ^
            inverse_s_box[2][prev[(j + 3) % Nb].bytes[2]] ^
            inverse_s_box[1][prev[(j + 2) % Nb].bytes[1]] ^
            inverse_s_box[0][prev[(j + 1) % Nb].bytes[0]] ^
            key[0][j];
    }

    free(prev);

    return state;
}
