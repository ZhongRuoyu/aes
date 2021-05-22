#include <stdlib.h>
#include <string.h>

#include "aes.h"

static void SubBytes(unsigned Nb, word state[]);
static void InvSubBytes(unsigned Nb, word state[]);

static void ShiftRows(unsigned Nb, word state[]);
static void InvShiftRows(unsigned Nb, word state[]);

word *Cipher(unsigned Nb, unsigned Nr, const word in[], word **key) {
    word *state = (word *)malloc(Nb * sizeof(word));
    memcpy(state, in, Nb * sizeof(word));

    for (unsigned j = 0; j < Nb; ++j) {
        state[j] ^= key[0][j];
    }

    for (unsigned round = 1; round < Nr; ++round) {
        uword *w = (uword *)malloc(Nb * sizeof(uword));
        for (unsigned j = 0; j < Nb; ++j) {
            w[j].word = state[j];
        }
        for (unsigned j = 0; j < Nb; ++j) {
            state[j] =
                cipher_table[0][w[(j + 0) % Nb].bytes[3]] ^
                cipher_table[1][w[(j + 1) % Nb].bytes[2]] ^
                cipher_table[2][w[(j + 2) % Nb].bytes[1]] ^
                cipher_table[3][w[(j + 3) % Nb].bytes[0]] ^
                key[round][j];
        }
        free(w);
    }

    SubBytes(Nb, state);
    ShiftRows(Nb, state);
    for (unsigned j = 0; j < Nb; ++j) {
        state[j] ^= key[Nr][j];
    }

    return state;
}

word *InvCipher(unsigned Nb, unsigned Nr, const word in[], word **key) {
    word *state = (word *)malloc(Nb * sizeof(word));
    memcpy(state, in, Nb * sizeof(word));

    for (unsigned j = 0; j < Nb; ++j) {
        state[j] ^= key[Nr][j];
    }

    for (unsigned round = Nr - 1; round > 0; --round) {
        uword *w = (uword *)malloc(Nb * sizeof(uword));
        for (unsigned j = 0; j < Nb; ++j) {
            w[j].word = state[j];
        }
        for (unsigned j = 0; j < Nb; ++j) {
            state[j] =
                inv_cipher_table[0][w[(j + 4) % Nb].bytes[3]] ^
                inv_cipher_table[1][w[(j + 3) % Nb].bytes[2]] ^
                inv_cipher_table[2][w[(j + 2) % Nb].bytes[1]] ^
                inv_cipher_table[3][w[(j + 1) % Nb].bytes[0]] ^
                key[round][j];
        }
        free(w);
    }

    InvShiftRows(Nb, state);
    InvSubBytes(Nb, state);
    for (unsigned j = 0; j < Nb; ++j) {
        state[j] ^= key[0][j];
    }

    return state;
}

static void SubBytes(unsigned Nb, word state[]) {
    for (unsigned j = 0; j < Nb; ++j) {
        const uword temp = {state[j]};
        state[j] =
            s_box[0][temp.bytes[0]] ^
            s_box[1][temp.bytes[1]] ^
            s_box[2][temp.bytes[2]] ^
            s_box[3][temp.bytes[3]];
    }
}

static void InvSubBytes(unsigned Nb, word state[]) {
    for (unsigned j = 0; j < Nb; ++j) {
        const uword temp = {state[j]};
        state[j] =
            inverse_s_box[0][temp.bytes[0]] ^
            inverse_s_box[1][temp.bytes[1]] ^
            inverse_s_box[2][temp.bytes[2]] ^
            inverse_s_box[3][temp.bytes[3]];
    }
}

static void ShiftRows(unsigned Nb, word state[]) {
    uword *w = (uword *)malloc(Nb * sizeof(uword));
    for (unsigned j = 0; j < Nb; ++j) {
        w[j].word = state[j];
    }
    for (unsigned j = 0; j < Nb; ++j) {
        state[j] =
            w[(j + 0) % Nb].bytes[3] << 24 ^
            w[(j + 1) % Nb].bytes[2] << 16 ^
            w[(j + 2) % Nb].bytes[1] << 8 ^
            w[(j + 3) % Nb].bytes[0] << 0;
    }
    free(w);
}

static void InvShiftRows(unsigned Nb, word state[]) {
    uword *w = (uword *)malloc(Nb * sizeof(uword));
    for (unsigned j = 0; j < Nb; ++j) {
        w[j].word = state[j];
    }
    for (unsigned j = 0; j < Nb; ++j) {
        state[j] =
            w[(j + 4) % Nb].bytes[3] << 24 ^
            w[(j + 3) % Nb].bytes[2] << 16 ^
            w[(j + 2) % Nb].bytes[1] << 8 ^
            w[(j + 1) % Nb].bytes[0] << 0;
    }
    free(w);
}
