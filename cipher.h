#ifndef CIPHER_H_
#define CIPHER_H_

#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "galois.h"
#include "lookup.h"

static void SubBytes(unsigned Nb, byte state[]);
static void InvSubBytes(unsigned Nb, byte state[]);
static void ShiftRows(unsigned Nb, byte state[]);
static void InvShiftRows(unsigned Nb, byte state[]);
static void MixColumns(unsigned Nb, byte state[]);
static void InvMixColumns(unsigned Nb, byte state[]);
static void AddRoundKey(unsigned Nb, byte state[], const word w[]);

static void SubBytes(unsigned Nb, byte state[]) {
    for (unsigned pos = 0; pos < 4 * Nb; ++pos) {
        state[pos] = s_box[state[pos]];
    }
}

static void InvSubBytes(unsigned Nb, byte state[]) {
    for (unsigned pos = 0; pos < 4 * Nb; ++pos) {
        state[pos] = inverse_s_box[state[pos]];
    }
}

static void ShiftRows(unsigned Nb, byte state[]) {
    byte *new_state = (byte *)malloc(4 * Nb * sizeof(byte));
    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned j = 0; j < Nb; ++j) {
            new_state[i * Nb + j] = state[i * Nb + (j + i) % Nb];
        }
    }
    memcpy(state, new_state, 4 * Nb * sizeof(byte));
    free(new_state);
}

static void InvShiftRows(unsigned Nb, byte state[]) {
    byte *new_state = (byte *)malloc(4 * Nb * sizeof(byte));
    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned j = 0; j < Nb; ++j) {
            new_state[i * Nb + j] = state[i * Nb + (Nb + j - i) % Nb];
        }
    }
    memcpy(state, new_state, 4 * Nb * sizeof(byte));
    free(new_state);
}

static void MixColumns(unsigned Nb, byte state[]) {
    byte *new_state = (byte *)malloc(4 * Nb * sizeof(byte));
    for (unsigned j = 0; j < Nb; ++j) {
        const byte r[4] = {state[0 * Nb + j],
                           state[1 * Nb + j],
                           state[2 * Nb + j],
                           state[3 * Nb + j]};
        for (unsigned i = 0; i < 4; ++i) {
            byte product = 0;
            for (unsigned k = 0; k < 4; ++k) {
                product ^= multiply(r[k], MixColumns_multiplier[(4 - i + k) % 4]);
            }
            new_state[i * Nb + j] = product;
        }
    }
    memcpy(state, new_state, 4 * Nb * sizeof(byte));
    free(new_state);
}

static void InvMixColumns(unsigned Nb, byte state[]) {
    byte *new_state = (byte *)malloc(4 * Nb * sizeof(byte));
    for (unsigned j = 0; j < Nb; ++j) {
        const byte r[4] = {state[0 * Nb + j],
                           state[1 * Nb + j],
                           state[2 * Nb + j],
                           state[3 * Nb + j]};
        for (unsigned i = 0; i < 4; ++i) {
            byte product = 0;
            for (unsigned k = 0; k < 4; ++k) {
                product ^= multiply(r[k], InvMixColumns_multiplier[(4 - i + k) % 4]);
            }
            new_state[i * Nb + j] = product;
        }
    }
    memcpy(state, new_state, 4 * Nb * sizeof(byte));
    free(new_state);
}

static void AddRoundKey(unsigned Nb, byte state[], const word w[]) {
    byte *bytes = to_bytes_array(Nb, w);
    for (unsigned pos = 0; pos < 4 * Nb; ++pos) {
        state[pos] ^= bytes[pos];
    }
    free(bytes);
}

#endif  // CIPHER_H_