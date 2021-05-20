#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "io.h"

static byte *verbose_Cipher(unsigned Nb, unsigned Nr, const byte in[], byte **w);
static byte *verbose_InvCipher(unsigned Nb, unsigned Nr, const byte in[], byte **w);

static inline byte multiply(byte a, byte b);

static void SubBytes(unsigned Nb, byte state[]);
static void InvSubBytes(unsigned Nb, byte state[]);
static void ShiftRows(unsigned Nb, byte state[]);
static void InvShiftRows(unsigned Nb, byte state[]);
static void MixColumns(unsigned Nb, byte state[]);
static void InvMixColumns(unsigned Nb, byte state[]);
static inline void AddRoundKey(unsigned Nb, byte state[], const byte w[]);

byte *Cipher(unsigned Nb, unsigned Nr, const byte in[], byte **w) {
    if (verbose) return verbose_Cipher(Nb, Nr, in, w);

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

    AddRoundKey(Nb, state, w[0]);

    for (unsigned round = 1; round < Nr; ++round) {
        SubBytes(Nb, state);
        ShiftRows(Nb, state);
        MixColumns(Nb, state);
        AddRoundKey(Nb, state, w[round]);
    }

    SubBytes(Nb, state);
    ShiftRows(Nb, state);
    AddRoundKey(Nb, state, w[Nr]);

    return state;
}

static byte *verbose_Cipher(unsigned Nb, unsigned Nr, const byte in[], byte **w) {
    printf("CIPHER (ENCRYPT):\n");

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

    printf("round[%2d].input    ", 0);
    print_block(Nb, state);

    AddRoundKey(Nb, state, w[0]);

    printf("round[%2d].k_sch    ", 0);
    print_block(Nb, w[0]);

    for (unsigned round = 1; round < Nr; ++round) {
        printf("round[%2d].start    ", round);
        print_block(Nb, state);

        SubBytes(Nb, state);

        printf("round[%2d].s_box    ", round);
        print_block(Nb, state);

        ShiftRows(Nb, state);

        printf("round[%2d].s_row    ", round);
        print_block(Nb, state);

        MixColumns(Nb, state);

        printf("round[%2d].m_col    ", round);
        print_block(Nb, state);

        AddRoundKey(Nb, state, w[round]);

        printf("round[%2d].k_sch    ", round);
        print_block(Nb, w[round]);
    }

    printf("round[%2d].start    ", Nr);
    print_block(Nb, state);

    SubBytes(Nb, state);

    printf("round[%2d].s_box    ", Nr);
    print_block(Nb, state);

    ShiftRows(Nb, state);

    printf("round[%2d].s_row    ", Nr);
    print_block(Nb, state);

    AddRoundKey(Nb, state, w[Nr]);

    printf("round[%2d].k_sch    ", Nr);
    print_block(Nb, w[Nr]);

    printf("round[%2d].output   ", Nr);
    print_block(Nb, state);
    printf("\n");

    return state;
}

byte *InvCipher(unsigned Nb, unsigned Nr, const byte in[], byte **w) {
    if (verbose) return verbose_InvCipher(Nb, Nr, in, w);

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

    AddRoundKey(Nb, state, w[Nr]);

    for (unsigned round = Nr - 1; round > 0; --round) {
        InvShiftRows(Nb, state);
        InvSubBytes(Nb, state);
        AddRoundKey(Nb, state, w[round]);
        InvMixColumns(Nb, state);
    }

    InvShiftRows(Nb, state);
    InvSubBytes(Nb, state);
    AddRoundKey(Nb, state, w[0]);

    return state;
}

static byte *verbose_InvCipher(unsigned Nb, unsigned Nr, const byte in[], byte **w) {
    printf("INVERSE CIPHER (DECRYPT):\n");

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

    printf("round[%2d].iinput   ", 0);
    print_block(Nb, state);

    AddRoundKey(Nb, state, w[Nr]);

    printf("round[%2d].ik_sch   ", 0);
    print_block(Nb, w[Nr]);

    for (unsigned round = Nr - 1; round > 0; --round) {
        printf("round[%2d].istart   ", Nr - round);
        print_block(Nb, state);

        InvShiftRows(Nb, state);

        printf("round[%2d].is_row   ", Nr - round);
        print_block(Nb, state);

        InvSubBytes(Nb, state);

        printf("round[%2d].is_box   ", Nr - round);
        print_block(Nb, state);

        AddRoundKey(Nb, state, w[round]);

        printf("round[%2d].ik_sch   ", Nr - round);
        print_block(Nb, w[round]);

        printf("round[%2d].ik_add   ", Nr - round);
        print_block(Nb, state);

        InvMixColumns(Nb, state);
    }

    printf("round[%2d].istart   ", Nr);
    print_block(Nb, state);

    InvShiftRows(Nb, state);

    printf("round[%2d].is_row   ", Nr);
    print_block(Nb, state);

    InvSubBytes(Nb, state);

    printf("round[%2d].is_box   ", Nr);
    print_block(Nb, state);

    AddRoundKey(Nb, state, w[0]);

    printf("round[%2d].ik_sch   ", Nr);
    print_block(Nb, w[0]);

    printf("round[%2d].output   ", Nr);
    print_block(Nb, state);
    printf("\n");

    return state;
}

static inline byte multiply(byte a, byte b) {
    byte res = 0;
    for (; b; b >>= 1) {
        if (b & 1) res ^= a;
        a = a << 1 ^ (a & 0x80 ? 0x1b : 0);
    }
    return res;
}

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
        for (unsigned i = 0; i < 4; ++i) {
            byte product = 0;
            for (unsigned k = 0; k < 4; ++k) {
                product ^= multiply(state[k * Nb + j], MixColumns_multiplier[(4 - i + k) % 4]);
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
        for (unsigned i = 0; i < 4; ++i) {
            byte product = 0;
            for (unsigned k = 0; k < 4; ++k) {
                product ^= multiply(state[k * Nb + j], InvMixColumns_multiplier[(4 - i + k) % 4]);
            }
            new_state[i * Nb + j] = product;
        }
    }
    memcpy(state, new_state, 4 * Nb * sizeof(byte));
    free(new_state);
}

static inline void AddRoundKey(unsigned Nb, byte state[], const byte w[]) {
    for (unsigned pos = 0; pos < 4 * Nb; ++pos) {
        state[pos] ^= w[pos];
    }
}
