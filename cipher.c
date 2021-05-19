#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "galois.h"
#include "io.h"

static void SubBytes(unsigned Nb, byte state[]);
static void InvSubBytes(unsigned Nb, byte state[]);
static void ShiftRows(unsigned Nb, byte state[]);
static void InvShiftRows(unsigned Nb, byte state[]);
static void MixColumns(unsigned Nb, byte state[]);
static void InvMixColumns(unsigned Nb, byte state[]);
static void AddRoundKey(unsigned Nb, byte state[], const word w[]);

byte *Cipher(unsigned Nb, unsigned Nr, const byte in[], word **w) {
    if (verbose) {
        printf("CIPHER (ENCRYPT):\n");
    }

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

    if (verbose) {
        printf("round[%2d].input    ", 0);
        print_block(Nb, state);
    }

    AddRoundKey(Nb, state, w[0]);

    if (verbose) {
        printf("round[%2d].k_sch    ", 0);
        byte *k_sch = to_bytes_array(Nb, w[0]);
        print_block(Nb, k_sch);
        free(k_sch);
    }

    for (unsigned round = 1; round < Nr; ++round) {
        if (verbose) {
            printf("round[%2d].start    ", round);
            print_block(Nb, state);
        }

        SubBytes(Nb, state);

        if (verbose) {
            printf("round[%2d].s_box    ", round);
            print_block(Nb, state);
        }

        ShiftRows(Nb, state);

        if (verbose) {
            printf("round[%2d].s_row    ", round);
            print_block(Nb, state);
        }

        MixColumns(Nb, state);

        if (verbose) {
            printf("round[%2d].m_col    ", round);
            print_block(Nb, state);
        }

        AddRoundKey(Nb, state, w[round]);

        if (verbose) {
            printf("round[%2d].k_sch    ", round);
            byte *k_sch = to_bytes_array(Nb, w[round]);
            print_block(Nb, k_sch);
            free(k_sch);
        }
    }

    if (verbose) {
        printf("round[%2d].start    ", Nr);
        print_block(Nb, state);
    }

    SubBytes(Nb, state);

    if (verbose) {
        printf("round[%2d].s_box    ", Nr);
        print_block(Nb, state);
    }

    ShiftRows(Nb, state);

    if (verbose) {
        printf("round[%2d].s_row    ", Nr);
        print_block(Nb, state);
    }

    AddRoundKey(Nb, state, w[Nr]);

    if (verbose) {
        printf("round[%2d].k_sch    ", Nr);
        byte *k_sch = to_bytes_array(Nb, w[Nr]);
        print_block(Nb, k_sch);
        free(k_sch);
    }

    if (verbose) {
        printf("round[%2d].output   ", Nr);
        print_block(Nb, state);
        printf("\n");
    }

    return state;
}

byte *InvCipher(unsigned Nb, unsigned Nr, const byte in[], word **w) {
    if (verbose) {
        printf("INVERSE CIPHER (DECRYPT):\n");
    }

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

    if (verbose) {
        printf("round[%2d].iinput   ", 0);
        print_block(Nb, state);
    }

    AddRoundKey(Nb, state, w[Nr]);

    if (verbose) {
        printf("round[%2d].ik_sch   ", 0);
        byte *ik_sch = to_bytes_array(Nb, w[Nr]);
        print_block(Nb, ik_sch);
        free(ik_sch);
    }

    for (unsigned round = Nr - 1; round > 0; --round) {
        if (verbose) {
            printf("round[%2d].istart   ", Nr - round);
            print_block(Nb, state);
        }

        InvShiftRows(Nb, state);

        if (verbose) {
            printf("round[%2d].is_row   ", Nr - round);
            print_block(Nb, state);
        }

        InvSubBytes(Nb, state);

        if (verbose) {
            printf("round[%2d].is_box   ", Nr - round);
            print_block(Nb, state);
        }

        AddRoundKey(Nb, state, w[round]);

        if (verbose) {
            printf("round[%2d].ik_sch   ", Nr - round);
            byte *ik_sch = to_bytes_array(Nb, w[round]);
            print_block(Nb, ik_sch);
            free(ik_sch);
        }

        if (verbose) {
            printf("round[%2d].ik_add   ", Nr - round);
            print_block(Nb, state);
        }

        InvMixColumns(Nb, state);
    }

    if (verbose) {
        printf("round[%2d].istart   ", Nr);
        print_block(Nb, state);
    }

    InvShiftRows(Nb, state);

    if (verbose) {
        printf("round[%2d].is_row   ", Nr);
        print_block(Nb, state);
    }

    InvSubBytes(Nb, state);

    if (verbose) {
        printf("round[%2d].is_box   ", Nr);
        print_block(Nb, state);
    }

    AddRoundKey(Nb, state, w[0]);

    if (verbose) {
        printf("round[%2d].ik_sch   ", Nr);
        byte *ik_sch = to_bytes_array(Nb, w[0]);
        print_block(Nb, ik_sch);
        free(ik_sch);
    }

    if (verbose) {
        printf("round[%2d].output   ", Nr);
        print_block(Nb, state);
        printf("\n");
    }

    return state;
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
