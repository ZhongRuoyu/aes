#include <stdlib.h>  // for malloc
#include <string.h>  // for memcpy

#include "aes.h"
#include "debug.h"
#include "lookup.h"

byte *cipher(unsigned Nb, unsigned Nr, byte in[], word w[][4]) {
#ifdef DEBUG
    printf("Input\n");
    print_state(in);
#endif

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

    AddRoundKey(Nb, state, w[0]);

    for (unsigned round = 1; round < Nr; ++round) {
#ifdef DEBUG
        printf("Round %d\n\n", round);
#endif

        SubBytes(Nb, state);
        ShiftRows(Nb, state);
        MixColumns(Nb, state);
        AddRoundKey(Nb, state, w[round]);
    }

    SubBytes(Nb, state);
    ShiftRows(Nb, state);
    AddRoundKey(Nb, state, w[Nr]);

#ifdef DEBUG
    printf("Output\n");
    print_state(in);
#endif

    return state;
}

void SubBytes(unsigned Nb, byte state[]) {
    for (unsigned pos = 0; pos < 4 * Nb; ++pos) {
        state[pos] = s_box[state[pos]];
    }

#ifdef DEBUG
    printf("After SubBytes\n");
    print_state(state);
#endif
}

void ShiftRows(unsigned Nb, byte state[]) {
    byte *new_state = (byte *)malloc(4 * Nb * sizeof(byte));

    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned j = 0; j < Nb; ++j) {
            new_state[i * Nb + j] = state[i * Nb + (j + i) % Nb];
        }
    }

    memcpy(state, new_state, 4 * Nb * sizeof(byte));
    free(new_state);

#ifdef DEBUG
    printf("After ShiftRows\n");
    print_state(state);
#endif
}

void MixColumns(unsigned Nb, byte state[]) {
    byte *new_state = (byte *)malloc(4 * Nb * sizeof(byte));

    for (unsigned j = 0; j < Nb; ++j) {
        const byte r[4] = {state[0 * Nb + j],
                           state[1 * Nb + j],
                           state[2 * Nb + j],
                           state[3 * Nb + j]};
        new_state[0 * Nb + j] = multiply(0x02, r[0]) ^
                                multiply(0x03, r[1]) ^
                                r[2] ^
                                r[3];
        new_state[1 * Nb + j] = r[0] ^
                                multiply(0x02, r[1]) ^
                                multiply(0x03, r[2]) ^
                                r[3];
        new_state[2 * Nb + j] = r[0] ^
                                r[1] ^
                                multiply(0x02, r[2]) ^
                                multiply(0x03, r[3]);
        new_state[3 * Nb + j] = multiply(0x03, r[0]) ^
                                r[1] ^
                                r[2] ^
                                multiply(0x02, r[3]);
    }

    memcpy(state, new_state, 4 * Nb * sizeof(byte));
    free(new_state);

#ifdef DEBUG
    printf("After MixColumns\n");
    print_state(state);
#endif
}

void AddRoundKey(unsigned Nb, byte state[], word w[]) {
    byte *bytes = to_bytes(Nb, w);

#ifdef DEBUG
    printf("Round Key Value\n");
    print_state(bytes);
#endif

    for (unsigned pos = 0; pos < 4 * Nb; ++pos) {
        state[pos] ^= bytes[pos];
    }

#ifdef DEBUG
    printf("After AddRoundKey\n");
    print_state(state);
#endif

    free(bytes);
}
