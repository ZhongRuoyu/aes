#include <stdlib.h>  // for malloc
#include <string.h>  // for memcpy

#include "aes.h"
#include "debug.h"
#include "lookup.h"

byte *Cipher(unsigned Nb, unsigned Nr, const byte in[], word **w) {
#ifdef DEBUG
    printf("Cipher begins\n\n");
    printf("Cipher input\n");
    print_state(in);
#endif

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

    AddRoundKey(Nb, state, w[0]);

    for (unsigned round = 1; round < Nr; ++round) {
#ifdef DEBUG
        printf("Cipher round %d\n\n", round);
#endif

        SubBytes(Nb, state);
        ShiftRows(Nb, state);
        MixColumns(Nb, state);
        AddRoundKey(Nb, state, w[round]);
    }

#ifdef DEBUG
    printf("Cipher round %d\n\n", Nr);
#endif

    SubBytes(Nb, state);
    ShiftRows(Nb, state);
    AddRoundKey(Nb, state, w[Nr]);

#ifdef DEBUG
    printf("Cipher output\n");
    print_state(state);
    printf("Cipher ends\n\n");
#endif

    return state;
}

byte *InvCipher(unsigned Nb, unsigned Nr, const byte in[], word **w) {
#ifdef DEBUG
    printf("InvCipher begins\n\n");
    printf("InvCipher input\n");
    print_state(in);
#endif

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

#ifdef DEBUG
    printf("InvCipher round %d\n\n", Nr);
#endif

    AddRoundKey(Nb, state, w[Nr]);

    for (unsigned round = Nr - 1; round > 0; --round) {
#ifdef DEBUG
        printf("InvCipher round %d\n\n", round);
#endif

        InvShiftRows(Nb, state);
        InvSubBytes(Nb, state);
        AddRoundKey(Nb, state, w[round]);
        InvMixColumns(Nb, state);
    }

#ifdef DEBUG
    printf("InvCipher round 0\n\n");
#endif

    InvShiftRows(Nb, state);
    InvSubBytes(Nb, state);
    AddRoundKey(Nb, state, w[0]);

#ifdef DEBUG
    printf("InvCipher output\n");
    print_state(state);
    printf("InvCipher ends\n\n");
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

void InvSubBytes(unsigned Nb, byte state[]) {
    for (unsigned pos = 0; pos < 4 * Nb; ++pos) {
        state[pos] = inverse_s_box[state[pos]];
    }

#ifdef DEBUG
    printf("After InvSubBytes\n");
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

void InvShiftRows(unsigned Nb, byte state[]) {
    byte *new_state = (byte *)malloc(4 * Nb * sizeof(byte));

    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned j = 0; j < Nb; ++j) {
            new_state[i * Nb + j] = state[i * Nb + (Nb + j - i) % Nb];
        }
    }

    memcpy(state, new_state, 4 * Nb * sizeof(byte));
    free(new_state);

#ifdef DEBUG
    printf("After InvShiftRows\n");
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

#ifdef DEBUG
    printf("After MixColumns\n");
    print_state(state);
#endif
}

void InvMixColumns(unsigned Nb, byte state[]) {
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

#ifdef DEBUG
    printf("After InvMixColumns\n");
    print_state(state);
#endif
}

void AddRoundKey(unsigned Nb, byte state[], const word w[]) {
    byte *bytes = to_bytes_array(Nb, w);

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
