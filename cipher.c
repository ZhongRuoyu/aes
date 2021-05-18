#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "cipher.h"
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
