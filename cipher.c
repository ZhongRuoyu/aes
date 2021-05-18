#include "cipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "debug.h"
#include "lookup.h"

byte *Cipher(unsigned Nb, unsigned Nr, const byte in[], word **w) {
#ifdef DEBUG
    printf("CIPHER (ENCRYPT):\n");
#endif

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

#ifdef DEBUG
    printf("round[%2d].input    ", 0);
    print_block(Nb, state);
#endif

    AddRoundKey(Nb, state, w[0]);

#ifdef DEBUG
    printf("round[%2d].k_sch    ", 0);
    byte *k_sch = to_bytes_array(Nb, w[0]);
    print_block(Nb, k_sch);
    free(k_sch);
#endif

    for (unsigned round = 1; round < Nr; ++round) {
#ifdef DEBUG
        printf("round[%2d].start    ", round);
        print_block(Nb, state);
#endif

        SubBytes(Nb, state);

#ifdef DEBUG
        printf("round[%2d].s_box    ", round);
        print_block(Nb, state);
#endif

        ShiftRows(Nb, state);

#ifdef DEBUG
        printf("round[%2d].s_row    ", round);
        print_block(Nb, state);
#endif

        MixColumns(Nb, state);

#ifdef DEBUG
        printf("round[%2d].m_col    ", round);
        print_block(Nb, state);
#endif

        AddRoundKey(Nb, state, w[round]);

#ifdef DEBUG
        printf("round[%2d].k_sch    ", round);
        k_sch = to_bytes_array(Nb, w[round]);
        print_block(Nb, k_sch);
        free(k_sch);
#endif
    }

#ifdef DEBUG
    printf("round[%2d].start    ", Nr);
    print_block(Nb, state);
#endif

    SubBytes(Nb, state);

#ifdef DEBUG
    printf("round[%2d].s_box    ", Nr);
    print_block(Nb, state);
#endif

    ShiftRows(Nb, state);

#ifdef DEBUG
    printf("round[%2d].s_row    ", Nr);
    print_block(Nb, state);
#endif

    AddRoundKey(Nb, state, w[Nr]);

#ifdef DEBUG
    printf("round[%2d].k_sch    ", Nr);
    k_sch = to_bytes_array(Nb, w[Nr]);
    print_block(Nb, k_sch);
    free(k_sch);
#endif

#ifdef DEBUG
    printf("round[%2d].output   ", Nr);
    print_block(Nb, state);
    printf("\n");
#endif

    return state;
}

byte *InvCipher(unsigned Nb, unsigned Nr, const byte in[], word **w) {
#ifdef DEBUG
    printf("INVERSE CIPHER (DECRYPT):\n");
#endif

    byte *state = (byte *)malloc(4 * Nb * sizeof(byte));
    memcpy(state, in, 4 * Nb * sizeof(byte));

#ifdef DEBUG
    printf("round[%2d].iinput   ", 0);
    print_block(Nb, state);
#endif

    AddRoundKey(Nb, state, w[Nr]);

#ifdef DEBUG
    printf("round[%2d].ik_sch   ", 0);
    byte *ik_sch = to_bytes_array(Nb, w[Nr]);
    print_block(Nb, ik_sch);
    free(ik_sch);
#endif

    for (unsigned round = Nr - 1; round > 0; --round) {
#ifdef DEBUG
        printf("round[%2d].istart   ", Nr - round);
        print_block(Nb, state);
#endif

        InvShiftRows(Nb, state);

#ifdef DEBUG
        printf("round[%2d].is_row   ", Nr - round);
        print_block(Nb, state);
#endif

        InvSubBytes(Nb, state);

#ifdef DEBUG
        printf("round[%2d].is_box   ", Nr - round);
        print_block(Nb, state);
#endif

        AddRoundKey(Nb, state, w[round]);

#ifdef DEBUG
        printf("round[%2d].ik_sch   ", Nr - round);
        ik_sch = to_bytes_array(Nb, w[round]);
        print_block(Nb, ik_sch);
        free(ik_sch);
#endif

#ifdef DEBUG
        printf("round[%2d].ik_add   ", Nr - round);
        print_block(Nb, state);
#endif

        InvMixColumns(Nb, state);
    }

#ifdef DEBUG
    printf("round[%2d].istart   ", Nr);
    print_block(Nb, state);
#endif

    InvShiftRows(Nb, state);

#ifdef DEBUG
    printf("round[%2d].is_row   ", Nr);
    print_block(Nb, state);
#endif

    InvSubBytes(Nb, state);

#ifdef DEBUG
    printf("round[%2d].is_box   ", Nr);
    print_block(Nb, state);
#endif

    AddRoundKey(Nb, state, w[0]);

#ifdef DEBUG
    printf("round[%2d].ik_sch   ", Nr);
    ik_sch = to_bytes_array(Nb, w[0]);
    print_block(Nb, ik_sch);
    free(ik_sch);
#endif

#ifdef DEBUG
    printf("round[%2d].output   ", Nr);
    print_block(Nb, state);
    printf("\n");
#endif

    return state;
}
