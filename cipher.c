#include "cipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "io.h"
#include "lookup.h"

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
