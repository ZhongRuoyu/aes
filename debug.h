#ifndef DEBUG_H_
#define DEBUG_H_

#include <ctype.h>
#include <stdio.h>

#include "aes.h"

static void print_block(unsigned Nb, const byte block[]);

static void print_block(unsigned Nb, const byte block[]) {
    for (unsigned j = 0; j < Nb; ++j) {
        for (unsigned i = 0; i < 4; ++i) {
            char buffer[3];
            sprintf_s(buffer, 3, "%2x", block[i * 4 + j]);
            if (isspace(buffer[0])) buffer[0] = '0';
            printf_s("%2s", buffer);
        }
    }
    printf("\n");
}

#endif  // DEBUG_H_
