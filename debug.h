#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdio.h>

#include "aes.h"

static void print_state(const byte *state) {
    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned j = 0; j < 4; ++j) {
            printf("%2x ", state[i * 4 + j]);
        }
        printf("\n");
    }
    printf("\n");
}

#endif  // DEBUG_H_
