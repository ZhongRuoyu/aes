#include "io.h"

#include <stdio.h>
#include <stdlib.h>

#include "aes.h"

void error(const char *msg, const char *from) {
    fprintf(stderr, "Error: %s%s\n\n", from ? from : "", msg);
    exit(EXIT_FAILURE);
}

void print_block(unsigned Nb, const word block[]) {
    for (unsigned j = 0; j < Nb; ++j) {
        const uword t = {block[j]};
        for (unsigned k = 0; k < 4; ++k) {
            printf("%02x", t.bytes[k]);
        }
    }
}
