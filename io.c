#include "io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

void error(const char *msg, const char *from) {
    fprintf(stderr, "Error: %s%s\n\n", from ? from : "", msg);
    exit(EXIT_FAILURE);
}

void print_multiline(const char *str, char delimiter) {
    size_t output_len = strlen(str);
    size_t pos = 0;
    for (; pos + 32 < output_len; pos += 32) {
        printf("%.32s%c", str + pos, delimiter);
    }
    printf("%s\n", str + pos);
}

void print_block(unsigned Nb, const word block[]) {
    for (unsigned j = 0; j < Nb; ++j) {
        const uword t = {block[j]};
        for (unsigned k = 0; k < 4; ++k) {
            printf("%02x", t.bytes[k]);
        }
    }
}
