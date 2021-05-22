#include "io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

void error(const char *msg, const char *from) {
    fprintf(stderr, "Error: %s%s\n\n", from ? from : "", msg);
    exit(EXIT_FAILURE);
}

void print_multiline(char *str, char delimiter) {
    unsigned output_len = strlen(str);
    unsigned pos = 0;
    for (; pos + 32 < output_len; pos += 32) {
        printf("%.32s%c", str + pos, delimiter);
    }
    printf("%s\n", str + pos);
    printf("\n");
}

void print_block(unsigned Nb, const word block[]) {
    for (unsigned j = 0; j < Nb; ++j) {
        printf("%08x", block[j]);
    }
    printf("\n");
}
