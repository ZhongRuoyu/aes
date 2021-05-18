#include "io.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

void error(const char *msg) {
    fprintf(stderr, "Error: %s\n\n", msg);
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

void print_block(unsigned Nb, const byte block[]) {
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
