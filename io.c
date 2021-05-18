#include "io.h"

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
