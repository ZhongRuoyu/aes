#include "io.h"

#include <stdio.h>
#include <string.h>

void print_multiline(char *str, char delimiter) {
    unsigned output_len = strlen(str);
    unsigned pos = 0;
    for (; pos + 32 < output_len; pos += 32) {
        printf("%.32s%c", str + pos, delimiter);
    }
    printf("%s\n", str + pos);
    printf("\n");
}
