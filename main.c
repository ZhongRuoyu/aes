#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "debug.h"
#include "io.h"

int main(int argc, char **argv) {
    const unsigned Nk = 4, Nr = 10, Nb = 4;
    const char *key = "2b7e1516 28aed2a6 abf71588 09cf4f3c";
    const char *in = "3243f6a8885a308d313198a2e0370734";
    char *out = cipher_hex(Nk, key, in);
    print_multiline(out, '\n');
    free(out);
}
