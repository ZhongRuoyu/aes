// disables deprecation warning for fopen
#define _CRT_SECURE_NO_WARNINGS

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint8_t byte;
typedef uint32_t word;

typedef union uword {
    word word;
    byte bytes[4];
} uword;

static word s_box[256];
static word inverse_s_box[256];

static byte multiply(byte a, byte b) {
    byte res = 0;
    for (; b; b >>= 1) {
        if (b & 1) res ^= a;
        a = a << 1 ^ (a & 0x80 ? 0x1b : 0);
    }
    return res;
}

static byte inverse(byte b) {
    byte res = b;
    // b ^ -1 == b ^ 254. The following loop calculates b ^ 254 instead.
    for (unsigned i = 0; i < 13; ++i) {
        res = multiply(res, i & 1 ? b : res);
    }
    return res;
}

static byte SubByte(byte b) {
    typedef uint16_t dbyte;
    byte t = inverse(b);
    dbyte d = t << 8 ^ t;  // duplicate t for rotation
    return d ^ d >> 4 ^ d >> 5 ^ d >> 6 ^ d >> 7 ^ 0x63;
}

static void initialise_s_box(void) {
    for (size_t i = 0; i < 256; ++i) {
        s_box[i] = SubByte((byte)i);
    }
}

static void initialise_inverse_s_box(void) {
    for (size_t i = 0; i < 256; ++i) {
        inverse_s_box[SubByte((byte)i)] = (byte)i;
    }
}

static void print_Rcon(FILE *file) {
    fprintf(file, "const word Rcon[] = {\n");

    // i in Rcon[i] can be up to (Nb * (Nr + 1)) / Nk (exclusive).
    // For Nb = 8, Nk = 4, Nr = 14, that is up to 30 (exclusive).
    const unsigned MaxRcon = 30;
    byte RC = 0x01;

    fprintf(file, "    // Rcon[0] is included for indexing simplicity\n");
    fprintf(file, "    0x00000000,\n");

    for (unsigned i = 1; i < MaxRcon; ++i) {
        fprintf(file, "    0x000000%02x,\n", RC);
        RC = multiply(0x02, RC);
    }

    fprintf(file, "};\n");
}

static void print_s_box(FILE *file) {
    fprintf(file, "const word s_box[4][256] = {\n");

    const char *fmt[4] = {
        "0x000000%02x",
        "0x0000%02x00",
        "0x00%02x0000",
        "0x%02x000000",
    };

    for (unsigned i = 0; i < 4; ++i) {
        fprintf(file, "    {");
        for (unsigned j = 0; j < 256; ++j) {
            fprintf(file, fmt[i], s_box[j]);
            if (j != 255) fprintf(file, ", ");
        }
        fprintf(file, "},\n");
    }

    fprintf(file, "};\n");
}

static void print_inverse_s_box(FILE *file) {
    fprintf(file, "const word inverse_s_box[4][256] = {\n");

    const char *fmt[4] = {
        "0x000000%02x",
        "0x0000%02x00",
        "0x00%02x0000",
        "0x%02x000000",
    };

    for (unsigned i = 0; i < 4; ++i) {
        fprintf(file, "    {");
        for (unsigned j = 0; j < 256; ++j) {
            fprintf(file, fmt[i], inverse_s_box[j]);
            if (j != 255) fprintf(file, ", ");
        }
        fprintf(file, "},\n");
    }

    fprintf(file, "};\n");
}

static void print_cipher_table(FILE *file) {
    fprintf(file, "const word cipher_table[4][256] = {\n");

    byte t[4][256];
    const word m[4] = {0x03, 0x01, 0x01, 0x02};

    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned j = 0; j < 256; ++j) {
            t[i][j] = multiply(m[i % 4], j);
        }
    }
    for (unsigned i = 0; i < 4; ++i) {
        fprintf(file, "    {");
        for (unsigned j = 0; j < 256; ++j) {
            fprintf(file, "0x%02x%02x%02x%02x",
                    t[(i + 0) % 4][s_box[j]],
                    t[(i + 1) % 4][s_box[j]],
                    t[(i + 2) % 4][s_box[j]],
                    t[(i + 3) % 4][s_box[j]]);
            if (j != 255) fprintf(file, ", ");
        }
        fprintf(file, "},\n");
    }

    fprintf(file, "};\n");
}

static void print_inv_cipher_table(FILE *file) {
    fprintf(file, "const word inv_cipher_table[4][256] = {\n");

    byte t[4][256];
    const word m[4] = {0x0b, 0x0d, 0x09, 0x0e};

    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned j = 0; j < 256; ++j) {
            t[i][j] = multiply(m[i % 4], j);
        }
    }
    for (unsigned i = 0; i < 4; ++i) {
        fprintf(file, "    {");
        for (unsigned j = 0; j < 256; ++j) {
            fprintf(file, "0x%02x%02x%02x%02x",
                    t[(i + 0) % 4][inverse_s_box[j]],
                    t[(i + 1) % 4][inverse_s_box[j]],
                    t[(i + 2) % 4][inverse_s_box[j]],
                    t[(i + 3) % 4][inverse_s_box[j]]);
            if (j != 255) fprintf(file, ", ");
        }
        fprintf(file, "},\n");
    }

    fprintf(file, "};\n");
}

static void print_InvMixColumns_table(FILE *file) {
    fprintf(file, "const word InvMixColumns_table[4][256] = {\n");

    const word m[4] = {0x0b, 0x0d, 0x09, 0x0e};

    for (unsigned i = 0; i < 4; ++i) {
        fprintf(file, "    {");
        for (unsigned j = 0; j < 256; ++j) {
            fprintf(file, "0x%02x%02x%02x%02x",
                    multiply(m[(i + 0) % 4], j),
                    multiply(m[(i + 1) % 4], j),
                    multiply(m[(i + 2) % 4], j),
                    multiply(m[(i + 3) % 4], j));
            if (j != 255) fprintf(file, ", ");
        }
        fprintf(file, "},\n");
    }

    fprintf(file, "};\n");
}

int main() {
    FILE *file;
    if (!(file = fopen("data.c", "w"))) {
        fprintf(stderr, "Failed to open output file.\n");
        exit(EXIT_FAILURE);
    }

    initialise_s_box();
    initialise_inverse_s_box();

    fprintf(file, "// This file was generated by makedata.c.\n");
    fprintf(file, "\n");

    fprintf(file, "#include \"aes.h\"\n");
    fprintf(file, "\n");

    print_Rcon(file);
    fprintf(file, "\n");

    print_s_box(file);
    fprintf(file, "\n");

    print_inverse_s_box(file);
    fprintf(file, "\n");

    print_cipher_table(file);
    fprintf(file, "\n");

    print_inv_cipher_table(file);
    fprintf(file, "\n");

    print_InvMixColumns_table(file);

    fclose(file);

    return 0;
}
