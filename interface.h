#ifndef INTERFACE_H_
#define INTERFACE_H_

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "key.h"
#include "strings.h"

static void error(const char *msg);

static inline unsigned get_Nb(unsigned Nk);
static inline unsigned get_Nr(unsigned Nk);

static char *cipher_hex_interface(unsigned Nb, unsigned Nk, unsigned Nr, word **key, byte **in, unsigned block_count);

static word **process_key(unsigned Nb, unsigned Nr, const char *key, unsigned Nk);

static char *process_hex_string(const char *str);
static char *string_bit_padding(char *str);
int remove_string_bit_padding(char *str);

static word *hex_string_to_key(unsigned Nk, const char *str);
static byte *hex_string_to_block(const char *str);
static byte **hex_string_to_blocks(char *str, unsigned block_count);

static char *state_to_string(unsigned Nb, byte *block);

static void error(const char *msg) {
    fprintf(stderr, "Error: %s\n\n", msg);
    exit(EXIT_FAILURE);
}

static inline unsigned get_Nb(unsigned Nk) {
    return 4;
}

static inline unsigned get_Nr(unsigned Nk) {
    switch (Nk) {
        case 4:
            return 10;
        case 6:
            return 12;
        case 8:
            return 14;
    }
    return 0;
}

static char *cipher_hex_interface(unsigned Nb, unsigned Nk, unsigned Nr, word **key, byte **in, unsigned block_count) {
    char *out = (char *)malloc((block_count * 32 + 1) * sizeof(char));
    for (unsigned i = 0; i < block_count; ++i) {
        byte *out_bytes = Cipher(Nb, Nr, in[i], key);
        char *out_str = state_to_string(Nb, out_bytes);
        free(out_bytes);
        string_copy(out + i * 32, out_str, 32);
        free(out_str);
    }
    out[block_count * 32] = '\0';
    return out;
}

static char *inv_cipher_hex_interface(unsigned Nb, unsigned Nk, unsigned Nr, word **key, byte **in, unsigned block_count) {
    char *out = (char *)malloc((block_count * 32 + 1) * sizeof(char));
    for (unsigned i = 0; i < block_count; ++i) {
        byte *out_bytes = InvCipher(Nb, Nr, in[i], key);
        char *out_str = state_to_string(Nb, out_bytes);
        free(out_bytes);
        string_copy(out + i * 32, out_str, 32);
        free(out_str);
    }
    out[block_count * 32] = '\0';
    return out;
}

static word **process_key(unsigned Nb, unsigned Nr, const char *key, unsigned Nk) {
    char *key_hex = process_hex_string(key);
    if (strlen(key_hex) != Nk * 8) {
        free(key_hex);
        error("Incorrect key length.");
    }
    word *key_words = hex_string_to_key(Nk, key_hex);
    free(key_hex);
    word *key_expanded = KeyExpansion(Nb, Nr, key_words, Nk);
    free(key_words);
    word **key_processed = wrap_key(Nb, Nr, key_expanded, Nk);
    free(key_expanded);
    return key_processed;
}

static char *process_hex_string(const char *str) {
    const int str_len = strlen(str);
    char *new_str = (char *)malloc((str_len + 1) * sizeof(char));
    unsigned n = 0;
    for (unsigned i = 0; i < str_len; ++i) {
        if (isspace(str[i])) continue;
        if (!isxdigit(str[i])) {
            free(new_str);
            error("Input contains invalid hexadecimal digit.");
        }
        new_str[n++] = str[i];
    }
    new_str[n] = '\0';
    return new_str;
}

// ISO/IEC 9797-1, padding method 2
static char *string_bit_padding(char *str) {
    const unsigned n = strlen(str);
    unsigned padded_length = ((n / 32) + 1) * 32;
    char *new_str = (char *)realloc(str, (padded_length + 1) * sizeof(char));
    new_str[n] = '8';  // 0b10000000
    for (unsigned i = n + 1; i < padded_length; ++i) new_str[i] = '0';
    new_str[padded_length] = '\0';
    return new_str;
}

// ISO/IEC 9797-1, padding method 2
int remove_string_bit_padding(char *str) {
    const unsigned n = strlen(str);
    for (signed i = n - 1; i >= 0; --i) {
        if (str[i] != '0') {
            if (str[i] != '8') return 1;
            str[i] = '\0';
            return 0;
        }
    }
    return 1;
}

static word *hex_string_to_key(unsigned Nk, const char *str) {
    word *key = (word *)malloc(Nk * sizeof(word *));
    for (unsigned i = 0; i < Nk; ++i) {
        char buffer[9];
        strncpy_s(buffer, 9, str + i * 8, 8);
        key[i] = strtoul(buffer, NULL, 16);
    }
    return key;
}

static byte *hex_string_to_block(const char *str) {
    byte *block = (byte *)malloc(16 * sizeof(byte));
    for (unsigned j = 0; j < 4; ++j) {
        for (unsigned i = 0; i < 4; ++i) {
            char buffer[3];
            strncpy_s(buffer, 3, str + j * 8 + i * 2, 2);
            block[i * 4 + j] = strtoul(buffer, NULL, 16);
        }
    }
    return block;
}

static byte **hex_string_to_blocks(char *str, unsigned block_count) {
    byte **blocks = (byte **)malloc(block_count * sizeof(byte *));
    for (unsigned curr_block = 0; curr_block < block_count; ++curr_block) {
        char buffer[33];
        strncpy_s(buffer, 33, str + curr_block * 32, 32);
        blocks[curr_block] = hex_string_to_block(buffer);
    }
    return blocks;
}

static char *state_to_string(unsigned Nb, byte *block) {
    char *str = (char *)malloc((8 * Nb + 1) * sizeof(char));
    for (unsigned j = 0; j < Nb; ++j) {
        for (unsigned i = 0; i < 4; ++i) {
            char buffer[3];
            sprintf_s(buffer, 3, "%2x", block[i * Nb + j]);
            if (isspace(buffer[0])) buffer[0] = '0';
            string_copy(str + j * 8 + i * 2, buffer, 2);
        }
    }
    str[8 * Nb] = '\0';
    return str;
}

#endif  // INTERFACE_H_
