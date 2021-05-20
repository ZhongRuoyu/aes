// disables deprecation warning for fopen and strncpy
#define _CRT_SECURE_NO_WARNINGS

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "io.h"
#include "strings.h"

static inline unsigned get_Nb();
static inline unsigned get_Nr(unsigned Nk);

static char *cipher_hex_interface(unsigned Nb, unsigned Nk, unsigned Nr, word **key, byte **in, unsigned block_count);
static char *inv_cipher_hex_interface(unsigned Nb, unsigned Nk, unsigned Nr, word **key, byte **in, unsigned block_count);

static word **process_key(unsigned Nb, unsigned Nr, const char *key, unsigned Nk);

// ISO/IEC 9797-1, padding method 2
static char *string_bit_padding(char *str);
static int remove_string_bit_padding(char *str);
static int get_block_bit_padding_position(unsigned Nb, byte block[]);

static word *hex_string_to_key(unsigned Nk, const char *str);
static byte *hex_string_to_block(const char *str);
static byte **hex_string_to_blocks(char *str, unsigned block_count);

char *cipher_hex(unsigned Nk, const char *key, const char *in) {
    unsigned Nb = get_Nb(), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    char *in_processed = process_hex_string(in);
    if (strlen(in_processed) != 32) {
        free(in_processed);
        for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
        free(key_processed);
        error("Incorrect input length.", NULL);
    }
    byte **in_blocks = hex_string_to_blocks(in_processed, 1);
    free(in_processed);

    char *out = cipher_hex_interface(Nb, Nk, Nr, key_processed, in_blocks, 1);

    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);
    free(in_blocks[0]);
    free(in_blocks);

    return out;
}

char *inv_cipher_hex(unsigned Nk, const char *key, const char *in) {
    unsigned Nb = get_Nb(), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    char *in_processed = process_hex_string(in);
    if (strlen(in_processed) != 32) {
        free(in_processed);
        for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
        free(key_processed);
        error("Incorrect input length.", NULL);
    }
    byte **in_blocks = hex_string_to_blocks(in_processed, 1);
    free(in_processed);

    char *out = inv_cipher_hex_interface(Nb, Nk, Nr, key_processed, in_blocks, 1);

    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);
    free(in_blocks[0]);
    free(in_blocks);

    return out;
}

char *cipher_hex_multiblock(unsigned Nk, const char *key, const char *in) {
    unsigned Nb = get_Nb(), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    char *in_processed = process_hex_string(in);
    char *in_padded = string_bit_padding(in_processed);  // in_processed is reallocated
    const unsigned block_count = strlen(in_padded) / 32;
    byte **in_blocks = hex_string_to_blocks(in_padded, block_count);
    free(in_padded);

    char *out = cipher_hex_interface(Nb, Nk, Nr, key_processed, in_blocks, block_count);

    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);
    for (unsigned i = 0; i < block_count; ++i) free(in_blocks[i]);
    free(in_blocks);

    return out;
}

char *inv_cipher_hex_multiblock(unsigned Nk, const char *key, const char *in) {
    unsigned Nb = get_Nb(), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    char *in_processed = process_hex_string(in);
    const unsigned n = strlen(in_processed);
    if (n % 32) {
        free(in_processed);
        for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
        free(key_processed);
        error("Incorrect input length.", NULL);
    }
    const unsigned block_count = n / 32;
    byte **in_blocks = hex_string_to_blocks(in_processed, block_count);
    free(in_processed);

    char *out = inv_cipher_hex_interface(Nb, Nk, Nr, key_processed, in_blocks, block_count);

    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);
    for (unsigned i = 0; i < block_count; ++i) free(in_blocks[i]);
    free(in_blocks);

    if (remove_string_bit_padding(out)) {
        free(out);
        error("Could not correctly interpret input.", NULL);
    }

    return out;
}

void cipher_file(unsigned Nk, const char *key, const char *in_dir, const char *out_dir) {
    unsigned Nb = get_Nb(), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    FILE *in_file, *out_file;
    if (!(in_file = fopen(in_dir, "rb"))) {
        error(": Failed to open input file.", in_dir);
    }
    if (!(out_file = fopen(out_dir, "wb"))) {
        fclose(in_file);
        error(": Failed to open output file.", out_dir);
    }

    byte *buffer = (byte *)malloc(4 * Nb * sizeof(byte));
    unsigned bytes_read;
    while ((bytes_read = fread(buffer, sizeof(byte), 4 * Nb, in_file)) == 4 * Nb) {
        transpose_block(Nb, buffer);
        byte *out_buffer = Cipher(Nb, Nr, buffer, key_processed);
        fwrite(out_buffer, sizeof(byte), 4 * Nb, out_file);
        free(out_buffer);
    }

    if (bytes_read == 4 * Nb) {
        memset(buffer, 0x00, 4 * Nb * sizeof(byte));
        buffer[0] = 0x80;
    } else {
        buffer[bytes_read] = 0x80;
        for (unsigned i = bytes_read + 1; i < 4 * Nb; ++i) {
            buffer[i] = 0x00;
        }
    }
    transpose_block(Nb, buffer);
    byte *out_buffer = Cipher(Nb, Nr, buffer, key_processed);
    fwrite(out_buffer, sizeof(byte), 4 * Nb, out_file);
    free(out_buffer);

    free(buffer);
    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);

    fclose(in_file);
    fclose(out_file);
}

void inv_cipher_file(unsigned Nk, const char *key, const char *in_dir, const char *out_dir) {
    unsigned Nb = get_Nb(), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    FILE *in_file, *out_file;
    if (!(in_file = fopen(in_dir, "rb"))) {
        error(": Failed to open input file.", in_dir);
    }
    if (!(out_file = fopen(out_dir, "wb"))) {
        fclose(in_file);
        error(": Failed to open output file.", out_dir);
    }

    fseek(in_file, 0, SEEK_END);
    unsigned file_size = ftell(in_file);
    rewind(in_file);

    if (file_size == 0 || file_size % (4 * Nb)) {
        for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
        free(key_processed);
        fclose(in_file);
        fclose(out_file);
        remove(out_dir);
        error(": Incorrect input file. Is it empty or modified?", in_dir);
    }

    byte *buffer = (byte *)malloc(4 * Nb * sizeof(byte));
    for (unsigned bytes_read = 0; (bytes_read + 4 * Nb) < file_size;) {
        bytes_read += fread(buffer, sizeof(byte), 4 * Nb, in_file);
        transpose_block(Nb, buffer);
        byte *out_buffer = InvCipher(Nb, Nr, buffer, key_processed);
        fwrite(out_buffer, sizeof(byte), 4 * Nb, out_file);
        free(out_buffer);
    }
    fread(buffer, sizeof(byte), 4 * Nb, in_file);
    transpose_block(Nb, buffer);
    byte *out_buffer = InvCipher(Nb, Nr, buffer, key_processed);

    int pos = get_block_bit_padding_position(Nb, out_buffer);
    if (pos < 0) {
        free(buffer);
        free(out_buffer);
        for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
        free(key_processed);
        fclose(in_file);
        fclose(out_file);
        remove(out_dir);
        error(": Could not correctly interpret input.", in_dir);
    }
    fwrite(out_buffer, sizeof(byte), pos, out_file);
    free(out_buffer);

    free(buffer);
    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);

    fclose(in_file);
    fclose(out_file);
}

char *process_hex_string(const char *str) {
    const int str_len = strlen(str);
    char *new_str = (char *)malloc((str_len + 1) * sizeof(char));
    unsigned n = 0;
    for (unsigned i = 0; i < str_len; ++i) {
        if (isspace(str[i])) continue;
        if (!isxdigit(str[i])) {
            free(new_str);
            error("Input contains invalid hexadecimal digit.", NULL);
        }
        new_str[n++] = str[i];
    }
    new_str[n] = '\0';
    return new_str;
}

static inline unsigned get_Nb() {
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
        char *out_str = block_to_string(Nb, out_bytes);
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
        char *out_str = block_to_string(Nb, out_bytes);
        free(out_bytes);
        string_copy(out + i * 32, out_str, 32);
        free(out_str);
    }
    out[block_count * 32] = '\0';
    return out;
}

static word **process_key(unsigned Nb, unsigned Nr, const char *key, unsigned Nk) {
    word *key_words = hex_string_to_key(Nk, key);
    word *key_expanded = KeyExpansion(Nb, Nr, key_words, Nk);
    free(key_words);
    word **key_processed = wrap_key(Nb, Nr, key_expanded, Nk);
    free(key_expanded);
    return key_processed;
}

static char *string_bit_padding(char *str) {
    const unsigned n = strlen(str);
    unsigned padded_length = ((n / 32) + 1) * 32;
    char *new_str = (char *)realloc(str, (padded_length + 1) * sizeof(char));
    new_str[n] = '8';  // 0b10000000
    for (unsigned i = n + 1; i < padded_length; ++i) new_str[i] = '0';
    new_str[padded_length] = '\0';
    return new_str;
}

static int remove_string_bit_padding(char *str) {
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

static int get_block_bit_padding_position(unsigned Nb, byte block[]) {
    for (signed i = 4 * Nb - 1; i >= 0; --i) {
        if (block[i] != 0x00) {
            if (block[i] != 0x80) return -1;
            return i;
        }
    }
    return -1;
}

static word *hex_string_to_key(unsigned Nk, const char *str) {
    word *key = (word *)malloc(Nk * sizeof(word *));
    for (unsigned i = 0; i < Nk; ++i) {
        char buffer[9];
        strncpy(buffer, str + i * 8, 8);
        buffer[8] = '\0';
        key[i] = strtoul(buffer, NULL, 16);
    }
    return key;
}

static byte *hex_string_to_block(const char *str) {
    byte *block = (byte *)malloc(16 * sizeof(byte));
    for (unsigned j = 0; j < 4; ++j) {
        for (unsigned i = 0; i < 4; ++i) {
            char buffer[3];
            strncpy(buffer, str + j * 8 + i * 2, 2);
            buffer[2] = '\0';
            block[i * 4 + j] = strtoul(buffer, NULL, 16);
        }
    }
    return block;
}

static byte **hex_string_to_blocks(char *str, unsigned block_count) {
    byte **blocks = (byte **)malloc(block_count * sizeof(byte *));
    for (unsigned curr_block = 0; curr_block < block_count; ++curr_block) {
        char buffer[33];
        strncpy(buffer, str + curr_block * 32, 32);
        buffer[32] = '\0';
        blocks[curr_block] = hex_string_to_block(buffer);
    }
    return blocks;
}
