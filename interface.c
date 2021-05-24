// disables deprecation warning for fopen
#define _CRT_SECURE_NO_WARNINGS

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "io.h"

static inline unsigned get_Nr(unsigned Nb, unsigned Nk);

static char *cipher_hex_interface(unsigned Nb, unsigned Nk, unsigned Nr, word **key, word in[]);
static char *inv_cipher_hex_interface(unsigned Nb, unsigned Nk, unsigned Nr, word **key, word in[]);

static word **hex_string_to_expanded_key(unsigned Nb, unsigned Nr, const char *key, unsigned Nk);
static word **hex_string_to_expanded_inv_key(unsigned Nb, unsigned Nr, const char *key, unsigned Nk);

// ISO/IEC 9797-1, padding method 2
static int get_block_padding_position(unsigned Nb, const byte block[]);

static word *hex_string_to_block(unsigned Nb, const char *str);
static char *block_to_string(unsigned Nb, const word block[]);

char *cipher_hex(unsigned Nb, unsigned Nk, const char *key, const char *in) {
    unsigned Nr = get_Nr(Nb, Nk);

    char *in_processed = process_hex_string(in);
    if (strlen(in_processed) != 8 * Nb) {
        free(in_processed);
        error("Incorrect input length.", NULL);
    }
    word *in_block = hex_string_to_block(Nb, in_processed);
    free(in_processed);

    word **key_processed = hex_string_to_expanded_key(Nb, Nr, key, Nk);

    char *out = cipher_hex_interface(Nb, Nk, Nr, key_processed, in_block);

    free(in_block);
    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);

    return out;
}

char *inv_cipher_hex(unsigned Nb, unsigned Nk, const char *key, const char *in) {
    unsigned Nr = get_Nr(Nb, Nk);

    char *in_processed = process_hex_string(in);
    if (strlen(in_processed) != 8 * Nb) {
        free(in_processed);
        error("Incorrect input length.", NULL);
    }
    word *in_block = hex_string_to_block(Nb, in_processed);
    free(in_processed);

    word **key_processed = hex_string_to_expanded_inv_key(Nb, Nr, key, Nk);

    char *out = inv_cipher_hex_interface(Nb, Nk, Nr, key_processed, in_block);

    free(in_block);
    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);

    return out;
}

void cipher_file(unsigned Nb, unsigned Nk, const char *key, const char *in_dir, const char *out_dir) {
    unsigned Nr = get_Nr(Nb, Nk);

    FILE *in_file, *out_file;
    if (!(in_file = fopen(in_dir, "rb"))) {
        error(": Failed to open input file.", in_dir);
    }
    fseek(in_file, 0, SEEK_END);
    long file_size = (ftell(in_file) / (4 * Nb) + 1) * (4 * Nb);
    rewind(in_file);
    if (!(out_file = fopen(out_dir, "wb"))) {
        fclose(in_file);
        error(": Failed to open output file.", out_dir);
    }

    word **key_processed = hex_string_to_expanded_key(Nb, Nr, key, Nk);

    {
        {
            word *in_buffer = (word *)malloc(Nb * sizeof(word));
            size_t words_read = 0;

            while (4 * (words_read + Nb) < file_size) {
                words_read += fread(in_buffer, sizeof(word), Nb, in_file);
                word *out_buffer = Cipher(Nb, Nr, in_buffer, key_processed);
                fwrite(out_buffer, sizeof(word), Nb, out_file);
                free(out_buffer);
            }

            free(in_buffer);
        }

        {
            byte *in_buffer = (byte *)malloc(4 * Nb * sizeof(byte));
            size_t bytes_read = fread(in_buffer, sizeof(byte), 4 * Nb, in_file);

            in_buffer[bytes_read] = 0x80;
            for (size_t i = bytes_read + 1; i < 4 * Nb; ++i) {
                in_buffer[i] = 0x00;
            }

            word *out_buffer = Cipher(Nb, Nr, (word *)in_buffer, key_processed);
            fwrite(out_buffer, sizeof(word), Nb, out_file);

            free(in_buffer);
            free(out_buffer);
        }
    }

    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);

    fclose(in_file);
    fclose(out_file);
}

void inv_cipher_file(unsigned Nb, unsigned Nk, const char *key, const char *in_dir, const char *out_dir) {
    unsigned Nr = get_Nr(Nb, Nk);

    FILE *in_file, *out_file;
    if (!(in_file = fopen(in_dir, "rb"))) {
        error(": Failed to open input file.", in_dir);
    }
    fseek(in_file, 0, SEEK_END);
    long file_size = ftell(in_file);
    rewind(in_file);
    if (file_size == 0 || file_size % (4 * Nb)) {
        fclose(in_file);
        error(": Incorrect input file. Is it empty or modified?", in_dir);
    }
    if (!(out_file = fopen(out_dir, "wb"))) {
        fclose(in_file);
        error(": Failed to open output file.", out_dir);
    }

    word **key_processed = hex_string_to_expanded_inv_key(Nb, Nr, key, Nk);

    {
        {
            word *in_buffer = (word *)malloc(Nb * sizeof(word));
            size_t words_read = 0;

            while (4 * (words_read + Nb) < file_size) {
                words_read += fread(in_buffer, sizeof(word), Nb, in_file);
                word *out_buffer = InvCipher(Nb, Nr, in_buffer, key_processed);
                fwrite(out_buffer, sizeof(word), Nb, out_file);
                free(out_buffer);
            }

            free(in_buffer);
        }

        {
            word *in_buffer = (word *)malloc(Nb * sizeof(word));
            fread(in_buffer, sizeof(word), Nb, in_file);
            word *out_buffer = InvCipher(Nb, Nr, in_buffer, key_processed);

            int pos = get_block_padding_position(Nb, (byte *)out_buffer);
            if (pos < 0) {
                free(in_buffer);
                free(out_buffer);
                for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
                free(key_processed);
                fclose(in_file);
                fclose(out_file);
                remove(out_dir);
                error(": Could not correctly interpret input.", in_dir);
            }

            fwrite(out_buffer, sizeof(byte), pos, out_file);

            free(in_buffer);
            free(out_buffer);
        }
    }

    for (unsigned i = 0; i <= Nr; ++i) free(key_processed[i]);
    free(key_processed);

    fclose(in_file);
    fclose(out_file);
}

char *process_hex_string(const char *str) {
    const size_t str_len = strlen(str);
    char *new_str = (char *)malloc((str_len + 1) * sizeof(char));
    size_t n = 0;
    for (size_t i = 0; i < str_len; ++i) {
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

static inline unsigned get_Nr(unsigned Nb, unsigned Nk) {
    if (Nb == 4) {
        switch (Nk) {
            case 4:
                return 10;
            case 6:
                return 12;
            case 8:
                return 14;
        }
    } else if (Nb == 6) {
        switch (Nk) {
            case 4:
            case 6:
                return 12;
            case 8:
                return 14;
        }
    } else if (Nb == 8) {
        switch (Nk) {
            case 4:
            case 6:
            case 8:
                return 14;
        }
    }
    return 0;
}

static char *cipher_hex_interface(unsigned Nb, unsigned Nk, unsigned Nr, word **key, word in[]) {
    change_endianness(Nb, in);
    word *out_bytes = Cipher(Nb, Nr, in, key);
    change_endianness(Nb, out_bytes);
    char *out = block_to_string(Nb, out_bytes);
    free(out_bytes);
    return out;
}

static char *inv_cipher_hex_interface(unsigned Nb, unsigned Nk, unsigned Nr, word **key, word in[]) {
    change_endianness(Nb, in);
    word *out_bytes = InvCipher(Nb, Nr, in, key);
    change_endianness(Nb, out_bytes);
    char *out = block_to_string(Nb, out_bytes);
    free(out_bytes);
    return out;
}

static word **hex_string_to_expanded_key(unsigned Nb, unsigned Nr, const char *key_str, unsigned Nk) {
    word *key = (word *)malloc(Nk * sizeof(word *));
    for (unsigned i = 0; i < Nk; ++i) {
        char buffer[9];
        memcpy(buffer, key_str + i * 8, 8 * sizeof(char));
        buffer[8] = '\0';
        key[i] = strtoul(buffer, NULL, 16);
    }
    change_endianness(Nb, key);
    word **key_expanded = KeyExpansion(Nb, Nr, key, Nk);
    free(key);
    return key_expanded;
}

static word **hex_string_to_expanded_inv_key(unsigned Nb, unsigned Nr, const char *key_str, unsigned Nk) {
    word **key_expanded = hex_string_to_expanded_key(Nb, Nr, key_str, Nk);
    for (unsigned round = 1; round < Nr; ++round) {
        for (unsigned j = 0; j < Nb; ++j) {
            const uword w = {key_expanded[round][j]};
            key_expanded[round][j] =
                InvMixColumns_table[0][w.bytes[0]] ^
                InvMixColumns_table[1][w.bytes[1]] ^
                InvMixColumns_table[2][w.bytes[2]] ^
                InvMixColumns_table[3][w.bytes[3]];
        }
    }
    return key_expanded;
}

static int get_block_padding_position(unsigned Nb, const byte block[]) {
    for (signed i = 4 * Nb - 1; i >= 0; --i) {
        if (block[i] != 0x00) {
            if (block[i] != 0x80) return -1;
            return i;
        }
    }
    return -1;
}

static word *hex_string_to_block(unsigned Nb, const char *str) {
    word *block = (word *)malloc(Nb * sizeof(word));
    for (unsigned j = 0; j < Nb; ++j) {
        char buffer[9];
        memcpy(buffer, str + j * 8, 8 * sizeof(char));
        buffer[8] = '\0';
        block[j] = strtoul(buffer, NULL, 16);
    }
    return block;
}

static char *block_to_string(unsigned Nb, const word block[]) {
    char *str = (char *)malloc((8 * Nb + 1) * sizeof(char));
    for (unsigned j = 0; j < Nb; ++j) {
        snprintf(str + j * 8, 9, "%08x", block[j]);
    }
    // the terminating null character is handled by the last snprintf() call
    return str;
}
