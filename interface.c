// disables deprecation warning for fopen and strncpy
#define _CRT_SECURE_NO_WARNINGS

#include "interface.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "io.h"
#include "interface.h"
#include "strings.h"

char *cipher_hex(unsigned Nk, const char *key, const char *in) {
    unsigned Nb = get_Nb(), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    char *in_processed = process_hex_string(in);
    if (strlen(in_processed) != 32) {
        for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
        free(key_processed);
        error("Incorrect input length.", NULL);
    }
    byte **in_blocks = hex_string_to_blocks(in_processed, 1);
    free(in_processed);

    char *out = cipher_hex_interface(Nb, Nk, Nr, key_processed, in_blocks, 1);

    for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
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
        for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
        free(key_processed);
        error("Incorrect input length.", NULL);
    }
    byte **in_blocks = hex_string_to_blocks(in_processed, 1);
    free(in_processed);

    char *out = inv_cipher_hex_interface(Nb, Nk, Nr, key_processed, in_blocks, 1);

    for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
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

    for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
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
        for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
        free(key_processed);
        error("Incorrect input length.", NULL);
    }
    const unsigned block_count = n / 32;
    byte **in_blocks = hex_string_to_blocks(in_processed, block_count);
    free(in_processed);

    char *out = inv_cipher_hex_interface(Nb, Nk, Nr, key_processed, in_blocks, block_count);

    for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
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
    for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
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
        for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
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
        for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
        free(key_processed);
        fclose(in_file);
        fclose(out_file);
        remove(out_dir);
        error(": Could not correctly interpret input.", in_dir);
    }
    fwrite(out_buffer, sizeof(byte), pos, out_file);
    free(out_buffer);

    free(buffer);
    for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
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
