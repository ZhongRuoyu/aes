#include "interface.h"

#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "interface.h"
#include "strings.h"

char *cipher_hex(unsigned Nk, const char *key, const char *in) {
    unsigned Nb = get_Nb(Nk), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    char *in_processed = process_hex_string(in);
    if (strlen(in_processed) != 32) {
        for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
        free(key_processed);
        error("Incorrect input length.");
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
    unsigned Nb = get_Nb(Nk), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    char *in_processed = process_hex_string(in);
    if (strlen(in_processed) != 32) {
        for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
        free(key_processed);
        error("Incorrect input length.");
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

char *cipher_hex_multiline(unsigned Nk, const char *key, const char *in) {
    unsigned Nb = get_Nb(Nk), Nr = get_Nr(Nk);
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

char *inv_cipher_hex_multiline(unsigned Nk, const char *key, const char *in) {
    unsigned Nb = get_Nb(Nk), Nr = get_Nr(Nk);
    word **key_processed = process_key(Nb, Nr, key, Nk);

    char *in_processed = process_hex_string(in);
    const unsigned n = strlen(in_processed);
    if (n % 32) {
        for (unsigned i = 0; i < Nr + 1; ++i) free(key_processed[i]);
        free(key_processed);
        error("Incorrect input length.");
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
        error("Could not correctly interpret input.");
    }

    return out;
}
