// disables deprecation warning for fopen
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aes.h"
#include "io.h"

int verbose = 0;
int time_display = 0;

typedef enum InputMode {
    INPUT_UNDEFINED,
    SINGLE_BLOCK_INPUT,
    MULTI_BLOCK_INPUT,
    FILE_INPUT,
} InputMode;

typedef enum KeyMode {
    KEY_UNDEFINED,
    KEY_STRING,
    KEY_FILE,
} KeyMode;

static const char *get_basename(const char *path) {
    const char *basename = strrchr(path, '/');
    if (basename) return basename + 1;
    basename = strrchr(path, '\\');
    if (basename) return basename + 1;
    return path;
}

static const char *read_from_key_file(const char *filename);

void usage(const char *basename) {
    fprintf(stderr,
            "Usage:\n"
            "    %s {-e|-d} [-v] [-t] { (-s|-m) <hex-string> | -f <in> <out> } { -k <key> | -kfile <file> }\n"
            "    %s {-h|--help}\n"
            "\n"
            "Options:\n"
            "          -e    Encryption (Cipher) mode: encrypts information with the AES \n"
            "                    algorithm.\n"
            "          -d    Decryption (Inverse Cipher) mode: decrypts information with \n"
            "                    the AES algorithm.\n"
            "          -v    Verbose output: enables display of cipher procedure. \n"
            "                    Deprecation warning: verbose output is no longer \n"
            "                    supported. The option -v will be removed in the next \n"
            "                    release.\n"
            "          -t    Time display: displays time elapsed when finished.\n"
            "          -s    Single-block mode: encrypts the single-block hexadecimal \n"
            "                    string. <hex-string> must be a valid 128-bit hexadecimal \n"
            "                    string.\n"
            "          -m    Multi-block mode: encrypts the hexadecimal string with no \n"
            "                    length limit. <hex-string> must be a valid hexadecimal \n"
            "                    string.\n"
            "          -f    File mode: encrypts the given file. <in> must be a valid path \n"
            "                    to an existing file with read access. <out> must be a \n"
            "                    valid path to a file with write access. If the output file \n"
            "                    already exists, it is overwritten; otherwise, it is \n"
            "                    created.\n"
            "          -k    Key provided as an argument. <key> must be a valid hexadecimal \n"
            "                    string. The length of the key should be 128, 192, or 256 \n"
            "                    bits. The AES algorithm is automatically deduced from the \n"
            "                    key length.\n"
            "      -kfile    Key provided as a file. <file> must be a valid path to the key \n"
            "                    file, which contains a valid hexadecimal string. The \n"
            "                    length of the key should be 128, 192, or 256 bits. The AES \n"
            "                    algorithm is automatically deduced from the key length.\n"
            "  -h, --help    Display this help message.\n"
            "\n",
            basename, basename);
    exit(EXIT_FAILURE);
}

int main(int argc, const char **argv) {
    clock_t begin = clock();

    const char *basename = get_basename(argv[0]);

    if (argc == 1) usage(basename);

    Mode mode = UNDEFINED;
    InputMode input_mode = INPUT_UNDEFINED;
    KeyMode key_mode = KEY_UNDEFINED;
    const char *in_str = NULL;
    const char *in_dir = NULL;
    const char *out_dir = NULL;
    const char *key_dir = NULL;
    const char *key = NULL;

    for (unsigned i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-e") == 0) {
            if (mode != UNDEFINED) error("Only one cipher mode can be specified.", NULL);
            mode = CIPHER;
        } else if (strcmp(argv[i], "-d") == 0) {
            if (mode != UNDEFINED) error("Only one cipher mode can be specified.", NULL);
            mode = INVCIPHER;
        } else if (strcmp(argv[i], "-v") == 0) {
            if (verbose != 0) error("-v can only be specified once.", NULL);
            verbose = 1;
            fprintf(stderr,
                    "Deprecation warning: verbose output is no longer supported. The option -v will \n"
                    "be removed in the next release.\n"
                    "\n");
        } else if (strcmp(argv[i], "-t") == 0) {
            if (time_display != 0) error("-t can only be specified once.", NULL);
            time_display = 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            if (input_mode != INPUT_UNDEFINED) error("Only one input mode can be specified.", NULL);
            input_mode = SINGLE_BLOCK_INPUT;
            if (++i == argc) error("No input string.", NULL);
            in_str = argv[i];
        } else if (strcmp(argv[i], "-m") == 0) {
            if (input_mode != INPUT_UNDEFINED) error("Only one input mode can be specified.", NULL);
            input_mode = MULTI_BLOCK_INPUT;
            if (++i == argc) error("No input string.", NULL);
            in_str = argv[i];
        } else if (strcmp(argv[i], "-f") == 0) {
            if (input_mode != INPUT_UNDEFINED) error("Only one input mode can be specified.", NULL);
            input_mode = FILE_INPUT;
            if (++i == argc) error("No input file.", NULL);
            in_dir = argv[i];
            if (++i == argc) error("No output file.", NULL);
            out_dir = argv[i];
        } else if (strcmp(argv[i], "-k") == 0) {
            if (key_mode != KEY_UNDEFINED) error("Only one key mode can be specified.", NULL);
            key_mode = KEY_STRING;
            if (++i == argc) error("No key string.", NULL);
            key = argv[i];
        } else if (strcmp(argv[i], "-kfile") == 0) {
            if (key_mode != KEY_UNDEFINED) error("Only one key mode can be specified.", NULL);
            key_mode = KEY_FILE;
            if (++i == argc) error("No key file.", NULL);
            key_dir = argv[i];
        } else if (strcmp(argv[i], "-h") == 0) {
            usage(basename);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(basename);
        } else {
            error("Invalid argument.", NULL);
        }
    }

    if (mode == UNDEFINED) error("The cipher mode is not specified.", NULL);
    if (input_mode == INPUT_UNDEFINED) error("The input mode is not specified.", NULL);
    if (key_mode == KEY_UNDEFINED) error("The key mode is not specified.", NULL);

    if (key_mode == KEY_FILE) {
        key = read_from_key_file(key_dir);
    }
    char *key_processed = process_hex_string(key);
    if (key_mode == KEY_FILE) free((void *)key);
    unsigned Nk;
    switch (strlen(key_processed)) {
        case 32: {
            Nk = 4;
            break;
        }
        case 48: {
            Nk = 6;
            break;
        }
        case 64: {
            Nk = 8;
            break;
        }
        default: {
            free(key_processed);
            error("Incorrect key length.", NULL);
        }
    }

    char *out = NULL;
    switch (input_mode) {
        case SINGLE_BLOCK_INPUT: {
            out = (mode == CIPHER ? cipher_hex : inv_cipher_hex)(Nk, key_processed, in_str);
            print_multiline(out, '\n');
            free(out);
            break;
        }
        case MULTI_BLOCK_INPUT: {
            out = (mode == CIPHER ? cipher_hex_multiblock : inv_cipher_hex_multiblock)(Nk, key_processed, in_str);
            print_multiline(out, '\n');
            free(out);
            break;
        }
        case FILE_INPUT: {
            (mode == CIPHER ? cipher_file : inv_cipher_file)(Nk, key_processed, in_dir, out_dir);
            break;
        }
        case INPUT_UNDEFINED: {
            break;
        }
    }

    free(key_processed);

    clock_t end = clock();
    if (time_display) {
        printf("Time elapsed: %.3fs.\n\n", (double)(end - begin) / CLOCKS_PER_SEC);
    }

    return 0;
}

static const char *read_from_key_file(const char *filename) {
    FILE *file;

    if (!(file = fopen(filename, "r"))) {
        error(": Failed to open key file.", filename);
    }

    fseek(file, 0, SEEK_END);
    unsigned file_size = ftell(file);
    rewind(file);

    char *out = (char *)malloc((file_size + 1) * sizeof(char));
    unsigned end = fread(out, sizeof(char), file_size, file);
    out[end] = '\0';

    fclose(file);

    return out;
}
