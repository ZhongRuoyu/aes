#ifndef AES_H_
#define AES_H_

#include <stdint.h>

typedef uint8_t byte;
typedef uint32_t word;

typedef union uword {
    word word;
    byte bytes[4];
} uword;

typedef enum Mode {
    UNDEFINED,
    CIPHER,
    INVCIPHER,
} Mode;

/* main.c begin */

extern int verbose;
extern int time_display;

/* end main.c */

/* bytes.c begin */

void change_endianness(unsigned Nb, word block[]);
char *block_to_string(unsigned Nb, word block[]);

/* end bytes.c */

/* cipher.c begin */

word *Cipher(unsigned Nb, unsigned Nr, const word in[], word **w);
word *InvCipher(unsigned Nb, unsigned Nr, const word in[], word **w);

/* end cipher.c */

/* data.c begin */

extern const word Rcon[];
extern const word s_box[4][256];
extern const word inverse_s_box[4][256];
extern const word cipher_table[4][256];
extern const word inv_cipher_table[4][256];
extern const word InvMixColumns_table[4][256];

/* end data.c */

/* interface.c begin */

char *cipher_hex(unsigned Nk, const char *key, const char *in);
char *inv_cipher_hex(unsigned Nk, const char *key, const char *in);

char *cipher_hex_multiblock(unsigned Nk, const char *key, const char *in);
char *inv_cipher_hex_multiblock(unsigned Nk, const char *key, const char *in);

void cipher_file(unsigned Nk, const char *key, const char *in_dir, const char *out_dir);
void inv_cipher_file(unsigned Nk, const char *key, const char *in_dir, const char *out_dir);

char *process_hex_string(const char *str);

/* end interface.c */

/* key.c begin */

word **KeyExpansion(unsigned Nb, unsigned Nr, const word key[], unsigned Nk);

/* end key.c */

#endif  // AES_H_
