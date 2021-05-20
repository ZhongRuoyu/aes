#ifndef AES_H_
#define AES_H_

#include <stdint.h>

typedef uint8_t byte;
typedef uint32_t word;

typedef enum Mode {
    UNDEFINED,
    CIPHER,
    INVCIPHER,
} Mode;

/* main.c begin */

extern int verbose;

/* end main.c */

/* bytes.c begin */

byte *to_bytes(word w);
word to_word(byte b3, byte b2, byte b1, byte b0);
byte *to_bytes_array(unsigned Nb, const word w[]);
void transpose_block(unsigned Nb, byte block[]);
char *block_to_string(unsigned Nb, byte block[]);

/* end bytes.c */

/* cipher.c begin */

byte *Cipher(unsigned Nb, unsigned Nr, const byte in[], byte **w);
byte *InvCipher(unsigned Nb, unsigned Nr, const byte in[], byte **w);

/* end cipher.c */

/* data.c begin */

extern const word Rcon[];
extern const byte s_box[256];
extern const byte inverse_s_box[256];
extern const byte MixColumns_table[4][256];
extern const byte InvMixColumns_table[4][256];

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

word *KeyExpansion(unsigned Nb, unsigned Nr, const word key[], unsigned Nk);
byte **wrap_key(unsigned Nb, unsigned Nr, const word w[], unsigned Nk);

/* end key.c */

#endif  // AES_H_
