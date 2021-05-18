#ifndef AES_H_
#define AES_H_

#include <stdint.h>

typedef uint8_t byte;
typedef uint16_t dbyte;
typedef uint32_t word;

typedef uint8_t bit;

/* bits.c begin */

byte *to_bytes(word w);
word to_word(byte b3, byte b2, byte b1, byte b0);
byte *to_bytes_array(unsigned Nb, const word w[]);

/* end bits.c */

/* cipher.c begin */

byte *Cipher(unsigned Nb, unsigned Nr, const byte in[], word **w);
byte *InvCipher(unsigned Nb, unsigned Nr, const byte in[], word **w);
void SubBytes(unsigned Nb, byte state[]);
void InvSubBytes(unsigned Nb, byte state[]);
void ShiftRows(unsigned Nb, byte state[]);
void InvShiftRows(unsigned Nb, byte state[]);
void MixColumns(unsigned Nb, byte state[]);
void InvMixColumns(unsigned Nb, byte state[]);
void AddRoundKey(unsigned Nb, byte state[], const word w[]);

/* end cipher.c */

/* galois.c begin */

byte multiply(byte a, byte b);

/* end galois.c */

/* interface.c begin */

char *cipher_hex(unsigned Nk, const char *key, const char *in);
char *inv_cipher_hex(unsigned Nk, const char *key, const char *in);
char *cipher_hex_multiline(unsigned Nk, const char *key, const char *in);
char *inv_cipher_hex_multiline(unsigned Nk, const char *key, const char *in);

/* end interface.c */

/* key.c begin */

word *KeyExpansion(unsigned Nb, unsigned Nr, const word key[], unsigned Nk);
word SubWord(word w);
word RotWord(word w);
word **wrap_key(unsigned Nb, unsigned Nr, const word *w, unsigned Nk);

/* end key.c */

#endif  // AES_H_
