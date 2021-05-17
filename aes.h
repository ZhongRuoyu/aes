#ifndef AES_H_
#define AES_H_

#include <stdint.h>  // for uintN_t

typedef uint8_t byte;
typedef uint16_t dbyte;
typedef uint32_t word;

typedef uint8_t bit;

/* bits.c begin */

byte *to_bytes(unsigned Nb, const word w[]);

/* end bits.c */

/* cipher.c begin */

byte *cipher(unsigned Nb, unsigned Nr, byte in[], word w[][4]);
void SubBytes(unsigned Nb, byte state[]);
void ShiftRows(unsigned Nb, byte state[]);
void MixColumns(unsigned Nb, byte state[]);
void AddRoundKey(unsigned Nb, byte state[], word w[]);

/* end cipher.c */

/* galois.c begin */

byte multiply(byte a, byte b);

/* end galois.c */

#endif  // AES_H_
