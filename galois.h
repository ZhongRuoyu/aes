#ifndef GALOIS_H_
#define GALOIS_H_

#include "aes.h"

static byte multiply(byte a, byte b) {
    byte res = 0;
    for (; b; b >>= 1) {
        if (b & 1) res ^= a;
        a = a << 1 ^ (a & 0x80 ? 0x1b : 0);
    }
    return res;
}

#endif  // GALOIS_H_
