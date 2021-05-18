#ifndef STRING_H_
#define STRING_H_

static inline void string_copy(char *dest, const char *src, unsigned count) {
    while ((*(dest++) = *(src++)) && count--) continue;
}

#endif  // STRING_H_
