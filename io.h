#ifndef IO_H_
#define IO_H_

#include "aes.h"

void error(const char *msg, const char *from);

void print_multiline(const char *str, char delimiter);
void print_block(unsigned Nb, const word block[]);

#endif  // IO_H_
