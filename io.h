#ifndef IO_H_
#define IO_H_

#include "aes.h"

void error(const char *msg);

void print_multiline(char *str, char delimiter);
void print_block(unsigned Nb, const byte block[]);

#endif  // IO_H_
