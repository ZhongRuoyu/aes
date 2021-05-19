# AES

`AES` is an implementation of the [Advanced Encryption Standard (AES)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in C, in accordance with the [Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) published in 2001.

## To Use

Run `aes --help` to view the detailed help message.

For example, running the following...

```
./aes -e -s "3243f6a8 885a308d 313198a2 e0370734" -k "2b7e1516 28aed2a6 abf71588 09cf4f3c"
```

... gives the following output:

```
3925841d02dc09fbdc118597196a0b32
```

## To Build

To build `AES`, include all the `*.c` files in the root directory. For instance, with `clang` on Ubuntu:

```
clang *.c -o aes
``` 

## Licence

Copyright (c) 2021 Zhong Ruoyu.

Licensed under the MIT license.

For more information, see [`LICENSE`](/LICENSE).
