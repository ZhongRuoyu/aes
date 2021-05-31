# AES

`AES` is an implementation of the [Advanced Encryption Standard (AES)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in C, in accordance with the [Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) published in 2001 and the [AES submission document on Rijndael](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf) originally published in 1999.

`AES` supports encryption and decryption of single-block (128-bit) hexadecimal strings and files. In terms of byte padding for file encryption/decryption, `AES` uses the padding method 2 from [ISO/IEC 9797-1](https://en.wikipedia.org/wiki/ISO/IEC_9797-1).

For file encryption/decryption, `AES`, as a single-threaded and instruction-set independent implementation, offers a considerable speed without sacrificing portability and future flexibility.

All the "flavours" of the algorithm, i.e. AES-128, AES-192, and AES-256, are supported. `AES` determines the exact algorithm by the length of the key provided.

## To Build

### Building with GNU Make

`AES` can be easily built with GNU Make, using the following commands.

```bash
$ sudo apt install build-essential clang git
$ git clone https://github.com/ZhongRuoyu/AES.git
$ cd aes
$ make
```

With the last `make` command, an executable named `aes` would be created in the working directory.

### Building Manually

If you are running on a platform where `make` is not well supported (e.g. Windows), you may build `AES` manually with `clang` or `gcc`.

To build, `git clone` this repository, or download a zipped archive. Open a terminal in the root directory of the repository, and build the executable by including all the source files in the [/src](/src) directory, with include path [/include](/include). For instance, using `clang` on Windows with PowerShell:

```powershell
clang src/*.c -I include -std=c11 -O2 -o aes.exe
```

The source file [/src/data.c](/src/data.c) may be generated with [/data/makedata.c](/data/makedata.c):

```powershell
clang data/makedata.c -I include -std=c11 -O2 -o makedata.exe
./makedata.exe src/data.c
```

## To Use

Run `aes --help` to view the detailed help message on using `AES`.

For example, running the following...

```bash
$ aes -e -s "3243f6a8 885a308d 313198a2 e0370734" -k "2b7e1516 28aed2a6 abf71588 09cf4f3c"
```

... gives the following output:

```bash
3925841d02dc09fbdc118597196a0b32
```

You may need to include the path to the executable `aes` as well.

## Licence

Copyright (c) 2021 Zhong Ruoyu.

This repository is licensed under the MIT License. See [LICENSE](/LICENSE) for more information.
