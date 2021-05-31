CC          = clang
CFLAGS      = -I include -std=c11

OBJ         = src/bytes.o src/cipher.o src/data.o \
              src/interface.o src/io.o src/key.o \
              src/main.o
DATA_SRC    = data/makedata.c
DATA        = src/data.c

DEBUG ?= 0
ifeq ($(DEBUG), 0)
    CFLAGS += -O2
else
    CFLAGS += -O0
endif

# to disable auto cleanup, comment out the following rule, or run `make aes`
all: aes clean

aes: $(OBJ)
	$(CC) $(OBJ) $(CFLAGS) -o $@

$(DATA): $(DATA_SRC)
	$(eval TEMPDIR := $(shell mktemp -d))
	$(CC) $(DATA_SRC) $(CFLAGS) -o $(TEMPDIR)/makedata
	$(TEMPDIR)/makedata $@
	rm -r $(TEMPDIR)

clean:
	$(RM) src/*.o

.PHONY: clean
