#
# Very simple Makefile for building 'extract-sig-list'
#
# define BUILD_DEBUG if you want to get a debug build (else: release, stripped)
# define BUILD_STATIC if you want to get a statically linked excutable (else: required OpenSSL libcrypto.so at runtime)
# define BIG_ENDIAN if your machine has a Big Endian CPU
# define OPENSSL_INC to specify a specific OpenSSL include folder
# define OPENSSL_LIB to specify an alternative library search dir
#

EXECFILE=extract-sig-list

BUILD_DEBUG ?= 0
BUILD_STATIC ?= 0
BIG_ENDIAN ?= 0

ifeq ($(BUILD_DEBUG),0)
CFLAGS = -O3 -fomit-frame-pointer -DNDEBUG
else
CFLAGS = -O0 -g3 -ggdb -D_DEBUG
endif

CFLAGS += -Wall -Werror -Wextra -pedantic -Wno-format-truncation -fPIC -D_LINUX -D__USE_GNU -I.

ifeq ($(BIG_ENDIAN),1)
CFLAGS += -D_BIG_ENDIAN_HOST
endif

ifneq ($(OPENSSL_INC),)
CFLAGS += -I$(OPENSSL_INC)
endif

LDFLAGS = -lcrypto

ifeq ($(BUILD_STATIC),1)
LDFLAGS += -static
endif

ifneq ($(OPENSSL_LIB),)
LDFLAGS += -L$(OPENSSL_LIB)
endif

SOURCE_FILES = main.c uefi.c

OBJECT_FILES = $(patsubst %.c,%.o,$(SOURCE_FILES))

all: $(EXECFILE)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

$(EXECFILE): main.o uefi.o
	$(CC) -o $@ $^ $(LDFLAGS)
ifeq ($(BUILD_DEBUG),0)
	strip $@
endif

install:
	install -v -d /usr/local/bin
	install -v -m 0755 $(EXECFILE) /usr/local/bin

clean:
	rm -f *.o $(EXECFILE) core

.PHONY: all clean install
