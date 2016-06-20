CC = gcc

check_protype = $(shell echo '$1' | \
                        ${CC} -E - | \
                         grep -q '\<$1\>' && echo '-DHAVE_$1=1')

CFLAGS = -g -O2 -pipe -fPIC\
    -Wall -Wextra -Wundef \
    -Winline -Wshadow -Wconversion \
    -Wno-trigraphs -Wmissing-include-dirs \
    -Wmissing-field-initializers \
    -Wswitch-default -Wswitch-enum \
    -Wformat-security -Wfloat-equal \
    -Wcast-qual -Wcast-align -Wpacked \
    -Wpointer-arith -Wstack-protector \
    -Wunsafe-loop-optimizations \
    -fno-strict-aliasing -fno-common \
    -fdelete-null-pointer-checks \
    $(call check_protype,FascistCheckUser,'\#include <crack.h>')

LDFLAGS = -fvisibility=hidden -Wl,-as-needed

KRB5_CFLAGS = $(shell krb5-config --cflags krb5)
KRB5_LIBS = $(shell krb5-config --libs krb5)

LDFLAGS_cracklib.so = -fPIC -shared -Wl,-soname=pwqual-cracklib.so

LIBS_cracklib.so = \
  $(KRB5_LIBS)

all: cracklib.so pwqual-cracklib

clean:
	@rm -f cracklib.so pwqual-cracklib

pwqual-cracklib: pwqual-cracklib.c
	$(CC) -D__MAIN__ ${CFLAGS} ${LDFLAGS} $^ -o $@ $(LIBS_$@) -lcrack

cracklib.so: pwqual-cracklib.c
	$(CC) ${CFLAGS} ${LDFLAGS} ${LDFLAGS_$@} $^ -o $@ $(LIBS_$@) -lcrack
