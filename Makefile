GCC = gcc
LIBPURPLE_CFLAGS = `pkg-config --cflags purple` -DPURPLE_PLUGINS -DENABLE_NLS -DHAVE_ZLIB

CFLAGS = ${LIBPURPLE_CFLAGS} -Wall -I. -g -O2 -pipe

FINET_SOURCES = \
	finet.c \
	finet.h

all:	finet.so

clean:
	rm finet.so


finet.so: ${FINET_SOURCES}
	${GCC} ${CFLAGS} ${FINET_SOURCES} -o finet.so -shared -fPIC -DPIC
