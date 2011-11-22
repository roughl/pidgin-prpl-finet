GCC = gcc
LIBPURPLE_CFLAGS = `pkg-config --libs --cflags osxcart` `pkg-config --cflags purple` -DPURPLE_PLUGINS -DENABLE_NLS -DHAVE_ZLIB

CFLAGS = ${LIBPURPLE_CFLAGS} -Wall -I. -g -O2 -pipe

BIN=libfinet.so

FINET_SOURCES = \
	finet.c \
	finet.h

all:	${BIN}

install:	finet.so
	mkdir -p ~/.purple/plugins
	cp ${BIN} ~/.purple/plugins/

clean:
	rm ${BIN}


${BIN}: ${FINET_SOURCES}
	${GCC} ${CFLAGS} ${FINET_SOURCES} -o ${BIN} -shared -fPIC -DPIC
