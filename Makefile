CC = gcc
TARGET=libfinet.so

LIBPURPLE_CFLAGS = `pkg-config --cflags purple` -DPURPLE_PLUGINS -DENABLE_NLS -DHAVE_ZLIB
CFLAGS += `pkg-config --cflags osxcart` $(LIBPURPLE_CFLAGS) -Wall -I. -g -O2 -pipe
LDFLAGS += `pkg-config --libs osxcart`

# default is installation in home without pixmaps
PREFIX ?= ~
ifeq ($(PREFIX),~)
	LIBDIR ?=$(PREFIX)/.purple/plugins
	INSTALL = $(LIBDIR)/$(TARGET)
else
	LIBDIR ?=$(PREFIX)/lib/purple-2
	PIXMAPDIR ?= $(PREFIX)/share
	INSTALL = $(LIBDIR)/$(TARGET) $(PIXMAPDIR)/pixmaps
endif

FINET_SOURCES = \
	finet.c \
	finet.h

all:	${TARGET}

.PHONY: clean install uninstall

clean:
	rm -f ${TARGET}

install: $(INSTALL)
uninstall:
	rm -f $(INSTALL)

# pattern rule to install executables
$(LIBDIR)/%: ./%
	-[ -e '$(@D)' ] || mkdir -p '$(@D)'
	cp -f '$<' '$@'

# pattern rule to install pixmaps
$(PIXMAPDIR)/%: ./%
	-[ -e '$(@D)' ] || mkdir -p '$(@D)'
	cp -rf '$<' '$@'

${TARGET}: ${FINET_SOURCES}
	${CC} ${CFLAGS} ${LDFLAGS} ${FINET_SOURCES} -o ${TARGET} -shared -fPIC -DPIC

