CC       ?= cc
CFLAGS   ?= -O2
CFLAGS   += -Wall -Wextra -std=gnu11
CPPFLAGS ?=
LDFLAGS  ?=
LDLIBS   ?=

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

all: ueventfw

ueventfw: ueventfw.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

install: ueventfw
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 ueventfw "$(DESTDIR)$(BINDIR)/ueventfw"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/ueventfw"

clean:
	rm -f ueventfw

.PHONY: all clean install uninstall
