CC = gcc
PKG_CONFIG_PATH = /usr/local/lib64/pkgconfig
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags openssl)
LDFLAGS = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs openssl)

TARGETS = server client

.PHONY: all clean

all: $(TARGETS)

server: server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

client: client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)