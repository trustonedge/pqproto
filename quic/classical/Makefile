CC = gcc
OPENSSL_DIR = /usr/local
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -I$(OPENSSL_DIR)/include
LDFLAGS = -L$(OPENSSL_DIR)/lib64 -lssl -lcrypto

TARGETS = server client

.PHONY: all clean

all: $(TARGETS)

server: server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

client: client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)