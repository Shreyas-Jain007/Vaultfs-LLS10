CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -D_FILE_OFFSET_BITS=64
CPPFLAGS := -Iinclude -Isrc
LDLIBS  := -lcrypto

ENGINE  := src/crypto.o src/util.o src/vault.o
FUSEOBJ := src/fuse_lowlevel.o

all: vaultfs

# vault.o #includes vault_ops.c, so add it as a dependency
src/vault.o: src/vault.c src/vault_ops.c include/vaultfs.h src/crypto.h src/util.h

vaultfs: $(ENGINE) src/cli.o $(FUSEOBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# unit test binary for crypto + engine
test_engine: $(ENGINE) tests/test_engine.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

check: vaultfs test_engine
	./test_engine
	bash tests/run_tests.sh

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f src/*.o tests/*.o vaultfs test_engine

.PHONY: all check clean
