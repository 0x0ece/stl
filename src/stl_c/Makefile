MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-builtin-variables
.SUFFIXES:
.SECONDARY:
.SECONDEXPANSION:

CC:=cc
CPPFLAGS:=-Werror -Wall -Wextra -Wpedantic \
  -Wstrict-aliasing=2 \
  -Wconversion -Wdouble-promotion \
  -isystem ../../opt/include
CFLAGS:=-std=c17 \
  -g \
  -O3 -march=native -mtune=native \
  -fomit-frame-pointer -fsanitize=address

LD:=cc
LDFLAGS:=-L../../opt/lib -lsodium -pthread -lrt -fsanitize=address

OBJS:=$(patsubst %.c,%.o,$(wildcard *.c))

.PHONY: build
build: stl_test

.PHONY: libs
libs:
	$(MAKE) -C ../../opt

stl_test: $(OBJS) | libs
	$(CC) $(CPPFLAGS) $^ $(LDFLAGS) -o $@

%.o: %.c $(wildcard *.h)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf *.o
	$(MAKE) -C ../../opt clean
