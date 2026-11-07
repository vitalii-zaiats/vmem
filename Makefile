CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -std=c11
CPPFLAGS ?= -Iinclude

CORE := $(wildcard src/core/*.c)

.PHONY: all test test-core test-python clean

all: test

test: test-core test-python

test-core: tests/c/test_core
	./tests/c/test_core

tests/c/test_core: tests/c/test_core.c $(CORE) include/vmem/vmem.h include/vmem/vmem_windows.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tests/c/test_core.c $(CORE)

test-python:
	uv run pytest -q

clean:
	rm -f tests/c/test_core
	rm -rf .pytest_cache build
