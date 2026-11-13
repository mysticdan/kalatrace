.DEFAULT_GOAL := all

CC := clang
CPPFLAGS += -I../../userspace/include
CFLAGS ?= -std=gnu23 -Wall -Wextra -Wpedantic -O0 -g3
LDLIBS += -lsqlite3

TARGET := test_close_storage
SRCS := test_close_storage.c \
	../../userspace/storage/sqlite_init.c \
	../../userspace/storage/sqlite_close.c
HEADERS := ../../userspace/include/storage.h

.PHONY: all test clean

all: test

test: $(TARGET)
	./$(TARGET)

$(TARGET): $(SRCS) $(HEADERS) Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRCS) $(LDFLAGS) $(LDLIBS) -o $@

clean:
	$(RM) $(TARGET)
