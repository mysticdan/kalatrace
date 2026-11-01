CC = gcc

TARGET = kalatracectl

CFLAGS = -Iinclude -Wall -Wextra -Werror -std=c11 -O2 -g

LDLIBS = -lcjson

SRCS = \
	cli/kalatracectl.c \

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean