CC := clang
CFLAGS := -Wall -Werror -Wextra -fPIC
LDFLAGS := -shared
TARGET := orbit.so

SRC := src/orBit.c src/libc-read.c src/libc-write.c src/orBit-tools.c src/libc-pam-start.c
OBJ := $(SRC:.c=.o)
HEADER := include/

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c $(HEADER)
	$(CC) $(CFLAGS) -I$(HEADER) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
