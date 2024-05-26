CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

TARGETS = sign_message verify_message

SRCS = sign_message.c verify_message.c

OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGETS)

sign_message: sign_message.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

verify_message: verify_message.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGETS) $(OBJS)
