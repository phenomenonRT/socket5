CC = gcc
CFLAGS ?= -O2 -Wall -Wextra
LDLIBS ?= -lnetfilter_queue

TARGET = socks5-winclamp
SRC = socks5-winclamp.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LDLIBS) -o $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all install clean
