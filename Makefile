CC = gcc
CFLAGS = -O2 -Wall -Wextra -s

mihomo-watchdog: watchdog.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f mihomo-watchdog
