CC = gcc
CFLAGS = -O2 -Wall -Wextra -s

mihomo-watchdog: watchdog.c
	$(CC) $(CFLAGS) -o $@ $<

test: test_watchdog.c watchdog.c
	$(CC) -O2 -Wall -Wextra -o test_watchdog test_watchdog.c
	./test_watchdog

clean:
	rm -f mihomo-watchdog test_watchdog

.PHONY: test clean
