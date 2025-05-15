.PHONY: all

all:
	clang -Wall -Wextra -I/usr/include/libnl3 -O2 -g main.c vhost.c tap.c -o vhost \
		$(shell pkg-config --cflags --libs libnl-3.0 libnl-route-3.0)
