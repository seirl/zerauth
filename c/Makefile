# CC = mips-openwrt-linux-gcc
CFLAGS =-Wall -Wextra -std=c99
NAME = zerauth

.PHONY: clean

include config.mk

ifdef USERNAME
	CFLAGS+=-DUSERNAME=\"$(USERNAME)\"
endif

ifdef PASSWORD
	CFLAGS+=-DPASSWORD=\"$(PASSWORD)\"
endif

ifdef DOMAIN
	CFLAGS+=-DDOMAIN=\"$(DOMAIN)\"
endif

ifdef PORT
	CFLAGS+=-DPORT=$(PORT)
endif

ifdef RENEW_DELAY
	CFLAGS+=-DRENEW_DELAY=$(RENEW_DELAY)
endif

ifdef TIMEOUT
	CFLAGS+=-DTIMEOUT=$(TIMEOUT)
endif

$(NAME): zerauth.c config.mk
	$(CC) $(CFLAGS) -o $(NAME) $(NAME).c

clean:
	rm -f $(NAME)
