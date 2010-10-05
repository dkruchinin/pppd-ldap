# Makefile for PPPD_LDAP plugin
#

# Uncomment this line to get more debug messages
#DEBUG=y
# Uncomment this line to enable SSL/TLS 
TLS=y
#

PPP_DIR := src/ppp

#
PLUGIN=pppd_ldap.so
TOOLS=ppp_list
DESTINATION=/usr/lib/ppp/
CC=gcc
LD=ld
INCLUDE := -I$(PPP_PATH)/pppd -I$(PPP_PATH)/include
CFLAGS  := -O2 -fPIC $(INCLUDE)
LDFLAGS=-lldap -lc
#

ifdef DEBUG
CFLAGS += -DDEBUG=1
endif
ifdef TLS
CFLAGS += -DOPT_WITH_TLS=1
endif

all : $(PLUGIN) $(TOOLS)

ppp_list: utmplib.o
	$(CC) $(CFLAGS) ppp_list.c -o ppp_list utmplib.o $(LDFLAGS)

pppd_ldap.so: main.o utmplib.o
	$(LD) -shared -o pppd_ldap.so utmplib.o main.o $(LDFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c -o main.o main.c

utmplib.o: utmplib.c
	$(CC) $(CFLAGS) -c -o utmplib.o utmplib.c

clean :
	rm $(PLUGIN) $(TOOLS) *.o *.so *~

