# Makefile for PPPD_LDAP plugin
#

# Uncomment this line to get more debug messages
#DEBUG=y
# Uncomment this line to enable SSL/TLS 
TLS=y
#

DESTDIR = $(INSTROOT)/usr/local
LIBDIR  = $(DESTDIR)/lib/pppd/$(VERSION)
BINDIR  = $(DESTDIR)/bin

VERSION = $(shell awk -F '"' '/VERSION/ { print $$2; }' ../../patchlevel.h)

INSTALL ?= install

PLUGIN := pppd_ldap.so
TOOLS  := ppp_list

INCLUDE := -I. -I../.. -I../../../include
CFLAGS  = -O2 $(INCLUDE) -fPIC
LDFLAGS += -lldap -lc

# Uncomment this line if you don't want to include MS-CHAP and MS-CHAP-V2 supprot
CHAPMS=y

# Uncomment this line if you don't want MPPE support
MPPE=y

ifdef CHAPMS
CFLAGS += -DCHAPMS=1
endif

ifdef MPPE
CFLAGS += -DMPPE=1
endif

all : $(PLUGIN) $(TOOLS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

ppp_list: utmplib.o
	$(CC) $(CFLAGS) ppp_list.c -o ppp_list utmplib.o $(LDFLAGS)

pppd_ldap.so: main.o utmplib.o ldap_utils.o chap_verifiers.o
	$(CC) -shared -o $@ $^ $(LDFLAGS)

install: all
	$(INSTALL) -d -m 755 $(LIBDIR)
	$(INSTALL) -c -m 6440 $(PLUGIN) $(LIBDIR)/pppd/
	$(INSTALL) -d -m 755 $(BINDIR)
	$(INSTALL) -c -m 755 $(TOOLS) $(BINDIR)

clean :
	rm $(PLUGIN) $(TOOLS) *.o *.so *~
