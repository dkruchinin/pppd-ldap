# Makefile for PPPD_LDAP plugin
#

# Uncomment this line to get more debug messages
#DEBUG=y
# Uncomment this line to enable SSL/TLS 
TLS=y
#

CC      ?= gcc
LD      ?= ld
MAKE    ?= make
INSTALL ?= install

DESTDIR ?= /usr/local
INCDIR  := $(DESTDIR)/include
LIBDIR  := $(DESTDIR)/lib
BINDIR  := $(DESTDIR)/bin

PLUGIN := pppd_ldap.so
TOOLS  := ppp_list

INCLUDE := -I$(INCDIR)/pppd
CFLAGS  += -O2 $(INCLUDE) -fPIC
LDFLAGS += -lldap -lc


ifdef DEBUG
CFLAGS += -DDEBUG=1
endif

ifdef TLS
CFLAGS += -DOPT_WITH_TLS=1
endif

ifdef CHAPMS
CFLAGS += -DCHAPMS
endif

define get_pppd_version
	$(shell grep VERSION $(INCDIR)/pppd/patchlevel.h | sed 's|.\([0-9.]*\)|\1|g')
endef

all : $(PLUGIN) $(TOOLS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

ppp_list: utmplib.o
	$(CC) $(CFLAGS) ppp_list.c -o ppp_list utmplib.o $(LDFLAGS)

pppd_ldap.so: main.o utmplib.o ldap_utils.o chap_verifiers.o
	$(CC) -shared -o $@ $^ $(LDFLAGS)

install: all
	$(eval PPPD_VERSION := $(call get_pppd_version))
	$(INSTALL) -d -m 755 $(LIBDIR)/pppd/$(PPPD_VERSION)
	$(INSTALL) -c -m 6440 $(PLUGIN) $(LIBDIR)/pppd/$(PPPD_VERSION)
	$(INSTALL) -d -m 755 $(BINDIR)
	$(INSTALL) -c -m 755 $(TOOLS) $(BINDIR)

clean :
	rm $(PLUGIN) $(TOOLS) *.o *.so *~
