
#################################################################
#  Makefile for eJet Web Server library - eJet
#  Copyright (c) 2003-2021 Ke Hengzhong <kehengzhong@hotmail.com>
#  All rights reserved. See MIT LICENSE for redistribution.
#################################################################

PKGNAME = ejet
PKGLIB = lib$(PKGNAME)
PKG_SO_LIB = $(PKGLIB).so
PKG_A_LIB = $(PKGLIB).a
PKG_A_LIB = $(PKGLIB).a
PKG_BIN = $(PKGNAME)srv

PREFIX = /usr/local
INSTALL_INC_PATH = $(DESTDIR)$(PREFIX)/include
INSTALL_LIB_PATH = $(DESTDIR)$(PREFIX)/lib

ROOT := .
PKGPATH := $(shell basename `/bin/pwd`)

adif_inc = $(PREFIX)/include/adif
adif_lib = $(PREFIX)/lib

epump_inc = $(PREFIX)/include
epump_lib = $(PREFIX)/lib

ejet_inc = $(ROOT)/include
ejet_src = $(ROOT)/src

ejetsrv_inc = $(ROOT)/ejetsrv
ejetsrv_src = $(ROOT)/ejetsrv

inc = $(ROOT)/include
obj = $(ROOT)/obj
libdst = $(ROOT)/lib
bindst = $(ROOT)/bin

alib = $(libdst)/$(PKG_A_LIB)
solib = $(libdst)/$(PKG_SO_LIB)
bin = $(bindst)/$(PKG_BIN)

ADIF_RPATH = -Wl,-rpath,$(adif_lib)
EPUMP_RPATH = -Wl,-rpath,$(epump_lib)
PKG_RPATH = -Wl,-rpath,$(libdst):$(INSTALL_LIB_PATH)

#################################################################
#  Customization of shared object library (SO)

PKG_VER_MAJOR = 1
PKG_VER_MINOR = 2
PKG_VER_RELEASE = 8
PKG_VER = $(PKG_VER_MAJOR).$(PKG_VER_MINOR).$(PKG_VER_RELEASE)

PKG_VERSO_LIB = $(PKG_SO_LIB).$(PKG_VER)
PKG_SONAME_LIB = $(PKG_SO_LIB).$(PKG_VER_MAJOR)
LD_SONAME = -Wl,-soname,$(PKG_SONAME_LIB)


#################################################################
#  Customization of the implicit rules

CC = gcc

IFLAGS = -I$(adif_inc) -I$(epump_inc) -I$(ejet_inc)

#CFLAGS = -Wall -O3 -fPIC -std=c99
CFLAGS = -Wall -O3 -fPIC
LFLAGS = -L/usr/lib -L/usr/local/lib -L$(libdst)
LIBS = -lnsl -lm -lz -lpthread
SOFLAGS = $(LD_SONAME)

APPLIBS = -ladif -lepump -l$(PKGNAME) $(PKG_RPATH)


ifeq ($(MAKECMDGOALS), debug)
  DEFS += -D_DEBUG
  CFLAGS += -g
endif

ifeq ($(MAKECMDGOALS), so)
  CFLAGS += 
endif


#################################################################
# Macro definition check

ifeq ($(shell test -e /usr/include/sys/epoll.h && echo 1), 1)
  DEFS += -DHAVE_EPOLL
else ifeq ($(shell test -e /usr/include/sys/event.h && echo 1), 1)
  DEFS += -DHAVE_KQUEUE
else
  DEFS += -DHAVE_SELECT
endif

ifeq ($(shell test -e /usr/include/sys/eventfd.h && echo 1), 1)
  DEFS += -DHAVE_EVENTFD
endif

ifeq ($(shell test -e /usr/include/openssl/ssl.h && echo 1), 1)
  DEFS += -DHAVE_OPENSSL
  LIBS += -lssl -lcrypto
endif


#################################################################
# Set long and pointer to 64 bits or 32 bits

ifeq ($(BITS),)
  CFLAGS += -m64
else ifeq ($(BITS),64)
  CFLAGS += -m64
else ifeq ($(BITS),32)
  CFLAGS += -m32
else ifeq ($(BITS),default)
  CFLAGS += 
else
  CFLAGS += $(BITS)
endif


#################################################################
# OS-specific definitions and flags

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
  DEFS += -DUNIX -D_LINUX_
endif

ifeq ($(UNAME), FreeBSD)
  DEFS += -DUNIX -D_FREEBSD_
  LIBS += -liconv
endif

ifeq ($(UNAME), Darwin)
  DEFS += -D_OSX_

  PKG_VERSO_LIB = $(PKGLIB).$(PKG_VER).dylib
  PKG_SONAME_LIB = $(PKGLIB).$(PKG_VER_MAJOR).dylib
  LD_SONAME=

  SOFLAGS += -install_name $(libdst)/$(PKGLIB).dylib
  SOFLAGS += -compatibility_version $(PKG_VER_MAJOR)
  SOFLAGS += -current_version $(PKG_VER)
endif

ifeq ($(UNAME), Solaris)
  DEFS += -DUNIX -D_SOLARIS_
endif
 

#################################################################
# Merge the rules

CFLAGS += $(DEFS)
LIBS += $(APPLIBS)
 

#################################################################
#  Customization of the implicit rules - BRAIN DAMAGED makes (HP)

AR = ar
ARFLAGS = rv
RANLIB = ranlib
RM = /bin/rm -f
COMPILE.c = $(CC) $(CFLAGS) $(IFLAGS) -c
LINK = $(CC) $(CFLAGS) $(IFLAGS) $(LFLAGS) -Wl,-E -o
SOLINK = $(CC) $(CFLAGS) $(IFLAGS) $(LFLAGS) -shared $(SOFLAGS) -o

#################################################################
#  Modules

ejet_incs = $(wildcard $(ejet_inc)/*.h)
ejet_sources = $(wildcard $(ejet_src)/*.c)
ejet_objs = $(patsubst $(ejet_src)/%.c,$(obj)/%.o,$(ejet_sources))

ejetsrv_incs = $(wildcard $(ejetsrv_inc)/*.h)
ejetsrv_sources = $(wildcard $(ejetsrv_src)/*.c)
ejetsrv_objs = $(patsubst $(ejetsrv_src)/%.c,$(obj)/%.o,$(ejetsrv_sources))


#################################################################
#  Standard Rules

.PHONY: all clean debug show

all: $(alib) $(solib) $(bin)
so: $(solib)
debug: $(alib) $(solib)
clean: 
	$(RM) $(ejet_objs)
	$(RM) -r $(obj)
	$(RM) $(ejetsrv_objs)
	@cd $(libdst) && $(RM) $(PKG_A_LIB)
	@cd $(libdst) && $(RM) $(PKG_SO_LIB)
	@cd $(libdst) && $(RM) $(PKG_SONAME_LIB)
	@cd $(libdst) && $(RM) $(PKG_VERSO_LIB)
show:
	@echo $(alib)
	@echo $(solib)
	@echo $(bin)

dist: $(ejet_incs) $(ejet_sources)
	cd $(ROOT)/.. && tar czvf $(PKGNAME)-$(PKG_VER).tar.gz $(PKGPATH)/src \
	    $(PKGPATH)/include $(PKGPATH)/lib $(PKGPATH)/Makefile $(PKGPATH)/README.md \
	    $(PKGPATH)/LICENSE $(PKGPATH)/ejetsrv $(PKGPATH)/bin

install: $(alib) $(solib)
	mkdir -p $(INSTALL_INC_PATH) $(INSTALL_LIB_PATH)
	install -s $(libdst)/$(PKG_A_LIB) $(INSTALL_LIB_PATH)
	cp -af $(libdst)/$(PKG_VERSO_LIB) $(INSTALL_LIB_PATH)
	@cd $(INSTALL_LIB_PATH) && $(RM) $(PKG_SONAME_LIB) && ln -sf $(PKG_VERSO_LIB) $(PKG_SONAME_LIB)
	@cd $(INSTALL_LIB_PATH) && $(RM) $(PKG_SO_LIB) && ln -sf $(PKG_SONAME_LIB) $(PKG_SO_LIB)
	cp -af $(inc)/ejet.h $(INSTALL_INC_PATH)

uninstall:
	cd $(INSTALL_LIB_PATH) && $(RM) $(PKG_SO_LIB)
	cd $(INSTALL_LIB_PATH) && $(RM) $(PKG_SONAME_LIB) 
	cd $(INSTALL_LIB_PATH) && $(RM) $(PKG_VERSO_LIB) 
	cd $(INSTALL_LIB_PATH) && $(RM) $(PKG_A_LIB) 
	$(RM) $(INSTALL_INC_PATH)/ejet.h

#################################################################
#  Additional Rules
#
#  target1 [target2 ...]:[:][dependent1 ...][;commands][#...]
#  [(tab) commands][#...]
#
#  $@ - variable, indicates the target
#  $? - all dependent files
#  $^ - all dependent files and remove the duplicate file
#  $< - the first dependent file
#  @echo - print the info to console
#
#  SOURCES = $(wildcard *.c *.cpp)
#  OBJS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCES)))
#  CSRC = $(filter %.c,$(files))


$(solib): $(ejet_objs) 
	@mkdir -p $(libdst)
	$(SOLINK) $(libdst)/$(PKG_VERSO_LIB) $? 
	@cd $(libdst) && $(RM) $(PKG_SONAME_LIB) && ln -s $(PKG_VERSO_LIB) $(PKG_SONAME_LIB)
	@cd $(libdst) && $(RM) $(PKG_SO_LIB) && ln -s $(PKG_SONAME_LIB) $(PKG_SO_LIB)
     
$(alib): $(ejet_objs) 
	@mkdir -p $(libdst)
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $(RANLIBFLAGS) $@

$(obj)/%.o: $(ejet_src)/%.c $(ejet_incs)
	@mkdir -p $(obj)
	$(COMPILE.c) $< -o $@

$(obj)/%.o: $(ejetsrv_src)/%.c $(ejetsrv_incs)
	@mkdir -p $(obj)
	$(COMPILE.c) $< -o $@

$(bin): $(ejetsrv_objs)
	@mkdir -p $(bindst)
	$(LINK) $@ $? $(LIBS)

