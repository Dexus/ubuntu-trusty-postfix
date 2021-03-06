# Do not edit -- this file documents how Postfix was built for your machine.
#----------------------------------------------------------------
# Start of summary of user-configurable 'make makefiles' options.
# CCARGS=-DDEBIAN -DUSE_DYNAMIC_MAPS -DHAS_PCRE -DHAS_LDAP -DUSE_LDAP_SASL -DHAS_SQLITE -DMYORIGIN_FROM_FILE  -DHAS_CDB -DHAS_MYSQL -I/usr/include/mysql -DHAS_PGSQL -I/usr/include/postgresql -DHAS_SQLITE -I/usr/include -DHAS_SSL -I/usr/include/openssl -DUSE_SASL_AUTH -I/usr/include/sasl -DUSE_CYRUS_SASL -DUSE_TLS
# AUXLIBS=-lssl -lcrypto -lsasl2 -lpthread -L/build-src/src/postfix-3.0.3/debian
# shared=yes
# dynamicmaps=yes
# pie=
# End of summary of user-configurable 'make makefiles' options.
#--------------------------------------------------------------
# System-dependent settings and compiler/linker overrides.
SYSTYPE	= LINUX3
_AR	= ar
ARFL	= rv
_RANLIB	= ranlib
SYSLIBS	= -lssl -lcrypto -lsasl2 -lpthread -L/build-src/src/postfix-3.0.3/debian -ldb -lnsl -lresolv -ldl -L/usr/local/lib -licuuc 
CC	= gcc -I. -I../../include -DDEBIAN -DUSE_DYNAMIC_MAPS -DHAS_PCRE -DHAS_LDAP -DUSE_LDAP_SASL -DHAS_SQLITE -DMYORIGIN_FROM_FILE -DHAS_CDB -DHAS_MYSQL -I/usr/include/mysql -DHAS_PGSQL -I/usr/include/postgresql -DHAS_SQLITE -I/usr/include -DHAS_SSL -I/usr/include/openssl -DUSE_SASL_AUTH -I/usr/include/sasl -DUSE_CYRUS_SASL -DUSE_TLS -DUSE_DYNAMIC_LIBS -DUSE_DYNAMIC_MAPS $(WARN)
OPT	= -O2
DEBUG	= 
AWK	= awk
STRCASE = 
EXPORT	= CCARGS='-I. -I../../include -DDEBIAN -DUSE_DYNAMIC_MAPS -DHAS_PCRE -DHAS_LDAP -DUSE_LDAP_SASL -DHAS_SQLITE -DMYORIGIN_FROM_FILE -DHAS_CDB -DHAS_MYSQL -I/usr/include/mysql -DHAS_PGSQL -I/usr/include/postgresql -DHAS_SQLITE -I/usr/include -DHAS_SSL -I/usr/include/openssl -DUSE_SASL_AUTH -I/usr/include/sasl -DUSE_CYRUS_SASL -DUSE_TLS -DUSE_DYNAMIC_LIBS -DUSE_DYNAMIC_MAPS' OPT='-O2' DEBUG=''
WARN	= -Wall -Wno-comment -Wformat -Wimplicit -Wmissing-prototypes \
	-Wparentheses -Wstrict-prototypes -Wswitch -Wuninitialized \
	-Wunused -Wno-missing-braces
DEFINED_MAP_TYPES = pcre ldap sqlite cdb mysql pgsql ssl
MAKE_FIX = 
# Switch between Postfix static and dynamically-linked libraries.
AR	= :
RANLIB	= :
LIB_PREFIX = postfix-
LIB_SUFFIX = .so
SHLIB_CFLAGS = -fPIC
SHLIB_DIR = /usr/lib/postfix
SHLIB_ENV = LD_LIBRARY_PATH=/build-src/src/postfix-3.0.3/lib
SHLIB_LD = gcc -shared -Wl,-soname,${LIB}
SHLIB_SYSLIBS = -lssl -lcrypto -lsasl2 -lpthread -L/build-src/src/postfix-3.0.3/debian -ldb -lnsl -lresolv -ldl -L/usr/local/lib -licuuc
SHLIB_RPATH = -Wl,--enable-new-dtags -Wl,-rpath,${SHLIB_DIR}
# Switch between dynamicmaps.cf plugins and hard-linked databases.
NON_PLUGIN_MAP_OBJ = 
PLUGIN_MAP_OBJ = $(MAP_OBJ)
PLUGIN_MAP_OBJ_UPDATE = plugin_map_obj_update
PLUGIN_MAP_SO_MAKE = plugin_map_so_make
PLUGIN_MAP_SO_UPDATE = plugin_map_so_update
PLUGIN_LD = gcc -shared
# Application-specific rules.
SHELL	= /bin/sh
SRCS	= xsasl_server.c xsasl_cyrus_server.c xsasl_cyrus_log.c \
	xsasl_cyrus_security.c xsasl_client.c xsasl_cyrus_client.c \
	xsasl_dovecot_server.c
OBJS	= xsasl_server.o xsasl_cyrus_server.o xsasl_cyrus_log.o \
	xsasl_cyrus_security.o xsasl_client.o xsasl_cyrus_client.o \
	xsasl_dovecot_server.o
HDRS	= xsasl.h
TESTSRC	= 
DEFS	= -I. -I$(INC_DIR) -D$(SYSTYPE)
CFLAGS	= $(DEBUG) $(OPT) $(DEFS)
INCL	=
LIB	= libxsasl.a
TESTPROG= 

LIBS	= ../../lib/lib$(LIB_PERFIX)global$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PERFIX)util$(LIB_SUFFIX)
LIB_DIR	= ../../lib
INC_DIR	= ../../include
MAKES	=

.c.o:;	$(CC) $(CFLAGS) -c $*.c

all: $(LIB)

$(OBJS): ../../conf/makedefs.out

Makefile: Makefile.in
	cat ../../conf/makedefs.out $? >$@

test:	$(TESTPROG)

tests:

root_tests:

$(LIB):	$(OBJS)
	$(_AR) $(ARFL) $(LIB) $?
	$(_RANLIB) $(LIB)

$(LIB_DIR)/$(LIB): $(LIB)
	cp $(LIB) $(LIB_DIR)
	$(_RANLIB) $(LIB_DIR)/$(LIB)

update: $(LIB_DIR)/$(LIB) $(HDRS)
	-for i in $(HDRS); \
	do \
	  cmp -s $$i $(INC_DIR)/$$i 2>/dev/null || cp $$i $(INC_DIR); \
	done
	cd $(INC_DIR); chmod 644 $(HDRS)

printfck: $(OBJS) $(PROG)
	rm -rf printfck
	mkdir printfck
	cp *.h printfck
	sed '1,/^# do not edit/!d' Makefile >printfck/Makefile
	set -e; for i in *.c; do printfck -f .printfck $$i >printfck/$$i; done
	cd printfck; make "INC_DIR=../../../include" `cd ..; ls *.o`

lint:
	lint $(DEFS) $(SRCS) $(LINTFIX)

clean:
	rm -f *.o $(LIB) *core $(TESTPROG) junk
	rm -rf printfck

tidy:	clean

foo: $(LIB) $(LIBS)
	mv $@.o junk
	$(CC) $(CFLAGS) -DTEST -o $@ $@.c $(LIB) $(LIBS) $(SYSLIBS)
	mv junk $@.o

depend: $(MAKES)
	(sed '1,/^# do not edit/!d' Makefile.in; \
	set -e; for i in [a-z][a-z0-9]*.c; do \
	    $(CC) -E $(DEFS) $(INCL) $$i | grep -v '[<>]' | sed -n -e '/^# *1 *"\([^"]*\)".*/{' \
	    -e 's//'`echo $$i|sed 's/c$$/o/'`': \1/' \
	    -e 's/o: \.\//o: /' -e p -e '}' ; \
	done | sort -u) | grep -v '[.][o][:][ ][/]' >$$$$ && mv $$$$ Makefile.in
	@$(EXPORT) make -f Makefile.in Makefile 1>&2

# do not edit below this line - it is generated by 'make depend'
xsasl_client.o: ../../include/argv.h
xsasl_client.o: ../../include/check_arg.h
xsasl_client.o: ../../include/msg.h
xsasl_client.o: ../../include/mymalloc.h
xsasl_client.o: ../../include/sys_defs.h
xsasl_client.o: ../../include/vbuf.h
xsasl_client.o: ../../include/vstream.h
xsasl_client.o: ../../include/vstring.h
xsasl_client.o: xsasl.h
xsasl_client.o: xsasl_client.c
xsasl_client.o: xsasl_cyrus.h
xsasl_cyrus_client.o: ../../include/argv.h
xsasl_cyrus_client.o: ../../include/check_arg.h
xsasl_cyrus_client.o: ../../include/mail_params.h
xsasl_cyrus_client.o: ../../include/msg.h
xsasl_cyrus_client.o: ../../include/mymalloc.h
xsasl_cyrus_client.o: ../../include/stringops.h
xsasl_cyrus_client.o: ../../include/sys_defs.h
xsasl_cyrus_client.o: ../../include/vbuf.h
xsasl_cyrus_client.o: ../../include/vstream.h
xsasl_cyrus_client.o: ../../include/vstring.h
xsasl_cyrus_client.o: xsasl.h
xsasl_cyrus_client.o: xsasl_cyrus.h
xsasl_cyrus_client.o: xsasl_cyrus_client.c
xsasl_cyrus_client.o: xsasl_cyrus_common.h
xsasl_cyrus_log.o: ../../include/msg.h
xsasl_cyrus_log.o: ../../include/sys_defs.h
xsasl_cyrus_log.o: xsasl_cyrus_common.h
xsasl_cyrus_log.o: xsasl_cyrus_log.c
xsasl_cyrus_security.o: ../../include/check_arg.h
xsasl_cyrus_security.o: ../../include/name_mask.h
xsasl_cyrus_security.o: ../../include/sys_defs.h
xsasl_cyrus_security.o: ../../include/vbuf.h
xsasl_cyrus_security.o: ../../include/vstring.h
xsasl_cyrus_security.o: xsasl_cyrus_common.h
xsasl_cyrus_security.o: xsasl_cyrus_security.c
xsasl_cyrus_server.o: ../../include/argv.h
xsasl_cyrus_server.o: ../../include/check_arg.h
xsasl_cyrus_server.o: ../../include/mail_params.h
xsasl_cyrus_server.o: ../../include/msg.h
xsasl_cyrus_server.o: ../../include/mymalloc.h
xsasl_cyrus_server.o: ../../include/name_mask.h
xsasl_cyrus_server.o: ../../include/stringops.h
xsasl_cyrus_server.o: ../../include/sys_defs.h
xsasl_cyrus_server.o: ../../include/vbuf.h
xsasl_cyrus_server.o: ../../include/vstream.h
xsasl_cyrus_server.o: ../../include/vstring.h
xsasl_cyrus_server.o: xsasl.h
xsasl_cyrus_server.o: xsasl_cyrus.h
xsasl_cyrus_server.o: xsasl_cyrus_common.h
xsasl_cyrus_server.o: xsasl_cyrus_server.c
xsasl_dovecot_server.o: ../../include/argv.h
xsasl_dovecot_server.o: ../../include/check_arg.h
xsasl_dovecot_server.o: ../../include/connect.h
xsasl_dovecot_server.o: ../../include/iostuff.h
xsasl_dovecot_server.o: ../../include/mail_params.h
xsasl_dovecot_server.o: ../../include/msg.h
xsasl_dovecot_server.o: ../../include/myaddrinfo.h
xsasl_dovecot_server.o: ../../include/mymalloc.h
xsasl_dovecot_server.o: ../../include/name_mask.h
xsasl_dovecot_server.o: ../../include/split_at.h
xsasl_dovecot_server.o: ../../include/stringops.h
xsasl_dovecot_server.o: ../../include/sys_defs.h
xsasl_dovecot_server.o: ../../include/vbuf.h
xsasl_dovecot_server.o: ../../include/vstream.h
xsasl_dovecot_server.o: ../../include/vstring.h
xsasl_dovecot_server.o: ../../include/vstring_vstream.h
xsasl_dovecot_server.o: xsasl.h
xsasl_dovecot_server.o: xsasl_dovecot.h
xsasl_dovecot_server.o: xsasl_dovecot_server.c
xsasl_server.o: ../../include/argv.h
xsasl_server.o: ../../include/check_arg.h
xsasl_server.o: ../../include/msg.h
xsasl_server.o: ../../include/mymalloc.h
xsasl_server.o: ../../include/sys_defs.h
xsasl_server.o: ../../include/vbuf.h
xsasl_server.o: ../../include/vstream.h
xsasl_server.o: ../../include/vstring.h
xsasl_server.o: xsasl.h
xsasl_server.o: xsasl_cyrus.h
xsasl_server.o: xsasl_dovecot.h
xsasl_server.o: xsasl_server.c
