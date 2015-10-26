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
SRCS	= dns_lookup.c dns_rr.c dns_strerror.c dns_strtype.c dns_rr_to_pa.c \
	dns_sa_to_rr.c dns_rr_eq_sa.c dns_rr_to_sa.c dns_strrecord.c \
	dns_rr_filter.c
OBJS	= dns_lookup.o dns_rr.o dns_strerror.o dns_strtype.o dns_rr_to_pa.o \
	dns_sa_to_rr.o dns_rr_eq_sa.o dns_rr_to_sa.o dns_strrecord.o \
	dns_rr_filter.o
HDRS	= dns.h
TESTSRC	= test_dns_lookup.c test_alias_token.c
DEFS	= -I. -I$(INC_DIR) -D$(SYSTYPE)
CFLAGS	= $(DEBUG) $(OPT) $(DEFS)
INCL	=
LIB	= lib$(LIB_PREFIX)dns$(LIB_SUFFIX)
TESTPROG= test_dns_lookup dns_rr_to_pa dns_rr_to_sa dns_sa_to_rr dns_rr_eq_sa
LIBS	= ../../lib/lib$(LIB_PREFIX)global$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PREFIX)util$(LIB_SUFFIX)
LIB_DIR	= ../../lib
INC_DIR	= ../../include

.c.o:;	$(CC) $(SHLIB_CFLAGS) $(CFLAGS) -c $*.c

all: $(LIB)

$(OBJS): ../../conf/makedefs.out

Makefile: Makefile.in
	cat ../../conf/makedefs.out $? >$@

test:	$(TESTPROG)

tests:	test dns_rr_to_pa_test dns_rr_to_sa_test dns_sa_to_rr_test \
	dns_rr_eq_sa_test no-a-test no-aaaa-test no-mx-test \
	error-filter-test nullmx_test nxdomain_test mxonly_test

root_tests:

$(LIB):	$(OBJS)
	$(AR) $(ARFL) $(LIB) $?
	$(RANLIB) $(LIB)
	$(SHLIB_LD) $(SHLIB_RPATH) -o $(LIB) $(OBJS) $(SHLIB_SYSLIBS)

$(LIB_DIR)/$(LIB): $(LIB)
	cp $(LIB) $(LIB_DIR)
	$(RANLIB) $(LIB_DIR)/$(LIB)

update: $(LIB_DIR)/$(LIB) $(HDRS)
	-for i in $(HDRS); \
	do \
	  cmp -s $$i $(INC_DIR)/$$i 2>/dev/null || cp $$i $(INC_DIR); \
	done
	cd $(INC_DIR); chmod 644 $(HDRS)

test_dns_lookup: test_dns_lookup.c $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ $@.c $(LIB) $(LIBS) $(SYSLIBS)

dns_rr_to_pa: $(LIB) $(LIBS)
	mv $@.o junk
	$(CC) $(CFLAGS) -DTEST -o $@ $@.c $(LIB) $(LIBS) $(SYSLIBS)
	mv junk $@.o

dns_rr_to_sa: $(LIB) $(LIBS)
	mv $@.o junk
	$(CC) $(CFLAGS) -DTEST -o $@ $@.c $(LIB) $(LIBS) $(SYSLIBS)
	mv junk $@.o

dns_sa_to_rr: $(LIB) $(LIBS)
	mv $@.o junk
	$(CC) $(CFLAGS) -DTEST -o $@ $@.c $(LIB) $(LIBS) $(SYSLIBS)
	mv junk $@.o

dns_rr_eq_sa: $(LIB) $(LIBS)
	mv $@.o junk
	$(CC) $(CFLAGS) -DTEST -o $@ $@.c $(LIB) $(LIBS) $(SYSLIBS)
	mv junk $@.o

dns_rr_to_pa_test: dns_rr_to_pa dns_rr_to_pa.in dns_rr_to_pa.ref
	$(SHLIB_ENV) ./dns_rr_to_pa `cat dns_rr_to_pa.in` >dns_rr_to_pa.tmp
	diff dns_rr_to_pa.ref dns_rr_to_pa.tmp
	rm -f dns_rr_to_pa.tmp

dns_rr_to_sa_test: dns_rr_to_sa dns_rr_to_sa.in dns_rr_to_sa.ref
	$(SHLIB_ENV) ./dns_rr_to_sa `cat dns_rr_to_sa.in` >dns_rr_to_sa.tmp
	diff dns_rr_to_sa.ref dns_rr_to_sa.tmp
	rm -f dns_rr_to_sa.tmp

dns_sa_to_rr_test: dns_sa_to_rr dns_sa_to_rr.in dns_sa_to_rr.ref
	$(SHLIB_ENV) ./dns_sa_to_rr `cat dns_sa_to_rr.in` >dns_sa_to_rr.tmp
	diff dns_sa_to_rr.ref dns_sa_to_rr.tmp
	rm -f dns_sa_to_rr.tmp

dns_rr_eq_sa_test: dns_rr_eq_sa dns_rr_eq_sa.in dns_rr_eq_sa.ref
	$(SHLIB_ENV) ./dns_rr_eq_sa `cat dns_rr_eq_sa.in` >dns_rr_eq_sa.tmp
	diff dns_rr_eq_sa.ref dns_rr_eq_sa.tmp
	rm -f dns_rr_eq_sa.tmp

no-a-test: no-a.reg test_dns_lookup no-a.ref
	$(SHLIB_ENV) ./test_dns_lookup -f regexp:no-a.reg a,aaaa spike.porcupine.org >test_dns_lookup.tmp 2>&1
	diff no-a.ref test_dns_lookup.tmp
	rm -f test_dns_lookup.tmp

no-aaaa-test: no-aaaa.reg test_dns_lookup no-aaaa.ref
	$(SHLIB_ENV) ./test_dns_lookup -f regexp:no-aaaa.reg a,aaaa spike.porcupine.org >test_dns_lookup.tmp 2>&1
	diff no-aaaa.ref test_dns_lookup.tmp
	rm -f test_dns_lookup.tmp

no-mx-test: no-mx.reg test_dns_lookup no-mx.ref
	set -e; $(SHLIB_ENV) ./test_dns_lookup -f regexp:no-mx.reg mx porcupine.org 2>&1 | sort >test_dns_lookup.tmp || true
	diff no-mx.ref test_dns_lookup.tmp
	rm -f test_dns_lookup.tmp

error-filter-test: error.reg test_dns_lookup error.ref
	set -e; $(SHLIB_ENV) ./test_dns_lookup -f regexp:error.reg a,aaaa spike.porcupine.org >test_dns_lookup.tmp 2>&1 || true
	diff error.ref test_dns_lookup.tmp
	rm -f test_dns_lookup.tmp

nullmx_test: test_dns_lookup nullmx_test.ref
	(set -e; \
	$(SHLIB_ENV) ./test_dns_lookup mx,a nullmx.porcupine.org; \
	) >nullmx_test.tmp 2>&1 || exit 0
	diff nullmx_test.ref nullmx_test.tmp
	rm -f nullmx_test.tmp

nxdomain_test: test_dns_lookup nxdomain_test.ref
	(set -e; \
	$(SHLIB_ENV) ./test_dns_lookup mx,a nxdomain.porcupine.org; \
	) >nxdomain_test.tmp 2>&1 || exit 0
	diff nxdomain_test.ref nxdomain_test.tmp
	rm -f nxdomain_test.tmp

mxonly_test: test_dns_lookup mxonly_test.ref
	(set -e; \
	$(SHLIB_ENV) ./test_dns_lookup mx,a porcupine.org | sort; \
	) >mxonly_test.tmp 2>&1 || exit 0
	diff mxonly_test.ref mxonly_test.tmp
	rm -f mxonly_test.tmp

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

depend: $(MAKES)
	(sed '1,/^# do not edit/!d' Makefile.in; \
	set -e; for i in [a-z][a-z0-9]*.c; do \
	    $(CC) -E $(DEFS) $(INCL) $$i | grep -v '[<>]' | sed -n -e '/^# *1 *"\([^"]*\)".*/{' \
	    -e 's//'`echo $$i|sed 's/c$$/o/'`': \1/' \
	    -e 's/o: \.\//o: /' -e p -e '}' ; \
	done | sort -u) | grep -v '[.][o][:][ ][/]' >$$$$ && mv $$$$ Makefile.in
	@$(EXPORT) make -f Makefile.in Makefile 1>&2

# do not edit below this line - it is generated by 'make depend'
dns_lookup.o: ../../include/argv.h
dns_lookup.o: ../../include/check_arg.h
dns_lookup.o: ../../include/dict.h
dns_lookup.o: ../../include/maps.h
dns_lookup.o: ../../include/msg.h
dns_lookup.o: ../../include/myaddrinfo.h
dns_lookup.o: ../../include/myflock.h
dns_lookup.o: ../../include/mymalloc.h
dns_lookup.o: ../../include/sock_addr.h
dns_lookup.o: ../../include/stringops.h
dns_lookup.o: ../../include/sys_defs.h
dns_lookup.o: ../../include/valid_hostname.h
dns_lookup.o: ../../include/vbuf.h
dns_lookup.o: ../../include/vstream.h
dns_lookup.o: ../../include/vstring.h
dns_lookup.o: dns.h
dns_lookup.o: dns_lookup.c
dns_rr.o: ../../include/check_arg.h
dns_rr.o: ../../include/msg.h
dns_rr.o: ../../include/myaddrinfo.h
dns_rr.o: ../../include/mymalloc.h
dns_rr.o: ../../include/myrand.h
dns_rr.o: ../../include/sock_addr.h
dns_rr.o: ../../include/sys_defs.h
dns_rr.o: ../../include/vbuf.h
dns_rr.o: ../../include/vstring.h
dns_rr.o: dns.h
dns_rr.o: dns_rr.c
dns_rr_eq_sa.o: ../../include/check_arg.h
dns_rr_eq_sa.o: ../../include/msg.h
dns_rr_eq_sa.o: ../../include/myaddrinfo.h
dns_rr_eq_sa.o: ../../include/sock_addr.h
dns_rr_eq_sa.o: ../../include/sys_defs.h
dns_rr_eq_sa.o: ../../include/vbuf.h
dns_rr_eq_sa.o: ../../include/vstring.h
dns_rr_eq_sa.o: dns.h
dns_rr_eq_sa.o: dns_rr_eq_sa.c
dns_rr_filter.o: ../../include/argv.h
dns_rr_filter.o: ../../include/check_arg.h
dns_rr_filter.o: ../../include/dict.h
dns_rr_filter.o: ../../include/maps.h
dns_rr_filter.o: ../../include/msg.h
dns_rr_filter.o: ../../include/myaddrinfo.h
dns_rr_filter.o: ../../include/myflock.h
dns_rr_filter.o: ../../include/sock_addr.h
dns_rr_filter.o: ../../include/sys_defs.h
dns_rr_filter.o: ../../include/vbuf.h
dns_rr_filter.o: ../../include/vstream.h
dns_rr_filter.o: ../../include/vstring.h
dns_rr_filter.o: dns.h
dns_rr_filter.o: dns_rr_filter.c
dns_rr_to_pa.o: ../../include/check_arg.h
dns_rr_to_pa.o: ../../include/msg.h
dns_rr_to_pa.o: ../../include/myaddrinfo.h
dns_rr_to_pa.o: ../../include/sock_addr.h
dns_rr_to_pa.o: ../../include/sys_defs.h
dns_rr_to_pa.o: ../../include/vbuf.h
dns_rr_to_pa.o: ../../include/vstring.h
dns_rr_to_pa.o: dns.h
dns_rr_to_pa.o: dns_rr_to_pa.c
dns_rr_to_sa.o: ../../include/check_arg.h
dns_rr_to_sa.o: ../../include/msg.h
dns_rr_to_sa.o: ../../include/myaddrinfo.h
dns_rr_to_sa.o: ../../include/sock_addr.h
dns_rr_to_sa.o: ../../include/sys_defs.h
dns_rr_to_sa.o: ../../include/vbuf.h
dns_rr_to_sa.o: ../../include/vstring.h
dns_rr_to_sa.o: dns.h
dns_rr_to_sa.o: dns_rr_to_sa.c
dns_sa_to_rr.o: ../../include/check_arg.h
dns_sa_to_rr.o: ../../include/msg.h
dns_sa_to_rr.o: ../../include/myaddrinfo.h
dns_sa_to_rr.o: ../../include/sock_addr.h
dns_sa_to_rr.o: ../../include/sys_defs.h
dns_sa_to_rr.o: ../../include/vbuf.h
dns_sa_to_rr.o: ../../include/vstring.h
dns_sa_to_rr.o: dns.h
dns_sa_to_rr.o: dns_sa_to_rr.c
dns_strerror.o: ../../include/check_arg.h
dns_strerror.o: ../../include/myaddrinfo.h
dns_strerror.o: ../../include/sock_addr.h
dns_strerror.o: ../../include/sys_defs.h
dns_strerror.o: ../../include/vbuf.h
dns_strerror.o: ../../include/vstring.h
dns_strerror.o: dns.h
dns_strerror.o: dns_strerror.c
dns_strrecord.o: ../../include/check_arg.h
dns_strrecord.o: ../../include/msg.h
dns_strrecord.o: ../../include/myaddrinfo.h
dns_strrecord.o: ../../include/sock_addr.h
dns_strrecord.o: ../../include/sys_defs.h
dns_strrecord.o: ../../include/vbuf.h
dns_strrecord.o: ../../include/vstring.h
dns_strrecord.o: dns.h
dns_strrecord.o: dns_strrecord.c
dns_strtype.o: ../../include/check_arg.h
dns_strtype.o: ../../include/myaddrinfo.h
dns_strtype.o: ../../include/sock_addr.h
dns_strtype.o: ../../include/sys_defs.h
dns_strtype.o: ../../include/vbuf.h
dns_strtype.o: ../../include/vstring.h
dns_strtype.o: dns.h
dns_strtype.o: dns_strtype.c
test_dns_lookup.o: ../../include/argv.h
test_dns_lookup.o: ../../include/check_arg.h
test_dns_lookup.o: ../../include/msg.h
test_dns_lookup.o: ../../include/msg_vstream.h
test_dns_lookup.o: ../../include/myaddrinfo.h
test_dns_lookup.o: ../../include/mymalloc.h
test_dns_lookup.o: ../../include/sock_addr.h
test_dns_lookup.o: ../../include/sys_defs.h
test_dns_lookup.o: ../../include/vbuf.h
test_dns_lookup.o: ../../include/vstream.h
test_dns_lookup.o: ../../include/vstring.h
test_dns_lookup.o: dns.h
test_dns_lookup.o: test_dns_lookup.c
