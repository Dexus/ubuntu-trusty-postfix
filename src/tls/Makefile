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
SRCS	= tls_prng_dev.c tls_prng_egd.c tls_prng_file.c tls_fprint.c \
	tls_prng_exch.c tls_stream.c tls_bio_ops.c tls_misc.c tls_dh.c \
	tls_rsa.c tls_verify.c tls_dane.c tls_certkey.c tls_session.c \
	tls_client.c tls_server.c tls_scache.c tls_mgr.c tls_seed.c \
	tls_level.c \
	tls_proxy_clnt.c tls_proxy_print.c tls_proxy_scan.c
OBJS	= tls_prng_dev.o tls_prng_egd.o tls_prng_file.o tls_fprint.o \
	tls_prng_exch.o tls_stream.o tls_bio_ops.o tls_misc.o tls_dh.o \
	tls_rsa.o tls_verify.o tls_dane.o tls_certkey.o tls_session.o \
	tls_client.o tls_server.o tls_scache.o tls_mgr.o tls_seed.o \
	tls_level.o \
	tls_proxy_clnt.o tls_proxy_print.o tls_proxy_scan.o
HDRS	= tls.h tls_prng.h tls_scache.h tls_mgr.h tls_proxy.h
TESTSRC	= 
DEFS	= -I. -I$(INC_DIR) -D$(SYSTYPE)
CFLAGS	= $(DEBUG) $(OPT) $(DEFS)
INCL	=
LIB	= lib$(LIB_PREFIX)tls$(LIB_SUFFIX)
TESTPROG= tls_dh tls_mgr tls_rsa tls_dane

LIBS	= ../../lib/lib$(LIB_PREFIX)dns$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PREFIX)global$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PREFIX)util$(LIB_SUFFIX)
LIB_DIR	= ../../lib
INC_DIR	= ../../include
MAKES	=

.c.o:;	$(CC) $(SHLIB_CFLAGS) $(CFLAGS) -c $*.c

all: $(LIB)

$(OBJS): ../../conf/makedefs.out

Makefile: Makefile.in
	cat ../../conf/makedefs.out $? >$@

test:	$(TESTPROG)

tests:

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

tls_dh:	$(LIB) $(LIBS)
	mv $@.o junk
	$(CC) $(CFLAGS) -DTEST -o $@ $@.c $(LIB) $(LIBS) $(SYSLIBS)
	mv junk $@.o

tls_mgr: $(LIB) $(LIBS)
	mv $@.o junk
	$(CC) $(CFLAGS) -DTEST -o $@ $@.c $(LIB) $(LIBS) $(SYSLIBS)
	mv junk $@.o

tls_rsa: $(LIB) $(LIBS)
	mv $@.o junk
	$(CC) $(CFLAGS) -DTEST -o $@ $@.c $(LIB) $(LIBS) $(SYSLIBS)
	mv junk $@.o

tls_dane: $(LIB) $(LIBS)
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
tls_bio_ops.o: ../../include/argv.h
tls_bio_ops.o: ../../include/check_arg.h
tls_bio_ops.o: ../../include/dns.h
tls_bio_ops.o: ../../include/iostuff.h
tls_bio_ops.o: ../../include/msg.h
tls_bio_ops.o: ../../include/myaddrinfo.h
tls_bio_ops.o: ../../include/name_code.h
tls_bio_ops.o: ../../include/name_mask.h
tls_bio_ops.o: ../../include/sock_addr.h
tls_bio_ops.o: ../../include/sys_defs.h
tls_bio_ops.o: ../../include/vbuf.h
tls_bio_ops.o: ../../include/vstream.h
tls_bio_ops.o: ../../include/vstring.h
tls_bio_ops.o: tls.h
tls_bio_ops.o: tls_bio_ops.c
tls_certkey.o: ../../include/argv.h
tls_certkey.o: ../../include/check_arg.h
tls_certkey.o: ../../include/dns.h
tls_certkey.o: ../../include/mail_params.h
tls_certkey.o: ../../include/msg.h
tls_certkey.o: ../../include/myaddrinfo.h
tls_certkey.o: ../../include/name_code.h
tls_certkey.o: ../../include/name_mask.h
tls_certkey.o: ../../include/sock_addr.h
tls_certkey.o: ../../include/sys_defs.h
tls_certkey.o: ../../include/vbuf.h
tls_certkey.o: ../../include/vstream.h
tls_certkey.o: ../../include/vstring.h
tls_certkey.o: tls.h
tls_certkey.o: tls_certkey.c
tls_client.o: ../../include/argv.h
tls_client.o: ../../include/check_arg.h
tls_client.o: ../../include/dict.h
tls_client.o: ../../include/dns.h
tls_client.o: ../../include/iostuff.h
tls_client.o: ../../include/mail_params.h
tls_client.o: ../../include/midna_domain.h
tls_client.o: ../../include/msg.h
tls_client.o: ../../include/myaddrinfo.h
tls_client.o: ../../include/myflock.h
tls_client.o: ../../include/mymalloc.h
tls_client.o: ../../include/name_code.h
tls_client.o: ../../include/name_mask.h
tls_client.o: ../../include/sock_addr.h
tls_client.o: ../../include/stringops.h
tls_client.o: ../../include/sys_defs.h
tls_client.o: ../../include/vbuf.h
tls_client.o: ../../include/vstream.h
tls_client.o: ../../include/vstring.h
tls_client.o: tls.h
tls_client.o: tls_client.c
tls_client.o: tls_mgr.h
tls_client.o: tls_scache.h
tls_dane.o: ../../include/argv.h
tls_dane.o: ../../include/check_arg.h
tls_dane.o: ../../include/ctable.h
tls_dane.o: ../../include/dns.h
tls_dane.o: ../../include/events.h
tls_dane.o: ../../include/hex_code.h
tls_dane.o: ../../include/mail_params.h
tls_dane.o: ../../include/msg.h
tls_dane.o: ../../include/myaddrinfo.h
tls_dane.o: ../../include/mymalloc.h
tls_dane.o: ../../include/name_code.h
tls_dane.o: ../../include/name_mask.h
tls_dane.o: ../../include/safe_ultostr.h
tls_dane.o: ../../include/sock_addr.h
tls_dane.o: ../../include/split_at.h
tls_dane.o: ../../include/stringops.h
tls_dane.o: ../../include/sys_defs.h
tls_dane.o: ../../include/timecmp.h
tls_dane.o: ../../include/vbuf.h
tls_dane.o: ../../include/vstream.h
tls_dane.o: ../../include/vstring.h
tls_dane.o: tls.h
tls_dane.o: tls_dane.c
tls_dh.o: ../../include/argv.h
tls_dh.o: ../../include/check_arg.h
tls_dh.o: ../../include/dns.h
tls_dh.o: ../../include/mail_params.h
tls_dh.o: ../../include/msg.h
tls_dh.o: ../../include/myaddrinfo.h
tls_dh.o: ../../include/name_code.h
tls_dh.o: ../../include/name_mask.h
tls_dh.o: ../../include/sock_addr.h
tls_dh.o: ../../include/sys_defs.h
tls_dh.o: ../../include/vbuf.h
tls_dh.o: ../../include/vstream.h
tls_dh.o: ../../include/vstring.h
tls_dh.o: tls.h
tls_dh.o: tls_dh.c
tls_fprint.o: ../../include/argv.h
tls_fprint.o: ../../include/check_arg.h
tls_fprint.o: ../../include/dns.h
tls_fprint.o: ../../include/mail_params.h
tls_fprint.o: ../../include/msg.h
tls_fprint.o: ../../include/myaddrinfo.h
tls_fprint.o: ../../include/mymalloc.h
tls_fprint.o: ../../include/name_code.h
tls_fprint.o: ../../include/name_mask.h
tls_fprint.o: ../../include/sock_addr.h
tls_fprint.o: ../../include/stringops.h
tls_fprint.o: ../../include/sys_defs.h
tls_fprint.o: ../../include/vbuf.h
tls_fprint.o: ../../include/vstream.h
tls_fprint.o: ../../include/vstring.h
tls_fprint.o: tls.h
tls_fprint.o: tls_fprint.c
tls_level.o: ../../include/argv.h
tls_level.o: ../../include/check_arg.h
tls_level.o: ../../include/dns.h
tls_level.o: ../../include/myaddrinfo.h
tls_level.o: ../../include/name_code.h
tls_level.o: ../../include/name_mask.h
tls_level.o: ../../include/sock_addr.h
tls_level.o: ../../include/sys_defs.h
tls_level.o: ../../include/vbuf.h
tls_level.o: ../../include/vstream.h
tls_level.o: ../../include/vstring.h
tls_level.o: tls.h
tls_level.o: tls_level.c
tls_mgr.o: ../../include/argv.h
tls_mgr.o: ../../include/attr.h
tls_mgr.o: ../../include/attr_clnt.h
tls_mgr.o: ../../include/check_arg.h
tls_mgr.o: ../../include/dict.h
tls_mgr.o: ../../include/htable.h
tls_mgr.o: ../../include/iostuff.h
tls_mgr.o: ../../include/mail_params.h
tls_mgr.o: ../../include/mail_proto.h
tls_mgr.o: ../../include/msg.h
tls_mgr.o: ../../include/myflock.h
tls_mgr.o: ../../include/mymalloc.h
tls_mgr.o: ../../include/nvtable.h
tls_mgr.o: ../../include/stringops.h
tls_mgr.o: ../../include/sys_defs.h
tls_mgr.o: ../../include/vbuf.h
tls_mgr.o: ../../include/vstream.h
tls_mgr.o: ../../include/vstring.h
tls_mgr.o: tls_mgr.c
tls_mgr.o: tls_mgr.h
tls_mgr.o: tls_scache.h
tls_misc.o: ../../include/argv.h
tls_misc.o: ../../include/check_arg.h
tls_misc.o: ../../include/dns.h
tls_misc.o: ../../include/mail_conf.h
tls_misc.o: ../../include/mail_params.h
tls_misc.o: ../../include/msg.h
tls_misc.o: ../../include/myaddrinfo.h
tls_misc.o: ../../include/mymalloc.h
tls_misc.o: ../../include/name_code.h
tls_misc.o: ../../include/name_mask.h
tls_misc.o: ../../include/sock_addr.h
tls_misc.o: ../../include/stringops.h
tls_misc.o: ../../include/sys_defs.h
tls_misc.o: ../../include/vbuf.h
tls_misc.o: ../../include/vstream.h
tls_misc.o: ../../include/vstring.h
tls_misc.o: tls.h
tls_misc.o: tls_misc.c
tls_prng_dev.o: ../../include/connect.h
tls_prng_dev.o: ../../include/iostuff.h
tls_prng_dev.o: ../../include/msg.h
tls_prng_dev.o: ../../include/mymalloc.h
tls_prng_dev.o: ../../include/sys_defs.h
tls_prng_dev.o: tls_prng.h
tls_prng_dev.o: tls_prng_dev.c
tls_prng_egd.o: ../../include/connect.h
tls_prng_egd.o: ../../include/iostuff.h
tls_prng_egd.o: ../../include/msg.h
tls_prng_egd.o: ../../include/mymalloc.h
tls_prng_egd.o: ../../include/sys_defs.h
tls_prng_egd.o: tls_prng.h
tls_prng_egd.o: tls_prng_egd.c
tls_prng_exch.o: ../../include/iostuff.h
tls_prng_exch.o: ../../include/msg.h
tls_prng_exch.o: ../../include/myflock.h
tls_prng_exch.o: ../../include/mymalloc.h
tls_prng_exch.o: ../../include/sys_defs.h
tls_prng_exch.o: tls_prng.h
tls_prng_exch.o: tls_prng_exch.c
tls_prng_file.o: ../../include/connect.h
tls_prng_file.o: ../../include/iostuff.h
tls_prng_file.o: ../../include/msg.h
tls_prng_file.o: ../../include/mymalloc.h
tls_prng_file.o: ../../include/sys_defs.h
tls_prng_file.o: tls_prng.h
tls_prng_file.o: tls_prng_file.c
tls_proxy_clnt.o: ../../include/argv.h
tls_proxy_clnt.o: ../../include/attr.h
tls_proxy_clnt.o: ../../include/check_arg.h
tls_proxy_clnt.o: ../../include/connect.h
tls_proxy_clnt.o: ../../include/dns.h
tls_proxy_clnt.o: ../../include/htable.h
tls_proxy_clnt.o: ../../include/iostuff.h
tls_proxy_clnt.o: ../../include/mail_params.h
tls_proxy_clnt.o: ../../include/mail_proto.h
tls_proxy_clnt.o: ../../include/msg.h
tls_proxy_clnt.o: ../../include/myaddrinfo.h
tls_proxy_clnt.o: ../../include/mymalloc.h
tls_proxy_clnt.o: ../../include/name_code.h
tls_proxy_clnt.o: ../../include/name_mask.h
tls_proxy_clnt.o: ../../include/nvtable.h
tls_proxy_clnt.o: ../../include/sock_addr.h
tls_proxy_clnt.o: ../../include/stringops.h
tls_proxy_clnt.o: ../../include/sys_defs.h
tls_proxy_clnt.o: ../../include/vbuf.h
tls_proxy_clnt.o: ../../include/vstream.h
tls_proxy_clnt.o: ../../include/vstring.h
tls_proxy_clnt.o: tls.h
tls_proxy_clnt.o: tls_proxy.h
tls_proxy_clnt.o: tls_proxy_clnt.c
tls_proxy_print.o: ../../include/argv.h
tls_proxy_print.o: ../../include/attr.h
tls_proxy_print.o: ../../include/check_arg.h
tls_proxy_print.o: ../../include/dns.h
tls_proxy_print.o: ../../include/htable.h
tls_proxy_print.o: ../../include/iostuff.h
tls_proxy_print.o: ../../include/mail_proto.h
tls_proxy_print.o: ../../include/myaddrinfo.h
tls_proxy_print.o: ../../include/mymalloc.h
tls_proxy_print.o: ../../include/name_code.h
tls_proxy_print.o: ../../include/name_mask.h
tls_proxy_print.o: ../../include/nvtable.h
tls_proxy_print.o: ../../include/sock_addr.h
tls_proxy_print.o: ../../include/sys_defs.h
tls_proxy_print.o: ../../include/vbuf.h
tls_proxy_print.o: ../../include/vstream.h
tls_proxy_print.o: ../../include/vstring.h
tls_proxy_print.o: tls.h
tls_proxy_print.o: tls_proxy.h
tls_proxy_print.o: tls_proxy_print.c
tls_proxy_scan.o: ../../include/argv.h
tls_proxy_scan.o: ../../include/attr.h
tls_proxy_scan.o: ../../include/check_arg.h
tls_proxy_scan.o: ../../include/dns.h
tls_proxy_scan.o: ../../include/htable.h
tls_proxy_scan.o: ../../include/iostuff.h
tls_proxy_scan.o: ../../include/mail_proto.h
tls_proxy_scan.o: ../../include/myaddrinfo.h
tls_proxy_scan.o: ../../include/mymalloc.h
tls_proxy_scan.o: ../../include/name_code.h
tls_proxy_scan.o: ../../include/name_mask.h
tls_proxy_scan.o: ../../include/nvtable.h
tls_proxy_scan.o: ../../include/sock_addr.h
tls_proxy_scan.o: ../../include/sys_defs.h
tls_proxy_scan.o: ../../include/vbuf.h
tls_proxy_scan.o: ../../include/vstream.h
tls_proxy_scan.o: ../../include/vstring.h
tls_proxy_scan.o: tls.h
tls_proxy_scan.o: tls_proxy.h
tls_proxy_scan.o: tls_proxy_scan.c
tls_rsa.o: ../../include/argv.h
tls_rsa.o: ../../include/check_arg.h
tls_rsa.o: ../../include/dns.h
tls_rsa.o: ../../include/msg.h
tls_rsa.o: ../../include/myaddrinfo.h
tls_rsa.o: ../../include/name_code.h
tls_rsa.o: ../../include/name_mask.h
tls_rsa.o: ../../include/sock_addr.h
tls_rsa.o: ../../include/sys_defs.h
tls_rsa.o: ../../include/vbuf.h
tls_rsa.o: ../../include/vstream.h
tls_rsa.o: ../../include/vstring.h
tls_rsa.o: tls.h
tls_rsa.o: tls_rsa.c
tls_scache.o: ../../include/argv.h
tls_scache.o: ../../include/check_arg.h
tls_scache.o: ../../include/dict.h
tls_scache.o: ../../include/hex_code.h
tls_scache.o: ../../include/msg.h
tls_scache.o: ../../include/myflock.h
tls_scache.o: ../../include/mymalloc.h
tls_scache.o: ../../include/stringops.h
tls_scache.o: ../../include/sys_defs.h
tls_scache.o: ../../include/timecmp.h
tls_scache.o: ../../include/vbuf.h
tls_scache.o: ../../include/vstream.h
tls_scache.o: ../../include/vstring.h
tls_scache.o: tls_scache.c
tls_scache.o: tls_scache.h
tls_seed.o: ../../include/argv.h
tls_seed.o: ../../include/check_arg.h
tls_seed.o: ../../include/dict.h
tls_seed.o: ../../include/dns.h
tls_seed.o: ../../include/msg.h
tls_seed.o: ../../include/myaddrinfo.h
tls_seed.o: ../../include/myflock.h
tls_seed.o: ../../include/name_code.h
tls_seed.o: ../../include/name_mask.h
tls_seed.o: ../../include/sock_addr.h
tls_seed.o: ../../include/sys_defs.h
tls_seed.o: ../../include/vbuf.h
tls_seed.o: ../../include/vstream.h
tls_seed.o: ../../include/vstring.h
tls_seed.o: tls.h
tls_seed.o: tls_mgr.h
tls_seed.o: tls_scache.h
tls_seed.o: tls_seed.c
tls_server.o: ../../include/argv.h
tls_server.o: ../../include/check_arg.h
tls_server.o: ../../include/dict.h
tls_server.o: ../../include/dns.h
tls_server.o: ../../include/hex_code.h
tls_server.o: ../../include/iostuff.h
tls_server.o: ../../include/mail_params.h
tls_server.o: ../../include/msg.h
tls_server.o: ../../include/myaddrinfo.h
tls_server.o: ../../include/myflock.h
tls_server.o: ../../include/mymalloc.h
tls_server.o: ../../include/name_code.h
tls_server.o: ../../include/name_mask.h
tls_server.o: ../../include/sock_addr.h
tls_server.o: ../../include/stringops.h
tls_server.o: ../../include/sys_defs.h
tls_server.o: ../../include/vbuf.h
tls_server.o: ../../include/vstream.h
tls_server.o: ../../include/vstring.h
tls_server.o: tls.h
tls_server.o: tls_mgr.h
tls_server.o: tls_scache.h
tls_server.o: tls_server.c
tls_session.o: ../../include/argv.h
tls_session.o: ../../include/check_arg.h
tls_session.o: ../../include/dns.h
tls_session.o: ../../include/msg.h
tls_session.o: ../../include/myaddrinfo.h
tls_session.o: ../../include/mymalloc.h
tls_session.o: ../../include/name_code.h
tls_session.o: ../../include/name_mask.h
tls_session.o: ../../include/sock_addr.h
tls_session.o: ../../include/sys_defs.h
tls_session.o: ../../include/vbuf.h
tls_session.o: ../../include/vstream.h
tls_session.o: ../../include/vstring.h
tls_session.o: tls.h
tls_session.o: tls_session.c
tls_stream.o: ../../include/argv.h
tls_stream.o: ../../include/check_arg.h
tls_stream.o: ../../include/dns.h
tls_stream.o: ../../include/iostuff.h
tls_stream.o: ../../include/msg.h
tls_stream.o: ../../include/myaddrinfo.h
tls_stream.o: ../../include/name_code.h
tls_stream.o: ../../include/name_mask.h
tls_stream.o: ../../include/sock_addr.h
tls_stream.o: ../../include/sys_defs.h
tls_stream.o: ../../include/vbuf.h
tls_stream.o: ../../include/vstream.h
tls_stream.o: ../../include/vstring.h
tls_stream.o: tls.h
tls_stream.o: tls_stream.c
tls_verify.o: ../../include/argv.h
tls_verify.o: ../../include/check_arg.h
tls_verify.o: ../../include/dns.h
tls_verify.o: ../../include/msg.h
tls_verify.o: ../../include/myaddrinfo.h
tls_verify.o: ../../include/mymalloc.h
tls_verify.o: ../../include/name_code.h
tls_verify.o: ../../include/name_mask.h
tls_verify.o: ../../include/sock_addr.h
tls_verify.o: ../../include/stringops.h
tls_verify.o: ../../include/sys_defs.h
tls_verify.o: ../../include/vbuf.h
tls_verify.o: ../../include/vstream.h
tls_verify.o: ../../include/vstring.h
tls_verify.o: tls.h
tls_verify.o: tls_verify.c
