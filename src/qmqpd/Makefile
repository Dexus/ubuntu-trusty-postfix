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
SRCS	= qmqpd.c qmqpd_state.c qmqpd_peer.c
OBJS	= qmqpd.o qmqpd_state.o qmqpd_peer.o
HDRS	=
TESTSRC	=
DEFS	= -I. -I$(INC_DIR) -D$(SYSTYPE)
CFLAGS	= $(DEBUG) $(OPT) $(DEFS)
TESTPROG=
PROG	= qmqpd
INC_DIR	= ../../include
LIBS	= ../../lib/lib$(LIB_PREFIX)master$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PREFIX)global$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PREFIX)dns$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PREFIX)util$(LIB_SUFFIX)

.c.o:;	$(CC) $(CFLAGS) -c $*.c

$(PROG): $(OBJS) $(LIBS)
	$(CC) $(CFLAGS) $(SHLIB_RPATH) -o $@ $(OBJS) $(LIBS) $(SYSLIBS)

$(OBJS): ../../conf/makedefs.out

Makefile: Makefile.in
	cat ../../conf/makedefs.out $? >$@

test:	$(TESTPROG)

tests:

root_tests:

update: ../../libexec/$(PROG)

../../libexec/$(PROG): $(PROG)
	cp $(PROG) ../../libexec

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
	rm -f *.o *core $(PROG) $(TESTPROG) junk *.db *.out *.tmp
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
qmqpd.o: ../../include/argv.h
qmqpd.o: ../../include/attr.h
qmqpd.o: ../../include/check_arg.h
qmqpd.o: ../../include/cleanup_user.h
qmqpd.o: ../../include/debug_peer.h
qmqpd.o: ../../include/dict.h
qmqpd.o: ../../include/htable.h
qmqpd.o: ../../include/inet_proto.h
qmqpd.o: ../../include/input_transp.h
qmqpd.o: ../../include/iostuff.h
qmqpd.o: ../../include/lex_822.h
qmqpd.o: ../../include/mail_conf.h
qmqpd.o: ../../include/mail_date.h
qmqpd.o: ../../include/mail_params.h
qmqpd.o: ../../include/mail_proto.h
qmqpd.o: ../../include/mail_server.h
qmqpd.o: ../../include/mail_stream.h
qmqpd.o: ../../include/mail_version.h
qmqpd.o: ../../include/match_list.h
qmqpd.o: ../../include/match_parent_style.h
qmqpd.o: ../../include/msg.h
qmqpd.o: ../../include/myflock.h
qmqpd.o: ../../include/mymalloc.h
qmqpd.o: ../../include/namadr_list.h
qmqpd.o: ../../include/netstring.h
qmqpd.o: ../../include/nvtable.h
qmqpd.o: ../../include/quote_822_local.h
qmqpd.o: ../../include/quote_flags.h
qmqpd.o: ../../include/rec_type.h
qmqpd.o: ../../include/recipient_list.h
qmqpd.o: ../../include/record.h
qmqpd.o: ../../include/smtputf8.h
qmqpd.o: ../../include/sys_defs.h
qmqpd.o: ../../include/vbuf.h
qmqpd.o: ../../include/verp_sender.h
qmqpd.o: ../../include/vstream.h
qmqpd.o: ../../include/vstring.h
qmqpd.o: qmqpd.c
qmqpd.o: qmqpd.h
qmqpd_peer.o: ../../include/attr.h
qmqpd_peer.o: ../../include/check_arg.h
qmqpd_peer.o: ../../include/htable.h
qmqpd_peer.o: ../../include/inet_proto.h
qmqpd_peer.o: ../../include/iostuff.h
qmqpd_peer.o: ../../include/mail_params.h
qmqpd_peer.o: ../../include/mail_proto.h
qmqpd_peer.o: ../../include/mail_stream.h
qmqpd_peer.o: ../../include/msg.h
qmqpd_peer.o: ../../include/myaddrinfo.h
qmqpd_peer.o: ../../include/mymalloc.h
qmqpd_peer.o: ../../include/nvtable.h
qmqpd_peer.o: ../../include/sock_addr.h
qmqpd_peer.o: ../../include/split_at.h
qmqpd_peer.o: ../../include/stringops.h
qmqpd_peer.o: ../../include/sys_defs.h
qmqpd_peer.o: ../../include/valid_hostname.h
qmqpd_peer.o: ../../include/valid_mailhost_addr.h
qmqpd_peer.o: ../../include/vbuf.h
qmqpd_peer.o: ../../include/vstream.h
qmqpd_peer.o: ../../include/vstring.h
qmqpd_peer.o: qmqpd.h
qmqpd_peer.o: qmqpd_peer.c
qmqpd_state.o: ../../include/attr.h
qmqpd_state.o: ../../include/check_arg.h
qmqpd_state.o: ../../include/cleanup_user.h
qmqpd_state.o: ../../include/htable.h
qmqpd_state.o: ../../include/iostuff.h
qmqpd_state.o: ../../include/mail_proto.h
qmqpd_state.o: ../../include/mail_stream.h
qmqpd_state.o: ../../include/mymalloc.h
qmqpd_state.o: ../../include/nvtable.h
qmqpd_state.o: ../../include/sys_defs.h
qmqpd_state.o: ../../include/vbuf.h
qmqpd_state.o: ../../include/vstream.h
qmqpd_state.o: ../../include/vstring.h
qmqpd_state.o: qmqpd.h
qmqpd_state.o: qmqpd_state.c
