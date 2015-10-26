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
SRCS	= postalias.c 
OBJS	= postalias.o 
HDRS	= 
TESTSRC	= 
DEFS	= -I. -I$(INC_DIR) -D$(SYSTYPE)
CFLAGS	= $(DEBUG) $(OPT) $(DEFS)
TESTPROG= 
PROG	= postalias
INC_DIR	= ../../include
LIBS	= ../../lib/lib$(LIB_PREFIX)global$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PREFIX)util$(LIB_SUFFIX)

.c.o:;	$(CC) $(CFLAGS) -c $*.c

$(PROG): $(OBJS) $(LIBS)
	$(CC) $(CFLAGS) $(SHLIB_RPATH) -o $@ $(OBJS) $(LIBS) $(SYSLIBS)

$(OBJS): ../../conf/makedefs.out

Makefile: Makefile.in
	cat ../../conf/makedefs.out $? >$@

update: ../../bin/$(PROG)

tests:	test1 test2 fail_test

root_tests:

test1:	$(PROG) map.in map-abc1.ref map-ghi1.ref map-uABC1.ref
	./$(PROG) map.in
	for key in abc ghi; \
	do \
	    ./$(PROG) -q $${key} map.in | diff map-$${key}1.ref -; \
	done
	./$(PROG) -f map.in
	for key in ABC; \
	do \
	    ./$(PROG) -fq $${key} map.in | diff map-u$${key}1.ref -; \
	done
	rm -f map.in.db

test2:	$(PROG) map.in map-abc2.ref map-ghi2.ref map-uABC2.ref
	./$(PROG) map.in
	for key in abc ghi; \
	do \
	    echo $${key} | ./$(PROG) -q - map.in | diff map-$${key}2.ref -; \
	done
	./$(PROG) -f map.in
	for key in ABC; \
	do \
	    echo $${key} | ./$(PROG) -fq - map.in | diff map-u$${key}2.ref -; \
	done
	rm -f map.in.db

fail_test: $(PROG) aliases fail_test.in fail_test.ref
	-(sh fail_test.in 2>&1 || exit 0) | sed 's/No error:/Unknown error:/' > fail_test.tmp
	diff fail_test.ref fail_test.tmp
	rm -f fail_test.tmp

../../bin/$(PROG): $(PROG)
	cp $(PROG) ../../bin

printfck: $(OBJS) $(PROG)
	rm -rf printfck
	mkdir printfck
	sed '1,/^# do not edit/!d' Makefile >printfck/Makefile
	set -e; for i in *.c; do printfck -f .printfck $$i >printfck/$$i; done
	cd printfck; make "INC_DIR=../../../include" `cd ..; ls *.o`

lint:
	lint $(DEFS) $(SRCS) $(LINTFIX)

clean:
	rm -f *.o *core $(PROG) $(TESTPROG) junk 
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
postalias.o: ../../include/argv.h
postalias.o: ../../include/check_arg.h
postalias.o: ../../include/dict.h
postalias.o: ../../include/dict_proxy.h
postalias.o: ../../include/mail_conf.h
postalias.o: ../../include/mail_dict.h
postalias.o: ../../include/mail_params.h
postalias.o: ../../include/mail_task.h
postalias.o: ../../include/mail_version.h
postalias.o: ../../include/mkmap.h
postalias.o: ../../include/msg.h
postalias.o: ../../include/msg_syslog.h
postalias.o: ../../include/msg_vstream.h
postalias.o: ../../include/myflock.h
postalias.o: ../../include/mymalloc.h
postalias.o: ../../include/readlline.h
postalias.o: ../../include/resolve_clnt.h
postalias.o: ../../include/set_eugid.h
postalias.o: ../../include/split_at.h
postalias.o: ../../include/stringops.h
postalias.o: ../../include/sys_defs.h
postalias.o: ../../include/tok822.h
postalias.o: ../../include/vbuf.h
postalias.o: ../../include/vstream.h
postalias.o: ../../include/vstring.h
postalias.o: ../../include/vstring_vstream.h
postalias.o: ../../include/warn_stat.h
postalias.o: postalias.c
