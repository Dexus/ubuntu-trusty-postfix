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
SRCS	= bounce.c bounce_append_service.c bounce_notify_service.c \
	bounce_cleanup.c bounce_notify_util.c bounce_notify_verp.c \
	bounce_one_service.c bounce_warn_service.c bounce_trace_service.c \
	bounce_template.c bounce_templates.c
OBJS	= bounce.o bounce_append_service.o bounce_notify_service.o \
	bounce_cleanup.o bounce_notify_util.o bounce_notify_verp.o \
	bounce_one_service.o bounce_warn_service.o bounce_trace_service.o \
	bounce_template.o bounce_templates.o
HDRS	= 
TESTSRC	= 
DEFS	= -I. -I$(INC_DIR) -D$(SYSTYPE)
CFLAGS	= $(DEBUG) $(OPT) $(DEFS)
TESTPROG=
PROG	= bounce
SAMPLES	= ../../conf/bounce.cf.default
INC_DIR	= ../../include
LIBS	= ../../lib/lib$(LIB_PREFIX)master$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PREFIX)global$(LIB_SUFFIX) \
	../../lib/lib$(LIB_PREFIX)util$(LIB_SUFFIX)

.c.o:;  $(CC) $(CFLAGS) -c $*.c

all:	$(PROG) ../../conf/bounce.cf.default

$(PROG):	$(OBJS) $(LIBS)
	$(CC) $(CFLAGS) $(SHLIB_RPATH) -o $@ $(OBJS) $(LIBS) $(SYSLIBS)

# Eliminate dependency on installed Postfix.
../../conf/bounce.cf.default: template_test.ref annotate.sh
	rm -f $@
	./annotate.sh <template_test.ref >$@

main.cf:
	echo queue_directory=. >main.cf
	echo myhostname=example.com >>main.cf

$(OBJS): ../../conf/makedefs.out

Makefile: Makefile.in
	cat ../../conf/makedefs.out $? >$@

test:	$(TESTPROG)

tests:	update template_test 2template_test

root_tests:

update: ../../libexec/$(PROG) $(SAMPLES)

../../libexec/$(PROG): $(PROG)
	cp $(PROG) ../../libexec

printfck: $(OBJS) $(PROG)
	rm -rf printfck
	mkdir printfck
	cp *.h printfck
	sed '1,/^# do not edit/!d' Makefile > printfck/Makefile
	set -e; for i in *.c; do printfck -f .printfck $$i >printfck/$$i; done
	cd printfck; make "INC_DIR=../../../include" `cd ..; ls *.o`

lint:
	lint $(DEFS) $(SRCS) $(LINTFIX)

clean:
	rm -f *.o *core $(PROG) $(TESTPROG) junk main.cf
	rm -rf printfck

tidy:	clean

# Avoid dependency on installed Postfix.
# XXX This still requires that default_privs, mail_owner etc. accounts exist.
template_test: $(PROG) main.cf template_test.ref
	MAIL_CONFIG=. ./$(PROG) -SVzndump_templates >template_test.tmp
	diff template_test.ref template_test.tmp
	MAIL_CONFIG=. ./$(PROG) -SVzndump_templates \
	    -o bounce_template_file=template_test.ref > template_test.tmp
	diff template_test.ref template_test.tmp
	rm -f template_test.tmp

2template_test: $(PROG) main.cf template_test.ref 2template_test.in
	MAIL_CONFIG=. ./$(PROG) -SVzndump_templates \
	    -o bounce_template_file=2template_test.in > template_test.tmp
	diff template_test.ref template_test.tmp
	rm -f template_test.tmp

depend: $(MAKES)
	(sed '1,/^# do not edit/!d' Makefile.in; \
	set -e; for i in [a-z][a-z0-9]*.c; do \
	    $(CC) -E $(DEFS) $(INCL) $$i | grep -v '[<>]' | sed -n -e '/^# *1 *"\([^"]*\)".*/{' \
	    -e 's//'`echo $$i|sed 's/c$$/o/'`': \1/' \
	    -e 's/o: \.\//o: /' -e p -e '}' ; \
	done | sort -u) | grep -v '[.][o][:][ ][/]' >$$$$ && mv $$$$ Makefile.in
	@$(EXPORT) make -f Makefile.in Makefile 1>&2

# do not edit below this line - it is generated by 'make depend'
bounce.o: ../../include/attr.h
bounce.o: ../../include/bounce.h
bounce.o: ../../include/bounce_log.h
bounce.o: ../../include/check_arg.h
bounce.o: ../../include/deliver_request.h
bounce.o: ../../include/dsb_scan.h
bounce.o: ../../include/dsn.h
bounce.o: ../../include/dsn_buf.h
bounce.o: ../../include/htable.h
bounce.o: ../../include/iostuff.h
bounce.o: ../../include/load_file.h
bounce.o: ../../include/mail_addr.h
bounce.o: ../../include/mail_conf.h
bounce.o: ../../include/mail_params.h
bounce.o: ../../include/mail_proto.h
bounce.o: ../../include/mail_queue.h
bounce.o: ../../include/mail_server.h
bounce.o: ../../include/mail_version.h
bounce.o: ../../include/msg.h
bounce.o: ../../include/msg_stats.h
bounce.o: ../../include/mymalloc.h
bounce.o: ../../include/nvtable.h
bounce.o: ../../include/rcpt_buf.h
bounce.o: ../../include/recipient_list.h
bounce.o: ../../include/stringops.h
bounce.o: ../../include/sys_defs.h
bounce.o: ../../include/vbuf.h
bounce.o: ../../include/vstream.h
bounce.o: ../../include/vstring.h
bounce.o: bounce.c
bounce.o: bounce_service.h
bounce.o: bounce_template.h
bounce_append_service.o: ../../include/attr.h
bounce_append_service.o: ../../include/bounce_log.h
bounce_append_service.o: ../../include/check_arg.h
bounce_append_service.o: ../../include/deliver_flock.h
bounce_append_service.o: ../../include/dsn.h
bounce_append_service.o: ../../include/dsn_buf.h
bounce_append_service.o: ../../include/htable.h
bounce_append_service.o: ../../include/iostuff.h
bounce_append_service.o: ../../include/mail_params.h
bounce_append_service.o: ../../include/mail_proto.h
bounce_append_service.o: ../../include/mail_queue.h
bounce_append_service.o: ../../include/msg.h
bounce_append_service.o: ../../include/myflock.h
bounce_append_service.o: ../../include/mymalloc.h
bounce_append_service.o: ../../include/nvtable.h
bounce_append_service.o: ../../include/quote_822_local.h
bounce_append_service.o: ../../include/quote_flags.h
bounce_append_service.o: ../../include/rcpt_buf.h
bounce_append_service.o: ../../include/recipient_list.h
bounce_append_service.o: ../../include/stringops.h
bounce_append_service.o: ../../include/sys_defs.h
bounce_append_service.o: ../../include/vbuf.h
bounce_append_service.o: ../../include/vstream.h
bounce_append_service.o: ../../include/vstring.h
bounce_append_service.o: bounce_append_service.c
bounce_append_service.o: bounce_service.h
bounce_append_service.o: bounce_template.h
bounce_cleanup.o: ../../include/attr.h
bounce_cleanup.o: ../../include/bounce_log.h
bounce_cleanup.o: ../../include/check_arg.h
bounce_cleanup.o: ../../include/dsn.h
bounce_cleanup.o: ../../include/dsn_buf.h
bounce_cleanup.o: ../../include/htable.h
bounce_cleanup.o: ../../include/mail_queue.h
bounce_cleanup.o: ../../include/msg.h
bounce_cleanup.o: ../../include/mymalloc.h
bounce_cleanup.o: ../../include/nvtable.h
bounce_cleanup.o: ../../include/rcpt_buf.h
bounce_cleanup.o: ../../include/recipient_list.h
bounce_cleanup.o: ../../include/sys_defs.h
bounce_cleanup.o: ../../include/vbuf.h
bounce_cleanup.o: ../../include/vstream.h
bounce_cleanup.o: ../../include/vstring.h
bounce_cleanup.o: bounce_cleanup.c
bounce_cleanup.o: bounce_service.h
bounce_cleanup.o: bounce_template.h
bounce_notify_service.o: ../../include/attr.h
bounce_notify_service.o: ../../include/bounce.h
bounce_notify_service.o: ../../include/bounce_log.h
bounce_notify_service.o: ../../include/check_arg.h
bounce_notify_service.o: ../../include/cleanup_user.h
bounce_notify_service.o: ../../include/deliver_request.h
bounce_notify_service.o: ../../include/dsn.h
bounce_notify_service.o: ../../include/dsn_buf.h
bounce_notify_service.o: ../../include/dsn_mask.h
bounce_notify_service.o: ../../include/htable.h
bounce_notify_service.o: ../../include/int_filt.h
bounce_notify_service.o: ../../include/iostuff.h
bounce_notify_service.o: ../../include/mail_addr.h
bounce_notify_service.o: ../../include/mail_error.h
bounce_notify_service.o: ../../include/mail_params.h
bounce_notify_service.o: ../../include/mail_proto.h
bounce_notify_service.o: ../../include/mail_queue.h
bounce_notify_service.o: ../../include/msg.h
bounce_notify_service.o: ../../include/msg_stats.h
bounce_notify_service.o: ../../include/mymalloc.h
bounce_notify_service.o: ../../include/name_mask.h
bounce_notify_service.o: ../../include/nvtable.h
bounce_notify_service.o: ../../include/post_mail.h
bounce_notify_service.o: ../../include/rcpt_buf.h
bounce_notify_service.o: ../../include/rec_type.h
bounce_notify_service.o: ../../include/recipient_list.h
bounce_notify_service.o: ../../include/smtputf8.h
bounce_notify_service.o: ../../include/stringops.h
bounce_notify_service.o: ../../include/sys_defs.h
bounce_notify_service.o: ../../include/vbuf.h
bounce_notify_service.o: ../../include/vstream.h
bounce_notify_service.o: ../../include/vstring.h
bounce_notify_service.o: bounce_notify_service.c
bounce_notify_service.o: bounce_service.h
bounce_notify_service.o: bounce_template.h
bounce_notify_util.o: ../../include/attr.h
bounce_notify_util.o: ../../include/bounce_log.h
bounce_notify_util.o: ../../include/check_arg.h
bounce_notify_util.o: ../../include/cleanup_user.h
bounce_notify_util.o: ../../include/deliver_completed.h
bounce_notify_util.o: ../../include/dsn.h
bounce_notify_util.o: ../../include/dsn_buf.h
bounce_notify_util.o: ../../include/dsn_mask.h
bounce_notify_util.o: ../../include/events.h
bounce_notify_util.o: ../../include/htable.h
bounce_notify_util.o: ../../include/int_filt.h
bounce_notify_util.o: ../../include/iostuff.h
bounce_notify_util.o: ../../include/is_header.h
bounce_notify_util.o: ../../include/lex_822.h
bounce_notify_util.o: ../../include/line_wrap.h
bounce_notify_util.o: ../../include/mail_addr.h
bounce_notify_util.o: ../../include/mail_date.h
bounce_notify_util.o: ../../include/mail_error.h
bounce_notify_util.o: ../../include/mail_params.h
bounce_notify_util.o: ../../include/mail_proto.h
bounce_notify_util.o: ../../include/mail_queue.h
bounce_notify_util.o: ../../include/msg.h
bounce_notify_util.o: ../../include/myflock.h
bounce_notify_util.o: ../../include/mymalloc.h
bounce_notify_util.o: ../../include/name_mask.h
bounce_notify_util.o: ../../include/nvtable.h
bounce_notify_util.o: ../../include/post_mail.h
bounce_notify_util.o: ../../include/quote_822_local.h
bounce_notify_util.o: ../../include/quote_flags.h
bounce_notify_util.o: ../../include/rcpt_buf.h
bounce_notify_util.o: ../../include/rec_type.h
bounce_notify_util.o: ../../include/recipient_list.h
bounce_notify_util.o: ../../include/record.h
bounce_notify_util.o: ../../include/smtputf8.h
bounce_notify_util.o: ../../include/stringops.h
bounce_notify_util.o: ../../include/sys_defs.h
bounce_notify_util.o: ../../include/vbuf.h
bounce_notify_util.o: ../../include/vstream.h
bounce_notify_util.o: ../../include/vstring.h
bounce_notify_util.o: bounce_notify_util.c
bounce_notify_util.o: bounce_service.h
bounce_notify_util.o: bounce_template.h
bounce_notify_verp.o: ../../include/attr.h
bounce_notify_verp.o: ../../include/bounce.h
bounce_notify_verp.o: ../../include/bounce_log.h
bounce_notify_verp.o: ../../include/check_arg.h
bounce_notify_verp.o: ../../include/cleanup_user.h
bounce_notify_verp.o: ../../include/deliver_request.h
bounce_notify_verp.o: ../../include/dsn.h
bounce_notify_verp.o: ../../include/dsn_buf.h
bounce_notify_verp.o: ../../include/dsn_mask.h
bounce_notify_verp.o: ../../include/htable.h
bounce_notify_verp.o: ../../include/int_filt.h
bounce_notify_verp.o: ../../include/iostuff.h
bounce_notify_verp.o: ../../include/mail_addr.h
bounce_notify_verp.o: ../../include/mail_error.h
bounce_notify_verp.o: ../../include/mail_params.h
bounce_notify_verp.o: ../../include/mail_proto.h
bounce_notify_verp.o: ../../include/mail_queue.h
bounce_notify_verp.o: ../../include/msg.h
bounce_notify_verp.o: ../../include/msg_stats.h
bounce_notify_verp.o: ../../include/mymalloc.h
bounce_notify_verp.o: ../../include/name_mask.h
bounce_notify_verp.o: ../../include/nvtable.h
bounce_notify_verp.o: ../../include/post_mail.h
bounce_notify_verp.o: ../../include/rcpt_buf.h
bounce_notify_verp.o: ../../include/rec_type.h
bounce_notify_verp.o: ../../include/recipient_list.h
bounce_notify_verp.o: ../../include/smtputf8.h
bounce_notify_verp.o: ../../include/stringops.h
bounce_notify_verp.o: ../../include/sys_defs.h
bounce_notify_verp.o: ../../include/vbuf.h
bounce_notify_verp.o: ../../include/verp_sender.h
bounce_notify_verp.o: ../../include/vstream.h
bounce_notify_verp.o: ../../include/vstring.h
bounce_notify_verp.o: bounce_notify_verp.c
bounce_notify_verp.o: bounce_service.h
bounce_notify_verp.o: bounce_template.h
bounce_one_service.o: ../../include/attr.h
bounce_one_service.o: ../../include/bounce.h
bounce_one_service.o: ../../include/bounce_log.h
bounce_one_service.o: ../../include/check_arg.h
bounce_one_service.o: ../../include/cleanup_user.h
bounce_one_service.o: ../../include/deliver_request.h
bounce_one_service.o: ../../include/dsn.h
bounce_one_service.o: ../../include/dsn_buf.h
bounce_one_service.o: ../../include/dsn_mask.h
bounce_one_service.o: ../../include/htable.h
bounce_one_service.o: ../../include/int_filt.h
bounce_one_service.o: ../../include/iostuff.h
bounce_one_service.o: ../../include/mail_addr.h
bounce_one_service.o: ../../include/mail_error.h
bounce_one_service.o: ../../include/mail_params.h
bounce_one_service.o: ../../include/mail_proto.h
bounce_one_service.o: ../../include/msg.h
bounce_one_service.o: ../../include/msg_stats.h
bounce_one_service.o: ../../include/mymalloc.h
bounce_one_service.o: ../../include/name_mask.h
bounce_one_service.o: ../../include/nvtable.h
bounce_one_service.o: ../../include/post_mail.h
bounce_one_service.o: ../../include/rcpt_buf.h
bounce_one_service.o: ../../include/rec_type.h
bounce_one_service.o: ../../include/recipient_list.h
bounce_one_service.o: ../../include/smtputf8.h
bounce_one_service.o: ../../include/stringops.h
bounce_one_service.o: ../../include/sys_defs.h
bounce_one_service.o: ../../include/vbuf.h
bounce_one_service.o: ../../include/vstream.h
bounce_one_service.o: ../../include/vstring.h
bounce_one_service.o: bounce_one_service.c
bounce_one_service.o: bounce_service.h
bounce_one_service.o: bounce_template.h
bounce_template.o: ../../include/attr.h
bounce_template.o: ../../include/check_arg.h
bounce_template.o: ../../include/htable.h
bounce_template.o: ../../include/iostuff.h
bounce_template.o: ../../include/is_header.h
bounce_template.o: ../../include/mac_expand.h
bounce_template.o: ../../include/mac_parse.h
bounce_template.o: ../../include/mail_conf.h
bounce_template.o: ../../include/mail_params.h
bounce_template.o: ../../include/mail_proto.h
bounce_template.o: ../../include/midna_domain.h
bounce_template.o: ../../include/msg.h
bounce_template.o: ../../include/mymalloc.h
bounce_template.o: ../../include/nvtable.h
bounce_template.o: ../../include/split_at.h
bounce_template.o: ../../include/stringops.h
bounce_template.o: ../../include/sys_defs.h
bounce_template.o: ../../include/vbuf.h
bounce_template.o: ../../include/vstream.h
bounce_template.o: ../../include/vstring.h
bounce_template.o: bounce_template.c
bounce_template.o: bounce_template.h
bounce_templates.o: ../../include/attr.h
bounce_templates.o: ../../include/check_arg.h
bounce_templates.o: ../../include/htable.h
bounce_templates.o: ../../include/iostuff.h
bounce_templates.o: ../../include/mail_addr.h
bounce_templates.o: ../../include/mail_proto.h
bounce_templates.o: ../../include/msg.h
bounce_templates.o: ../../include/mymalloc.h
bounce_templates.o: ../../include/nvtable.h
bounce_templates.o: ../../include/stringops.h
bounce_templates.o: ../../include/sys_defs.h
bounce_templates.o: ../../include/vbuf.h
bounce_templates.o: ../../include/vstream.h
bounce_templates.o: ../../include/vstring.h
bounce_templates.o: ../../include/vstring_vstream.h
bounce_templates.o: bounce_template.h
bounce_templates.o: bounce_templates.c
bounce_trace_service.o: ../../include/attr.h
bounce_trace_service.o: ../../include/bounce_log.h
bounce_trace_service.o: ../../include/check_arg.h
bounce_trace_service.o: ../../include/cleanup_user.h
bounce_trace_service.o: ../../include/deliver_request.h
bounce_trace_service.o: ../../include/dsn.h
bounce_trace_service.o: ../../include/dsn_buf.h
bounce_trace_service.o: ../../include/dsn_mask.h
bounce_trace_service.o: ../../include/htable.h
bounce_trace_service.o: ../../include/int_filt.h
bounce_trace_service.o: ../../include/iostuff.h
bounce_trace_service.o: ../../include/mail_addr.h
bounce_trace_service.o: ../../include/mail_error.h
bounce_trace_service.o: ../../include/mail_params.h
bounce_trace_service.o: ../../include/mail_proto.h
bounce_trace_service.o: ../../include/mail_queue.h
bounce_trace_service.o: ../../include/msg.h
bounce_trace_service.o: ../../include/msg_stats.h
bounce_trace_service.o: ../../include/mymalloc.h
bounce_trace_service.o: ../../include/name_mask.h
bounce_trace_service.o: ../../include/nvtable.h
bounce_trace_service.o: ../../include/post_mail.h
bounce_trace_service.o: ../../include/rcpt_buf.h
bounce_trace_service.o: ../../include/rec_type.h
bounce_trace_service.o: ../../include/recipient_list.h
bounce_trace_service.o: ../../include/smtputf8.h
bounce_trace_service.o: ../../include/stringops.h
bounce_trace_service.o: ../../include/sys_defs.h
bounce_trace_service.o: ../../include/vbuf.h
bounce_trace_service.o: ../../include/vstream.h
bounce_trace_service.o: ../../include/vstring.h
bounce_trace_service.o: bounce_service.h
bounce_trace_service.o: bounce_template.h
bounce_trace_service.o: bounce_trace_service.c
bounce_warn_service.o: ../../include/attr.h
bounce_warn_service.o: ../../include/bounce_log.h
bounce_warn_service.o: ../../include/check_arg.h
bounce_warn_service.o: ../../include/cleanup_user.h
bounce_warn_service.o: ../../include/dsn.h
bounce_warn_service.o: ../../include/dsn_buf.h
bounce_warn_service.o: ../../include/dsn_mask.h
bounce_warn_service.o: ../../include/htable.h
bounce_warn_service.o: ../../include/int_filt.h
bounce_warn_service.o: ../../include/iostuff.h
bounce_warn_service.o: ../../include/mail_addr.h
bounce_warn_service.o: ../../include/mail_error.h
bounce_warn_service.o: ../../include/mail_params.h
bounce_warn_service.o: ../../include/mail_proto.h
bounce_warn_service.o: ../../include/mail_queue.h
bounce_warn_service.o: ../../include/msg.h
bounce_warn_service.o: ../../include/mymalloc.h
bounce_warn_service.o: ../../include/name_mask.h
bounce_warn_service.o: ../../include/nvtable.h
bounce_warn_service.o: ../../include/post_mail.h
bounce_warn_service.o: ../../include/rcpt_buf.h
bounce_warn_service.o: ../../include/rec_type.h
bounce_warn_service.o: ../../include/recipient_list.h
bounce_warn_service.o: ../../include/smtputf8.h
bounce_warn_service.o: ../../include/stringops.h
bounce_warn_service.o: ../../include/sys_defs.h
bounce_warn_service.o: ../../include/vbuf.h
bounce_warn_service.o: ../../include/vstream.h
bounce_warn_service.o: ../../include/vstring.h
bounce_warn_service.o: bounce_service.h
bounce_warn_service.o: bounce_template.h
bounce_warn_service.o: bounce_warn_service.c
