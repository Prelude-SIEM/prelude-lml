SUBDIRS = include

DEFS = -I$(top_srcdir)/ -I$(srcdir)/include @defined@ -DLOG_PLUGIN_DIR=\"@log_plugin_dir@\" \
	-DREGEX_CONF=\"@regex_conf@\" -DCONFIG_DIR=\"@configdir@\"        \
	-DLOCALSTATEDIR=\"@localstatedir@\" @LIBPRELUDE_CFLAGS@ @PCRE_CFLAGS@

bin_PROGRAMS = prelude-lml

prelude_lml_LDFLAGS = -export-dynamic
prelude_lml_LDADD = @LIBPRELUDE_LIBS@ @PCRE_LIBS@

prelude_lml_SOURCES = 			\
	main.c				\
	udp-server.c			\
	queue.c				\
	regex.c				\
	hashkey.c			\
	log-common.c			\
	log-plugins.c			\
	pconfig.c			\
	file-server.c			\
	server-logic.c




