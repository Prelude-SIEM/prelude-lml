SUBDIRS = include


AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @defined@ 	\
	-DLOG_PLUGIN_DIR=\"@log_plugin_dir@\" -DREGEX_CONF=\"@regex_conf@\" 			\
	-DCONFIG_DIR=\"@configdir@\" -D_FILE_OFFSET_BITS=64 					\
	-DLOCALSTATEDIR=\"@localstatedir@\" @LIBPRELUDE_CFLAGS@ @PCRE_CFLAGS@

bin_PROGRAMS = prelude-lml
prelude_lml_LDADD = @LIBPRELUDE_LIBS@ @PCRE_LIBS@ $(top_builddir)/libmissing/libmissing.la
prelude_lml_LDFLAGS = @LIBPRELUDE_LDFLAGS@ -export-dynamic 	\
	"-dlopen" $(top_builddir)/plugins/debug/debug.la   	\
	"-dlopen" $(top_builddir)/plugins/simple/simple.la

prelude_lml_SOURCES = 			\
	main.c				\
	udp-server.c			\
	regex.c				\
	log-common.c			\
	log-plugins.c			\
	pconfig.c			\
	file-server.c			\
	lml-alert.c




