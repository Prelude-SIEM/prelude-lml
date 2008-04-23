SUBDIRS = include

AM_CPPFLAGS = -I$(srcdir)/include/ -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@ @PCRE_CFLAGS@ @FAM_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

bin_PROGRAMS = prelude-lml
prelude_lml_LDADD = @LIBPRELUDE_LIBS@ @PCRE_LIBS@ @FAM_LIBS@ $(top_builddir)/libmissing/libmissing.la
prelude_lml_LDFLAGS = @LIBPRELUDE_LDFLAGS@ @FAM_LDFLAGS@ -export-dynamic \
        "-dlopen" $(top_builddir)/plugins/debug/debug.la \
        "-dlopen" $(top_builddir)/plugins/pcre/pcre.la

prelude_lml_SOURCES = 	\
        prelude-lml.c 	\
        udp-server.c 	\
        regex.c 	\
        log-entry.c 	\
	log-source.c	\
        log-plugins.c 	\
        lml-options.c 	\
        file-server.c 	\
        lml-alert.c

