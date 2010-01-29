SUBDIRS = include

AM_CPPFLAGS = -I$(srcdir)/include/ -I$(top_srcdir)/libmissing -I$(top_builddir)/libmissing -I$(top_srcdir)/libev @LIBPRELUDE_CFLAGS@ @PCRE_CFLAGS@ @ICU_CPPFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

bin_PROGRAMS = prelude-lml
prelude_lml_LDADD = @LIBPRELUDE_LIBS@ @PCRE_LIBS@ @ICU_LIBS@ $(top_builddir)/libev/libev.la $(top_builddir)/libmissing/libmissing.la $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB) $(LIBSOCKET) $(LTLIBICONV) $(LTLIBINTL) $(SERVENT_LIB)
prelude_lml_LDFLAGS = @LIBPRELUDE_LDFLAGS@ -export-dynamic \
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
        lml-alert.c	\
	lml-charset.c


-include $(top_srcdir)/git.mk
