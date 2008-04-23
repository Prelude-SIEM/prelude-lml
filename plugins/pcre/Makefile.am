SUBDIRS = ruleset

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@ @PCRE_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

noinst_HEADERS = pcre-mod.h rule-object.h rule-regex.h value-container.h

pcre_la_SOURCES = pcre-mod.c rule-object.c rule-regex.c value-container.c
pcre_la_LDFLAGS = -module -avoid-version
pcredir = $(libdir)/prelude-lml
pcre_LTLIBRARIES = pcre.la
