SUBDIRS = ruleset
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @defined@

noinst_HEADERS = pcre-mod.h rule-object.c rule-regex.h

pcre_la_SOURCES = pcre-mod.c rule-object.c rule-regex.c
pcre_la_LDFLAGS = -module -avoid-version
pcredir = $(log_plugin_dir)
pcre_LTLIBRARIES = pcre.la
