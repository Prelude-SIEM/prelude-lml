SUBDIRS = ruleset
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @defined@

simple_la_SOURCES = simple.c
simple_la_LDFLAGS = -module -avoid-version
simpledir = $(log_plugin_dir)
simple_LTLIBRARIES = simple.la
