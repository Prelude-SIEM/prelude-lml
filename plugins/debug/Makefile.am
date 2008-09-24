AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing -I$(top_builddir)/libmissing @LIBPRELUDE_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

debug_la_SOURCES = debug.c
debug_la_LDFLAGS = -module -avoid-version
debugdir = $(libdir)/prelude-lml
debug_LTLIBRARIES = debug.la
