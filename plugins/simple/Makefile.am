SUBDIRS = ruleset

DEFS = @defined@
INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src/include 

simple_la_SOURCES = simple.c
simple_la_LDFLAGS = -module -avoid-version
simpledir = $(log_plugin_dir)
simple_LTLIBRARIES = simple.la
