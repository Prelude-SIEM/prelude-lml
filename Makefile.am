SUBDIRS = src plugins

preludeconfdir = $(configdir)
preludeconf_DATA = prelude-lml.conf plugins.rules

EXTRA_DIST = $(preludeconf_DATA) config.h \
             AUTHORS COPYING CREDITS INSTALL NEWS README \
             prelude.spec ChangeLog

nickel: distclean
	@find . -type f -name Makefile.in | xargs rm
	@rm -f aclocal.m4 config.* ltmain.sh install-sh configure stamp-h* missing mkinstalldirs
