SUBDIRS = src plugins

preludeconfdir = $(configdir)
preludeconf_DATA = plugins.rules prelude-lml.conf

EXTRA_DIST = $(preludeconf_DATA) config.h \
             AUTHORS COPYING CREDITS INSTALL NEWS README \
             prelude.spec ChangeLog

install-data-local:        
	@if test -f $(configdir)/prelude-lml.conf; then                                                  \
		echo "********************************************************************************"; \
                echo;                                                                                    \
                echo "$(configdir)/prelude-lml.conf already exist...";                                   \
                echo "Installing default configuration in $(configdir)/prelude-lml.conf-dist";           \
                echo;                                                                                    \
                echo "********************************************************************************"; \
		$(INSTALL) $(top_srcdir)/prelude-lml.conf $(configdir)/prelude-lml.conf-dist;            \
        else                                                                                             \
                $(INSTALL) -m 600 $(top_srcdir)/prelude-lml.conf $(configdir)/;                          \
        fi


nickel: distclean
	@find . -type f -name Makefile.in | xargs rm
	@rm -f aclocal.m4 config.* ltmain.sh install-sh configure stamp-h* missing mkinstalldirs
