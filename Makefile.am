ACLOCAL_AMFLAGS = -I m4 -I libmissing/m4
AUTOMAKE_OPTIONS = 1.8
SUBDIRS = libmissing plugins src

preludeconfdir = $(configdir)
EXTRA_DIST = plugins.rules prelude-lml.conf config.h \
             AUTHORS COPYING INSTALL NEWS README \
             prelude.spec ChangeLog

install-data-local:
	$(INSTALL) -m 700 -d $(DESTDIR)$(configdir)/metadata;							
	@if test -f $(DESTDIR)$(configdir)/prelude-lml.conf; then         					\
		echo "********************************************************************************"; 	\
                echo;                                                                                    	\
                echo "$(DESTDIR)$(configdir)/prelude-lml.conf already exist...";				\
                echo "Installing default configuration in $(DESTDIR)$(configdir)/prelude-lml.conf-dist";        \
                echo;                                                                                    	\
                echo "********************************************************************************"; 	\
		$(INSTALL) -m 600 $(top_srcdir)/prelude-lml.conf $(DESTDIR)$(configdir)/prelude-lml.conf-dist;  \
        else                                                                                             	\
                $(INSTALL) -m 600 $(top_srcdir)/prelude-lml.conf $(DESTDIR)$(configdir)/;                       \
        fi
	@if test -f $(DESTDIR)$(configdir)/plugins.rules; then         					\
		echo "********************************************************************************"; 	\
                echo;                                                                                    	\
                echo "$(DESTDIR)$(configdir)/plugins.rules already exist...";					\
                echo "Installing default configuration in $(DESTDIR)$(configdir)/plugins.rules-dist";	        \
                echo;                                                                                    	\
                echo "********************************************************************************"; 	\
		$(INSTALL) -m 600 $(top_srcdir)/plugins.rules $(DESTDIR)$(configdir)/plugins.rules-dist;	\
        else                                                                                             	\
		$(INSTALL) -m 600 $(top_srcdir)/plugins.rules $(DESTDIR)$(configdir)/;				\
        fi


uninstall-local:
	rm -f $(DESTDIR)$(configdir)/prelude-lml.conf;	\
	rm -f $(DESTDIR)$(configdir)/plugin.rules;
