EXTRA_DIST = loggrep.py prelude-lml.conf

$(top_srcdir)/prelude-lml:
	cd $(top_srcdir)/prelude-lml && make

all:
	@echo "You might want to run run 'make tests'"

tests:
	$(srcdir)/loggrep.py $(top_srcdir)/plugins/pcre/ruleset/*.rules | $(top_srcdir)/src/prelude-lml --dry-run --ignore-metadata --batch-mode --no-resolve --pcre --dump-unmatched --config $(srcdir)/prelude-lml.conf
