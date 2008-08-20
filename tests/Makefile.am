EXTRA_DIST = loggrep.py prelude-lml.conf ignored

$(top_srcdir)/prelude-lml:
	cd $(top_srcdir)/prelude-lml && make

check-am:
	$(top_srcdir)/src/prelude-lml --quiet --dry-run --metadata=nowrite,head --batch-mode --no-resolve --pcre --dump-unmatched --config $(srcdir)/prelude-lml.conf 2>&1 | $(GREP) -Fvf ignored
