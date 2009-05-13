if ENABLE_UNSUPPORTED_RULESETS

ruleset_DATA = \
        exim.rules              \
	ipso.rules		\
	zywall.rules		\
	zyxel.rules		

rulesetdir = $(configdir)/ruleset
EXTRA_DIST = $(ruleset_DATA)

endif

-include $(top_srcdir)/git.mk
