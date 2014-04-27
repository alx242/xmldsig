PROJECT = xmldsig

include erlang.mk

# Possibly want to switch out xmerl for erlsom...
#
# DEPS = erlsom
# dep_erlsom = https://github.com/willemdj/erlsom.git

# Using some deprecated stuff so I killed off the warnings as errors
ERLC_OPTS = +debug_info +warn_export_all +warn_export_vars \
	+warn_shadow_vars +warn_obsolete_guard

shell:
	erl -pa ../xmldsig/ebin/

eunit:
	erl -noshell -pa ../xmldsig/ebin/ -pa ../xmldsig/test -eval \
	"eunit:test(xmldsig_tests, [verbose])" \
	-s init stop


