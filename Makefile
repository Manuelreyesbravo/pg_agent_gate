# The extension is built with cargo-pgrx; this file only names the one command that
# checks every claim of the README against a throwaway cluster. See tests/verify.sh.
#
#   make verify PG_CONFIG=/path/to/pg_config
#   make verify PG_CONFIG=/path/to/pg_config VERIFY_DRIVERS=1
#   make clean-machine     # the same, inside a fresh container: tests/clean-machine/

PG_CONFIG ?= pg_config

.PHONY: verify clean-machine demo
demo:
	PG_CONFIG=$(PG_CONFIG) bash tests/demo.sh


verify:
	PG_CONFIG=$(PG_CONFIG) VERIFY_DRIVERS=$(VERIFY_DRIVERS) bash tests/verify.sh

clean-machine:
	bash tests/clean-machine/run.sh
