# The extension is built with cargo-pgrx; this file only names the one command that
# checks every claim of the README against a throwaway cluster. See tests/verify.sh.
#
#   make verify PG_CONFIG=/path/to/pg_config
#   make verify PG_CONFIG=/path/to/pg_config VERIFY_DRIVERS=1
#   make clean-machine                 # the same, inside a fresh container (PostgreSQL 18)
#   make clean-machine PG_MAJOR=19     # ... with the newest 19 from PGDG; CI runs both

PG_CONFIG ?= pg_config

.PHONY: verify clean-machine demo
demo:
	PG_CONFIG=$(PG_CONFIG) bash tests/demo.sh


verify:
	PG_CONFIG=$(PG_CONFIG) VERIFY_DRIVERS=$(VERIFY_DRIVERS) bash tests/verify.sh

clean-machine:
	PG_MAJOR=$(or $(PG_MAJOR),18) bash tests/clean-machine/run.sh
