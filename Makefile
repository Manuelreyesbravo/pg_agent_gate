# The extension is built with cargo-pgrx; this file only names the one command that
# checks every claim of the README against a throwaway cluster. See tests/verify.sh.
#
#   make verify PG_CONFIG=/path/to/pg_config
#   make verify PG_CONFIG=/path/to/pg_config VERIFY_DRIVERS=1
#   make clean-machine                 # the same, inside a fresh container (PostgreSQL 18)
#   make clean-machine PG_MAJOR=19     # ... with the newest 19 from PGDG; CI runs both

PG_CONFIG ?= pg_config

.PHONY: verify clean-machine demo contrast transfer bench mcp docker-demo fuzz

# Container engine for docker-demo: docker, or override with DOCKER=podman.
DOCKER ?= docker
# psycopg 3 is the only dependency; uv fetches it without touching your environment.
# Python pinned to 3.13: a default free-threaded 3.14 has no psycopg-binary wheel yet.
bench:
	PG_CONFIG=$(PG_CONFIG) $(if $(shell command -v uv),uv run --python 3.13 --with 'psycopg[binary]' python,python3) tests/bench.py



demo:
	PG_CONFIG=$(PG_CONFIG) bash tests/demo.sh


# Fuzz the gate: generated and mutated adversarial SQL, checked from a superuser's side.
# FUZZ_ITERS and FUZZ_SEED tune it. Needs uv (or psycopg on PATH).
fuzz:
	PG_CONFIG=$(PG_CONFIG) bash tests/fuzz.sh


# What you remove, and what goes in its place: the same statement run by an ordinary
# connection (gone) and refused by the gate, and the rich verification the gate returns.
contrast:
	PG_CONFIG=$(PG_CONFIG) bash tests/contrast.sh


# What the pipe costs: the same data native (typed, binary) and forced through JSON, on a
# replica of a real workload. Needs node for the fidelity proof.
transfer:
	PG_CONFIG=$(PG_CONFIG) bash tests/transfer.sh


# A real MCP client, through gated-mcp, can only operate the gate. Needs node and bun.
mcp:
	PG_CONFIG=$(PG_CONFIG) bash tests/mcp.sh


# Run the demo with no Rust, cargo-pgrx or PostgreSQL installed locally: build a throwaway
# image that carries the extension and PostgreSQL, and run the with/without-gate demo in it.
docker-demo:
	$(DOCKER) build -t pg_agent_gate-demo .
	$(DOCKER) run --rm pg_agent_gate-demo


verify:
	PG_CONFIG=$(PG_CONFIG) VERIFY_DRIVERS=$(VERIFY_DRIVERS) bash tests/verify.sh

clean-machine:
	PG_MAJOR=$(or $(PG_MAJOR),18) bash tests/clean-machine/run.sh
