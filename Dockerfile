# Run the demo with no Rust on your side. A multi-stage build: the first stage has Rust and
# cargo-pgrx and compiles the extension; the image you actually run has only PostgreSQL and
# the built extension, and `make demo` as its entrypoint -- the same with/without-gate demo
# as `make demo` on a workstation, in a throwaway container.
#
#   docker build -t pg_agent_gate-demo .
#   docker run --rm pg_agent_gate-demo
#
# or just `make docker-demo`. PostgreSQL is pinned by PG_MAJOR; pgrx by PGRX_VERSION.
ARG PG_MAJOR=18
ARG PGRX_VERSION=0.19.2

# ---------------------------------------------------------------- builder (has the toolchain)
FROM docker.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS builder
ARG PG_MAJOR
ARG PGRX_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && install -d /usr/share/postgresql-common/pgdg \
 && curl -fsSo /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
      https://www.postgresql.org/media/keys/ACCC4CF8.asc \
 && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main $PG_MAJOR" \
      > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      postgresql-$PG_MAJOR postgresql-server-dev-$PG_MAJOR \
      build-essential clang libclang-dev pkg-config git make \
 && rm -rf /var/lib/apt/lists/*
ENV PATH=/root/.cargo/bin:/usr/lib/postgresql/$PG_MAJOR/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.0
RUN cargo install cargo-pgrx --version "$PGRX_VERSION" --locked
RUN cargo pgrx init --pg$PG_MAJOR /usr/lib/postgresql/$PG_MAJOR/bin/pg_config
COPY . /src
WORKDIR /src
RUN cargo pgrx package --pg-config /usr/lib/postgresql/$PG_MAJOR/bin/pg_config

# ---------------------------------------------------------------- runtime (no toolchain)
FROM docker.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime
ARG PG_MAJOR
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl make bash \
 && install -d /usr/share/postgresql-common/pgdg \
 && curl -fsSo /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
      https://www.postgresql.org/media/keys/ACCC4CF8.asc \
 && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main $PG_MAJOR" \
      > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends postgresql-$PG_MAJOR \
 && rm -rf /var/lib/apt/lists/*
# initdb refuses to run as root, and a stranger would not run it as root either.
RUN useradd -m demo
# Only what the demo needs: the scripts, the Makefile, and the built extension -- not the
# build cache and not the toolchain.
COPY --from=builder --chown=demo:demo /src/tests   /home/demo/pg_agent_gate/tests
COPY --from=builder --chown=demo:demo /src/Makefile /home/demo/pg_agent_gate/Makefile
COPY --from=builder --chown=demo:demo /src/target/release/pg_agent_gate-pg${PG_MAJOR} /home/demo/pg_agent_gate/target/release/pg_agent_gate-pg${PG_MAJOR}
USER demo
WORKDIR /home/demo/pg_agent_gate
ENV USER=demo \
    PATH=/usr/lib/postgresql/${PG_MAJOR}/bin:$PATH \
    PG_CONFIG=/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config
# The with/without-gate demo. Override the command to run something else in the image.
ENTRYPOINT ["make", "demo"]
