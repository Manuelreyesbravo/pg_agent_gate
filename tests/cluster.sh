#!/usr/bin/env bash
# A throwaway cluster built from the binaries of the PostgreSQL the extension
# will be installed into (PG_CONFIG), loading pg_agent_gate from the output of
# `cargo pgrx package` -- nothing is installed into that PostgreSQL.
#
# Why not the pgrx development instance: it is built with --enable-cassert,
# which inflates every server-side cost, and it is not what gets installed.
#
#   tests/cluster.sh package             build the release artifact for PG_CONFIG
#   tests/cluster.sh init                fresh data directory
#   tests/cluster.sh start [preload|bare]   bare = without the library preloaded
#   tests/cluster.sh stop [fast|immediate]  immediate = no checkpoint, like a crash
#   tests/cluster.sh psql [args...]
set -euo pipefail

PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DATA=${GATE_CLUSTER:-$ROOT/.testcluster}
PORT=${GATE_PORT:-5499}
MAJOR=$("$PG_CONFIG" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
PKG="$ROOT/target/release/pg_agent_gate-pg$MAJOR"
LIBDIR="$PKG$("$PG_CONFIG" --pkglibdir)"
SHAREDIR="$PKG$("$PG_CONFIG" --sharedir)"

case "${1:-}" in
  package)
    cd "$ROOT" && cargo pgrx package --pg-config "$PG_CONFIG"
    ls -l "$LIBDIR/pg_agent_gate.so" "$SHAREDIR/extension/pg_agent_gate.control"
    ;;
  init)
    "$BIN/pg_ctl" -D "$DATA" -m immediate -w stop >/dev/null 2>&1 || true
    rm -rf "$DATA"
    "$BIN/initdb" -D "$DATA" --auth=trust -E UTF8 >/dev/null
    cat >>"$DATA/postgresql.conf" <<EOF
port = $PORT
listen_addresses = 'localhost'
unix_socket_directories = '$DATA'
dynamic_library_path = '$LIBDIR:\$libdir'
extension_control_path = '$SHAREDIR:\$system'
EOF
    echo "initialised $DATA on port $PORT"
    ;;
  start)
    case "${2:-preload}" in
      preload) PRELOAD=pg_agent_gate ;;
      bare) PRELOAD= ;;
      *) echo "start preload|bare" >&2; exit 2 ;;
    esac
    "$BIN/pg_ctl" -D "$DATA" -l "$DATA/server.log" -w -o "-c shared_preload_libraries=$PRELOAD" start >/dev/null
    echo "started (shared_preload_libraries='$PRELOAD')"
    ;;
  stop)
    "$BIN/pg_ctl" -D "$DATA" -m "${2:-fast}" -w stop >/dev/null
    echo "stopped (${2:-fast})"
    ;;
  psql)
    shift
    exec "$BIN/psql" -X -h "$DATA" -p "$PORT" "$@"
    ;;
  *)
    sed -n '2,15p' "$0"
    exit 2
    ;;
esac
