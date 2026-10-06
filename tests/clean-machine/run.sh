#!/usr/bin/env bash
# `make verify`, on a machine that has never seen this project.
#
#   bash tests/clean-machine/run.sh          # podman, or docker if there is no podman
#
# The container gets ONLY what git has committed (`git archive HEAD`): no build output, no
# untracked file, no local configuration. If it passes here and not in the container, the
# difference is something this machine has and the repository does not say -- which is
# exactly what this script exists to find.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ENGINE=${ENGINE:-$(command -v podman || command -v docker || true)}
[ -n "$ENGINE" ] || { echo "needs podman or docker" >&2; exit 2; }

if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]; then
    echo "note: there are uncommitted changes; the container verifies HEAD ($(git -C "$ROOT" rev-parse --short HEAD)), not them"
fi

CONTEXT=$(mktemp -d)
trap 'rm -rf "$CONTEXT"' EXIT
git -C "$ROOT" archive HEAD | tar -x -C "$CONTEXT"

"$ENGINE" build -t pg_agent_gate-verify -f "$CONTEXT/tests/clean-machine/Containerfile" "$CONTEXT"
"$ENGINE" run --rm pg_agent_gate-verify
