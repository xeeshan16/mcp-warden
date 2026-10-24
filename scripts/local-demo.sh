#!/usr/bin/env bash
# Run the scripted demo agent against a gateway started from this checkout,
# without Docker: SQLite in a temporary directory, the fake MCP server on
# 127.0.0.1:9001 and the gateway on 127.0.0.1:8080 (override with
# WARDEN_PORT / UPSTREAM_PORT). Everything is removed again on exit.
#
#   uv sync && scripts/local-demo.sh
#
# CI runs this from a fresh checkout, so it doubles as a check that the
# quick start works from a clean clone.
set -euo pipefail

cd "$(dirname "$0")/.."

gateway_port="${WARDEN_PORT:-8080}"
upstream_port="${UPSTREAM_PORT:-9001}"
workdir="$(mktemp -d)"
pids=()

cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$workdir"
}
trap cleanup EXIT

secret() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }

# Point the "demo" upstream at the chosen port; the policy is the example one.
sed "s#http://127.0.0.1:9001/mcp#http://127.0.0.1:${upstream_port}/mcp#" \
    examples/upstreams.yaml > "$workdir/upstreams.yaml"

export WARDEN_DATABASE_URL="sqlite:///$workdir/warden.db"
export WARDEN_POLICY_PATH="$PWD/examples/policy.yaml"
export WARDEN_UPSTREAMS_PATH="$workdir/upstreams.yaml"
export WARDEN_PORT="$gateway_port"
export WARDEN_AUTH_MODE=api-key
WARDEN_ADMIN_TOKEN="$(secret)"
WARDEN_AUDIT_HASH_KEY="$(secret)"
export WARDEN_ADMIN_TOKEN WARDEN_AUDIT_HASH_KEY
# Database-backed stores, as in production, so the CLI could inspect them too.
export WARDEN_RATE_LIMIT_STORE=database
export WARDEN_USAGE_STORE=database
export WARDEN_APPROVAL_STORE=database
export WARDEN_AUDIT_STORE=database

uv run --quiet mcp-warden db upgrade

uv run --quiet mcp-warden fake-upstream --port "$upstream_port" \
    > "$workdir/upstream.log" 2>&1 &
pids+=("$!")
uv run --quiet mcp-warden serve > "$workdir/gateway.log" 2>&1 &
pids+=("$!")

if ! uv run --quiet mcp-warden demo --gateway "http://127.0.0.1:${gateway_port}" --wait 30; then
    echo "--- gateway log ---" >&2
    tail -n 50 "$workdir/gateway.log" >&2
    echo "--- upstream log ---" >&2
    tail -n 50 "$workdir/upstream.log" >&2
    exit 1
fi
