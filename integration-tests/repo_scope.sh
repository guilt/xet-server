#!/bin/bash
# XET_IT_TEST_TIMEOUT: 20
# Regression test for the openxet report: a minted token must be bound to
# the repo it was issued for. A read token for alice/sec must not read
# bob/private, and a write token for alice/sec must not commit there or
# create a repo in carol's namespace. The shared secret remains the
# unrestricted operator credential.
set -euo pipefail

# Hardcoded integration-test fixture, not a real credential.
AUTH_TOKEN="it-fixture-token-not-a-real-secret"
PORT="${XET_IT_REPO_SCOPE_CAS_PORT:-18450}"
HUB_PORT="${XET_IT_REPO_SCOPE_HUB_PORT:-18451}"
CAS_URL="http://127.0.0.1:${PORT}"
HUB_URL="http://127.0.0.1:${HUB_PORT}"
DATA_DIR="$WORKDIR/server-data"
SERVER_LOG="$WORKDIR/xetd-repo-scope.log"

mkdir -p "$DATA_DIR"
"$XETD" -addr ":${PORT}" -hub-addr ":${HUB_PORT}" -data "$DATA_DIR" -auth-token "$AUTH_TOKEN" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

ready=false
for _ in $(seq 1 50); do
    if curl -s -o /dev/null "$CAS_URL/v1/stats"; then
        ready=true
        break
    fi
    sleep 0.1
done
if [[ "$ready" != true ]]; then
    echo "xetd did not become ready; log follows:"
    cat "$SERVER_LOG"
    exit 1
fi

mint() {
    local kind=$1 repo=$2
    curl -sS -H "Authorization: Bearer $AUTH_TOKEN" "$HUB_URL/api/models/${repo}/xet-${kind}-token/main" \
        | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p'
}
read_token=$(mint read alice/sec)
write_token=$(mint write alice/sec)
[[ -n "$read_token" && -n "$write_token" ]] || { echo "failed to mint tokens"; exit 1; }

expect() {
    local want=$1; shift
    local got
    got=$(curl -s -o /dev/null -w '%{http_code}' "$@")
    if [[ "$got" != "$want" ]]; then
        echo "expected $want, got $got: curl $*"
        exit 1
    fi
}

# Read token: own repo works, another repo is forbidden.
expect 200 -H "Authorization: Bearer $read_token" "$HUB_URL/api/models/alice/sec/revision/main"
expect 403 -H "Authorization: Bearer $read_token" "$HUB_URL/api/models/bob/private/revision/main"
expect 403 -H "Authorization: Bearer $read_token" "$HUB_URL/bob/private/resolve/main/x.bin"
expect 403 -H "Authorization: Bearer $read_token" "$HUB_URL/api/models/bob/private/xet-read-token/main"

# Write token: own repo works, another repo is forbidden.
expect 200 -X POST -H "Authorization: Bearer $write_token" -H 'Content-Type: application/x-ndjson' \
    --data-binary $'{"key":"header","value":{}}\n' "$HUB_URL/api/models/alice/sec/commit/main"
expect 403 -X POST -H "Authorization: Bearer $write_token" -H 'Content-Type: application/x-ndjson' \
    --data-binary $'{"key":"header","value":{}}\n' "$HUB_URL/api/models/bob/private/commit/main"
expect 403 -X POST -H "Authorization: Bearer $write_token" -H 'Content-Type: application/json' \
    --data-binary '{"files":[]}' "$HUB_URL/api/models/bob/private/preupload/main"
expect 403 -X POST -H "Authorization: Bearer $write_token" -H 'Content-Type: application/vnd.git-lfs+json' \
    --data-binary '{"operation":"upload","transfers":["xet"],"objects":[]}' "$HUB_URL/bob/private.git/info/lfs/objects/batch"

# Repo creation: same namespace allowed, another namespace requires the secret.
expect 200 -X POST -H "Authorization: Bearer $write_token" -H 'Content-Type: application/json' \
    --data-binary '{"name":"new","organization":"alice","type":"model"}' "$HUB_URL/api/repos/create"
expect 403 -X POST -H "Authorization: Bearer $write_token" -H 'Content-Type: application/json' \
    --data-binary '{"name":"x","organization":"carol","type":"model"}' "$HUB_URL/api/repos/create"

# The shared secret is the operator credential: it still reaches every repo.
expect 200 -H "Authorization: Bearer $AUTH_TOKEN" "$HUB_URL/api/models/bob/private/revision/main"
expect 200 -X POST -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' \
    --data-binary '{"name":"x","organization":"carol","type":"model"}' "$HUB_URL/api/repos/create"

echo "repo-scoped minted tokens: cross-repo read/write/create refused, own namespace allowed"