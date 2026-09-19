#!/usr/bin/env bash
# The end-to-end smoke test: a real control plane against a real PostgreSQL, a
# fake agent that speaks the agent protocol, and the panel in a browser. It
# answers one question - do the parts start and talk to each other - and leaves
# what every screen shows to Vitest and to the laboratory.
#
#   FLOTESTRO_DATABASE_URL=postgres://... tests/e2e/smoke.sh
#
# The database has to be empty: the first start of the control plane creates
# the bootstrap identity the panel signs in with, and the fake agent enrolls
# into a fleet that has nothing in it yet. Everything else - the state
# directory, the identity of the fake agent, the logs - lives in the work
# directory and goes away with it.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="${FLOTESTRO_E2E_WORK:-${RUNNER_TEMP:-/tmp}/flotestro-e2e}"
bin="${FLOTESTRO_E2E_BIN:-$work/bin}"
admin_addr="${FLOTESTRO_E2E_ADMIN_ADDR:-127.0.0.1:8080}"
gateway_addr="${FLOTESTRO_E2E_GATEWAY_ADDR:-127.0.0.1:8443}"
enrollment_addr="${FLOTESTRO_E2E_ENROLLMENT_ADDR:-127.0.0.1:8444}"
base_url="http://$admin_addr"
# The prefix decides the host name of the fake agent: the simulator numbers
# its agents, so one agent under this prefix is e2e-fake-00000.
prefix="e2e-fake"
hostname="$prefix-00000"

: "${FLOTESTRO_DATABASE_URL:?set FLOTESTRO_DATABASE_URL to an empty database}"
export FLOTESTRO_DATABASE_URL
for tool in curl jq npx; do
    command -v "$tool" >/dev/null || { echo "$tool is missing" >&2; exit 1; }
done
if [ ! -f "$repo/web/dist/index.html" ]; then
    echo "the panel is not built; run \"npm ci && npm run build\" in web/" >&2
    exit 1
fi

control_plane_log="$work/control-plane.log"
agent_log="$work/agent.log"
control_plane_pid=""
agent_pid=""

# The children are stopped whichever way the run ends, and their logs are
# printed only when something failed: on a green run they say nothing anybody
# needs.
cleanup() {
    status=$?
    if [ -n "$agent_pid" ]; then kill "$agent_pid" 2>/dev/null || true; fi
    if [ -n "$control_plane_pid" ]; then kill "$control_plane_pid" 2>/dev/null || true; fi
    wait 2>/dev/null || true
    if [ "$status" -ne 0 ]; then
        for log in "$control_plane_log" "$agent_log"; do
            [ -f "$log" ] || continue
            echo "==> the last lines of $(basename "$log")"
            tail -n 50 "$log"
        done
    fi
    exit "$status"
}
trap cleanup EXIT

# waitFor calls a function until it succeeds, and gives up loudly.
waitFor() {
    local what="$1" limit="$2" check="$3" waited=0
    until "$check"; do
        if [ "$waited" -ge "$limit" ]; then
            echo "$what did not happen within ${limit}s" >&2
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

rm -rf "$work"
mkdir -p "$work/state" "$work/agent-state" "$bin"
export FLOTESTRO_STATE_DIR="$work/state"

if [ ! -x "$bin/flotestro-control-plane" ]; then
    echo "==> building the control plane and the fake agent"
    bin="$(cd "$bin" && pwd)"
    (cd "$repo" && go build -o "$bin/flotestro-control-plane" ./cmd/control-plane)
    (cd "$repo" && go build -o "$bin/flotestro-agent-simulator" ./cmd/agent-simulator)
fi

echo "==> the schema"
"$bin/flotestro-control-plane" migrate

echo "==> the control plane"
# A short heartbeat: the fake agent has to appear as online while the browser
# is still on the login screen, not a minute later.
FLOTESTRO_ADMIN_ADDR="$admin_addr" \
    FLOTESTRO_GATEWAY_ADDR="$gateway_addr" \
    FLOTESTRO_ENROLLMENT_ADDR="$enrollment_addr" \
    FLOTESTRO_ADVERTISE="${gateway_addr%%:*}" \
    FLOTESTRO_WEB_ROOT="$repo/web/dist" \
    FLOTESTRO_PUBLIC_URL="$base_url" \
    FLOTESTRO_HEARTBEAT_SECONDS=10 \
    FLOTESTRO_HEARTBEAT_JITTER=2 \
    "$bin/flotestro-control-plane" serve >"$control_plane_log" 2>&1 &
control_plane_pid=$!

serving() {
    # A process that is gone will not come back; the wait ends with it and the
    # log of the control plane says what happened.
    kill -0 "$control_plane_pid" 2>/dev/null || { echo "the control plane exited" >&2; exit 1; }
    curl -fsS -o /dev/null "$base_url/healthz"
}
waitFor "the control plane" 90 serving

bootstrapWritten() { [ -s "$work/state/bootstrap-token" ]; }
waitFor "the bootstrap token" 30 bootstrapWritten
admin_token="$(tr -d '\r\n' <"$work/state/bootstrap-token")"

echo "==> the enrollment order"
# One use, a non-production environment: an order for more machines is a
# standing door and asks for a fresh authentication the runner has no way to
# give.
enrollment_token="$(curl -fsS -X POST "$base_url/api/v1/enrollment-requests" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $admin_token" \
    -d '{"description":"the end-to-end smoke test","site":"ci","environment":"ci","max_uses":1,"ttl_minutes":30}' |
    jq -r ".token")"
[ -n "$enrollment_token" ] && [ "$enrollment_token" != "null" ] ||
    { echo "the enrollment order carried no token" >&2; exit 1; }

echo "==> the fake agent"
# The token travels in the environment and not in the argument list: the
# process list of the runner is readable by everything else on it.
FLOTESTRO_ENROLLMENT_TOKEN="$enrollment_token" \
    "$bin/flotestro-agent-simulator" \
    --count=1 \
    --prefix="$prefix" \
    --state-dir="$work/agent-state" \
    --enrollment-url="https://$enrollment_addr" \
    --gateway-url="https://$gateway_addr" \
    --ca-file="$work/state/ca.pem" \
    --ramp-up=0 \
    --report-interval=0 \
    --verbose >"$agent_log" 2>&1 &
agent_pid=$!

host_id=""
enrolled() {
    kill -0 "$agent_pid" 2>/dev/null || { echo "the fake agent exited" >&2; exit 1; }
    host_id="$(curl -fsS -H "Authorization: Bearer $admin_token" "$base_url/api/v1/hosts?limit=50" |
        jq -r --arg name "$hostname" \
            'first(.items[] | select(.hostname == $name and .connection_state == "online") | .id) // ""')"
    [ -n "$host_id" ]
}
waitFor "the fake agent showing up online in the panel" 120 enrolled
echo "    $hostname is online as $host_id"

echo "==> the panel in a browser"
cd "$repo/web"
BASE_URL="$base_url" \
    FLOTESTRO_TOKEN="$admin_token" \
    FLOTESTRO_E2E_HOSTNAME="$hostname" \
    FLOTESTRO_E2E_HOST_ID="$host_id" \
    npx playwright test --config=playwright.smoke.config.ts
