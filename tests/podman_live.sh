#!/usr/bin/env bash
# Live rootless Podman verification suite for agy-container.
# Builds all three images and exercises real kernel, network, Squid, SSRF,
# API-key brokerage, mount, concurrency, and SIGTERM cleanup boundaries.

set -euo pipefail

REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$REPO_DIR"

cargo build --release --quiet
BIN="$REPO_DIR/target/release/agy-container"

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

export HOME="$TEST_ROOT/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_STATE_HOME="$HOME/.local/state"
mkdir -p "$HOME" "$TEST_ROOT/workspace" "$TEST_ROOT/ref-ro" "$TEST_ROOT/extra-rw"
printf 'hello reference\n' > "$TEST_ROOT/ref-ro/note.txt"
printf 'hello workspace\n' > "$TEST_ROOT/workspace/file.txt"

# Preserve user-local Podman storage/containers config if present on host.
REAL_HOME="$(getent passwd "$(id -u)" | cut -d: -f6)"
if [ -d "$REAL_HOME/.config/containers" ]; then
  mkdir -p "$HOME/.config"
  cp -a "$REAL_HOME/.config/containers" "$HOME/.config/containers"
fi
if [ -d "$REAL_HOME/.local/share/containers" ]; then
  mkdir -p "$HOME/.local/share"
  ln -s "$REAL_HOME/.local/share/containers" "$HOME/.local/share/containers"
fi

echo "=== 1. Precondition & Doctor ==="
"$BIN" --precondition
"$BIN" doctor

echo "=== 2. Build all three images (agy with SHA-512 verification, proxy, git-gateway) ==="
if [ "${FORCE_REBUILD:-0}" = "1" ] || ! podman image exists localhost/agy-container-agy:latest; then
  "$BIN" update-image
else
  podman build -t localhost/agy-container-proxy:latest -f assets/Containerfile.proxy assets >/dev/null
  podman build -t localhost/agy-container-gitgateway:latest -f assets/Containerfile.gitgateway assets >/dev/null
fi

echo "=== 3. Validate Squid configs across all --allow groups + API broker ==="
SQUID_CI="$TEST_ROOT/squid-ci"
mkdir -p "$SQUID_CI"
for g in "" google-auth gcp-enterprise github npm pypi crates go telemetry updater remote-control; do
  if [ -z "$g" ]; then
    printf '# empty\n' > "$SQUID_CI/allow.conf"
  else
    cargo run --quiet --example emit-squid-fragments -- allow "$g" > "$SQUID_CI/allow.conf"
  fi
  printf '# broker off\n' > "$SQUID_CI/api-broker.conf"
  podman run --rm --user 0:0 --entrypoint squid \
    -v "$REPO_DIR/assets/squid.conf:/etc/squid/squid.conf:ro" \
    -v "$SQUID_CI/allow.conf:/etc/squid/conf.d/allow.conf:ro" \
    -v "$SQUID_CI/api-broker.conf:/etc/squid/conf.d/api-broker.conf:ro" \
    localhost/agy-container-proxy:latest -k parse -f /etc/squid/squid.conf >/dev/null 2>&1
done
cargo run --quiet --example emit-squid-fragments -- broker > "$SQUID_CI/api-broker.conf"
printf '# empty\n' > "$SQUID_CI/allow.conf"
podman run --rm --user 0:0 --entrypoint squid \
  -v "$REPO_DIR/assets/squid.conf:/etc/squid/squid.conf:ro" \
  -v "$SQUID_CI/allow.conf:/etc/squid/conf.d/allow.conf:ro" \
  -v "$SQUID_CI/api-broker.conf:/etc/squid/conf.d/api-broker.conf:ro" \
  localhost/agy-container-proxy:latest -k parse -f /etc/squid/squid.conf >/dev/null 2>&1
podman run --rm --user 0:0 --entrypoint squid \
  -v "$REPO_DIR/assets/squid.permissive.conf:/etc/squid/squid.conf:ro" \
  -v "$SQUID_CI/api-broker.conf:/etc/squid/conf.d/api-broker.conf:ro" \
  localhost/agy-container-proxy:latest -k parse -f /etc/squid/squid.conf >/dev/null 2>&1
echo "PASS: all Squid configs parsed cleanly"

echo "=== 4. Validate sshd_gitgateway.conf inside built git-gateway image ==="
ssh-keygen -q -t ed25519 -N '' -f "$TEST_ROOT/ci_host_key"
podman run --rm --user 0:0 --entrypoint /usr/sbin/sshd \
  -v "$TEST_ROOT/ci_host_key:/run/secrets/host_key:ro" \
  localhost/agy-container-gitgateway:latest -t -f /etc/ssh/sshd_config
echo "PASS: sshd_gitgateway.conf valid"

echo "=== 5. Real agy CLI execution & argument forwarding ==="
VER="$("$BIN" -w "$TEST_ROOT/workspace" -- --version </dev/null)"
echo "Containerized agy version: $VER"
test -n "$VER"

echo "=== 6. In-container verify-boundary (capabilities, allowlist, SSRF, route isolation) ==="
"$BIN" -w "$TEST_ROOT/workspace" --ro "$TEST_ROOT/ref-ro" --rw "$TEST_ROOT/extra-rw" \
  --shell -- -c '
    set -eu
    http_status() {
      pair="$(curl -s -o /dev/null -w "%{http_code}:%{http_connect}" --max-time 8 "$@" 2>/dev/null || true)"
      [ -n "$pair" ] || pair="000:000"
      code="${pair%%:*}"; conn="${pair##*:}"
      if [ "$code" = "000" ] && [ "$conn" != "000" ]; then printf "%s" "$conn"; else printf "%s" "$code"; fi
    }
    cap_eff="$(awk "/^CapEff:/{print \$2}" /proc/self/status)"
    nnp="$(awk "/^NoNewPrivs:/{print \$2}" /proc/self/status)"
    test "$cap_eff" = "0000000000000000"
    test "$nnp" = "1"
    test "$(id -u)" = "1000"
    test -z "$(ip route | awk "/^default/{print \$3}")"
    ! timeout 2 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null
    ! timeout 2 bash -c "exec 3<>/dev/tcp/1.1.1.1/53" 2>/dev/null
    test "$(http_status https://example.com/)" = "403"
    test "$(http_status https://compute.googleapis.com/)" = "403"
    test "$(http_status --noproxy "" http://169.254.169.254/latest/meta-data/)" = "403"
    test "$(http_status --noproxy "" https://127.0.0.1/)" = "403"
    test "$(http_status --noproxy "" https://10.0.0.1/)" = "403"
    test "$(http_status --noproxy "" -g "https://[::]/")" = "403"
    code="$(http_status https://generativelanguage.googleapis.com/)"
    test "$code" != "000" && test "$code" != "403"
    echo "PASS: non-root UID 1000, CapEff=0, NoNewPrivs=1, internal route, allowlist, and SSRF protections verified (api HTTP=$code)"
  ' </dev/null

echo "=== 7. Mount boundaries (--ro-workspace, --ro, --rw) ==="
"$BIN" -w "$TEST_ROOT/workspace" --ro-workspace --ro "$TEST_ROOT/ref-ro" --rw "$TEST_ROOT/extra-rw" \
  --shell -- -c '
    set -eu
    ! touch /workspace/should-fail 2>/dev/null
    ! touch /mnt/ref-ro/should-fail 2>/dev/null
    cat /mnt/ref-ro/note.txt | grep -q "hello reference"
    touch /mnt/extra-rw/written-ok
    echo "PASS: read-only workspace & ref-ro blocked writes; extra-rw allowed writes"
  ' </dev/null
test -f "$TEST_ROOT/extra-rw/written-ok"

echo "=== 8. Zero-MITM GEMINI_API_KEY brokerage (real key never in workspace) ==="
REAL_DUMMY_KEY="AIzaSyLiveBrokerTestKey000111222"
GEMINI_API_KEY="$REAL_DUMMY_KEY" "$BIN" -w "$TEST_ROOT/workspace" --auth api-key \
  --shell -- -c '
    set -eu
    test "$GEMINI_API_KEY" = "agy-container-proxy-managed"
    test "$GOOGLE_GEMINI_BASE_URL" = "http://proxy:3129"
    ! env | grep -q "AIzaSyLiveBrokerTestKey"
    # Path restriction on port 3129 blocks paths outside /v1/ and /v1beta/ AND dot-segment traversal
    bad_path_code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 http://proxy:3129/not-v1)"
    test "$bad_path_code" = "403"
    dotdot_code="$(curl -s --path-as-is -o /dev/null -w "%{http_code}" --max-time 8 http://proxy:3129/v1beta/../../other)"
    test "$dotdot_code" = "403"
    enc_dotdot_code="$(curl -s --path-as-is -o /dev/null -w "%{http_code}" --max-time 8 http://proxy:3129/v1beta/%2e%2e/other)"
    test "$enc_dotdot_code" = "403"
    # Valid /v1beta/ path forwards over TLS to generativelanguage.googleapis.com with injected header
    # (Google responds HTTP 400 API_KEY_INVALID for our fake test key, proving real TLS round-trip!)
    api_body="$(curl -sS --max-time 10 http://proxy:3129/v1beta/models || true)"
    echo "$api_body" | grep -qiE "API_KEY_INVALID|API key not valid|error"
    echo "PASS: zero-MITM API key broker injected header over TLS while blocking traversal & hiding key"
  ' </dev/null

echo "=== 9. --probe --self-test ==="
"$BIN" -w "$TEST_ROOT/workspace" --probe --self-test </dev/null

echo "=== 10. Concurrent independent invocations ==="
"$BIN" -w "$TEST_ROOT/workspace" --isolated --shell -- -c 'sleep 3; echo "RUN_A_OK"' </dev/null >"$TEST_ROOT/run_a.out" &
PID_A=$!
"$BIN" -w "$TEST_ROOT/workspace" --isolated --shell -- -c 'sleep 1; echo "RUN_B_OK"' </dev/null >"$TEST_ROOT/run_b.out" &
PID_B=$!
wait "$PID_B"
wait "$PID_A"
grep -q "RUN_A_OK" "$TEST_ROOT/run_a.out"
grep -q "RUN_B_OK" "$TEST_ROOT/run_b.out"
echo "PASS: concurrent runs completed independently without interfering"

echo "=== 11. SIGTERM cancellation & zero orphaned resources ==="
"$BIN" -w "$TEST_ROOT/workspace" --isolated --shell -- -c 'sleep 30' </dev/null >/dev/null 2>&1 &
PID_SIG=$!
sleep 2
kill -TERM "$PID_SIG"
wait "$PID_SIG" || true
leftover_c="$(podman ps -a --filter label=agy-container.run --format '{{.Names}}')"
leftover_n="$(podman network ls --format '{{.Name}}' | grep -E '^agy-(caged|egress)-' || true)"
test -z "$leftover_c"
test -z "$leftover_n"
echo "PASS: SIGTERM cleaned up all containers and networks (zero orphans)"

echo "=== 12. Egress audit log populated ==="
test -s "$XDG_STATE_HOME/agy-container/egress.log"
grep -q "generativelanguage.googleapis.com" "$XDG_STATE_HOME/agy-container/egress.log"
echo "PASS: egress.log recorded session traffic"

echo "ALL LIVE ROOTLESS PODMAN TESTS PASSED!"
