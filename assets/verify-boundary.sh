#!/usr/bin/env bash
# Empirical security boundary verifier — run inside the agy-container workspace.
#
# curl     goes through HTTPS_PROXY -> verifies Squid allowlist & SSRF denials
# /dev/tcp ignores HTTPS_PROXY      -> verifies internal network route isolation
# /proc    reads kernel state       -> verifies capabilities & no-new-privileges

set -u

PASS=0
FAIL=0

report() {
  if [ "$2" = "$3" ]; then
    printf 'ok   %-44s (%s)\n' "$1" "$3"
    PASS=$((PASS + 1))
  else
    printf 'FAIL %-44s (want %s, got %s)\n' "$1" "$2" "$3"
    FAIL=$((FAIL + 1))
  fi
}

http_code() {
  local pair code conn
  pair="$(curl -s -o /dev/null -w '%{http_code}:%{http_connect}' --max-time 8 "$@" 2>/dev/null || true)"
  [ -n "$pair" ] || pair="000:000"
  code="${pair%%:*}"
  conn="${pair##*:}"
  if [ "$code" = "000" ] && [ "$conn" != "000" ]; then
    printf '%s' "$conn"
  else
    printf '%s' "$code"
  fi
}
tcp()       { timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

echo "--- process & privilege hardening ---"

cap_eff="$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || echo unknown)"
report "effective capabilities empty" "0000000000000000" "$cap_eff"

nnp="$(awk '/^NoNewPrivs:/{print $2}' /proc/self/status 2>/dev/null || echo unknown)"
report "no-new-privileges enabled" "1" "$nnp"

bin_owner="$(stat -c %u /usr/local/bin/agy 2>/dev/null || echo unknown)"
cur_uid="$(id -u)"
if [ -w /usr/local/bin/agy ]; then
  report "/usr/local/bin/agy immutable to agent" "immutable" "writable"
elif [ "$bin_owner" = "$cur_uid" ]; then
  printf 'note %-44s (owner=%s == uid=%s; single-mapping userns)\n' "/usr/local/bin/agy 0555 but same owner" "$bin_owner" "$cur_uid"
else
  report "/usr/local/bin/agy immutable to agent" "immutable" "immutable"
fi

echo
echo "--- allowlist & SSRF layer (via Squid gateway) ---"

c="$(http_code https://generativelanguage.googleapis.com/)"
[ "$c" = "000" ] && r="no-response" || r="responded"
report "antigravity/gemini API reachable" "responded" "$r"

for h in https://example.com https://compute.googleapis.com https://iam.googleapis.com \
         https://secretmanager.googleapis.com https://pastebin.com; do
  c="$(http_code "$h")"
  if   [ "$c" = "403" ]; then r="gateway-denied"
  elif [ "$c" = "000" ]; then r="no-response"
  else r="allowed:$c"; fi
  report "gateway denies ${h#https://}" "gateway-denied" "$r"
done

for priv in http://169.254.169.254/latest/meta-data/ https://127.0.0.1/ https://10.0.0.1/; do
  c="$(http_code --noproxy '' "$priv")"
  if   [ "$c" = "403" ]; then r="ssrf-denied"
  elif [ "$c" = "000" ]; then r="no-response"
  else r="allowed:$c"; fi
  report "gateway blocks private target ${priv#*://}" "ssrf-denied" "$r"
done

echo
echo "--- route layer (bypasses proxy) ---"

for t in "1.1.1.1 443" "1.1.1.1 53" "169.254.169.254 80" "github.com 22"; do
  set -- $t
  tcp "$1" "$2" && r="reach" || r="block"
  report "direct route $1:$2" "block" "$r"
done

gw="$(ip route 2>/dev/null | awk '/^default/{print $3}')"
if [ -z "$gw" ]; then
  report "no default route on internal network" "none" "none"
else
  report "no default route on internal network" "none" "$gw"
fi

echo
echo "--- host isolation & mount modes ---"

for d in "$HOME/.ssh" "$HOME/.aws" "$HOME/.gnupg" "$HOME/.kube"; do
  if [ -d "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null)" ]; then
    r="present"
  else
    r="absent"
  fi
  report "host $(basename "$d") absent" "absent" "$r"
done

probe_write() {
  [ -d "$1" ] || return 0
  if touch "$1/.agy-write-probe" 2>/dev/null; then
    rm -f "$1/.agy-write-probe"
    printf '     %-44s writable\n' "$1"
  else
    printf '     %-44s read-only\n' "$1"
  fi
}

probe_write /workspace
for d in /mnt/*; do
  [ -e "$d" ] && probe_write "$d"
done

echo
echo "--- secret-shaped files in mounted trees ---"

FOUND="$(find /workspace /mnt -maxdepth 4 \
  \( -name node_modules -o -name .git -o -name target \) -prune -o \
  -type f \( -name '.env' -o -name '.env.*' -o -name '.npmrc' -o -name '.netrc' \
             -o -name '.pypirc' -o -name 'id_rsa' -o -name 'id_ed25519' \
             -o -name '*.pem' -o -name 'credentials' -o -name 'service-account*.json' \) -print \
  2>/dev/null | head -20)"

if [ -n "$FOUND" ]; then
  echo "$FOUND" | sed 's/^/     ! /'
  echo "     ^ readable by agent even on read-only mounts"
else
  printf 'ok   %-44s (%s)\n' "no secret-shaped files detected" "none"
fi

echo
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
