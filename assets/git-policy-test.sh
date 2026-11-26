#!/bin/sh
# Standalone POSIX test suite for assets/git-policy and assets/git-gateway-entrypoint.
# Runs entirely without containers using stub ssh, sshd, and chown commands.

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
POLICY_SCRIPT="$SCRIPT_DIR/git-policy"
ENTRY_SCRIPT="$SCRIPT_DIR/git-gateway-entrypoint"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

STUB_BIN="$TMP_DIR/bin"
mkdir -p "$STUB_BIN"

cat > "$STUB_BIN/ssh" <<'EOF'
#!/bin/sh
printf 'SSH_EXEC:%s\n' "$*"
EOF
chmod +x "$STUB_BIN/ssh"

cat > "$STUB_BIN/sshd" <<'EOF'
#!/bin/sh
printf 'SSHD_EXEC:%s\n' "$*"
EOF
chmod +x "$STUB_BIN/sshd"

PASS=0
FAIL=0

write_policy() {
  push_flag="$1"
  repos="$2"
  marker="${3:-1}"
  cat > "$TMP_DIR/policy.env" <<EOF
AGY_GITGW_POLICY_OK=$marker
AGY_GITGW_PUSH='$push_flag'
AGY_GITGW_REPOS='$repos'
EOF
}

run_case() {
  desc="$1"
  want_rc="$2"
  want_substr="$3"
  orig_cmd="$4"

  out_file="$TMP_DIR/out"
  set +e
  env -i \
    PATH="/usr/bin:/bin" \
    AGY_GITGW_POLICY_FILE="$TMP_DIR/policy.env" \
    AGY_GITGW_KEY_DST="$TMP_DIR/key" \
    AGY_GITGW_KNOWN_HOSTS="$TMP_DIR/known_hosts" \
    AGY_GITGW_SSH="$STUB_BIN/ssh" \
    SSH_ORIGINAL_COMMAND="$orig_cmd" \
    sh "$POLICY_SCRIPT" >"$out_file" 2>&1
  rc=$?
  set -e

  body="$(cat "$out_file")"
  ok=1
  if [ "$rc" -ne "$want_rc" ]; then ok=0; fi
  case "$body" in
    *"$want_substr"*) ;;
    *) ok=0 ;;
  esac

  if [ "$ok" = "1" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL: %s (want rc=%s substr=%s, got rc=%s body=%s)\n' \
      "$desc" "$want_rc" "$want_substr" "$rc" "$body" >&2
  fi
}

# 1. Fail-closed when policy file is missing
rm -f "$TMP_DIR/policy.env"
run_case "missing policy file fails closed" 1 "missing policy file" "git-upload-pack 'owner/repo.git'"

# 2. Fail-closed when policy marker is absent
write_policy 1 "" 0
run_case "missing policy marker fails closed" 1 "policy marker absent" "git-upload-pack 'owner/repo.git'"

# 3. Read-only mode allows upload-pack and upload-archive, denies receive-pack
write_policy 0 ""
run_case "read-only allows git-upload-pack" 0 "ALLOW read git-upload-pack owner/repo" "git-upload-pack 'owner/repo.git'"
run_case "read-only allows git-upload-archive" 0 "ALLOW read git-upload-archive owner/repo" "git-upload-archive '/owner/repo'"
run_case "read-only denies git-receive-pack" 1 "push disabled" "git-receive-pack 'owner/repo.git'"
run_case "denies empty command (shell)" 1 "empty command" ""
run_case "denies arbitrary command" 1 "disallowed operation" "sh -c id"

# 4. Push mode allows receive-pack
write_policy 1 ""
run_case "push mode allows git-receive-pack" 0 "ALLOW write git-receive-pack owner/repo" "git-receive-pack 'owner/repo.git'"

# 5. Repository allowlist & normalization
write_policy 1 "org/allowed-repo,org/second.git"
run_case "allowlist permits exact match" 0 "ALLOW write git-receive-pack org/allowed-repo" "git-receive-pack 'org/allowed-repo.git'"
run_case "allowlist normalizes leading slash and .git" 0 "ALLOW read git-upload-pack org/second" "git-upload-pack '/org/second'"
run_case "allowlist blocks other repo" 1 "repo not in allowlist" "git-upload-pack 'org/other.git'"

# 6. Injection, traversal, quoting, and path-shape attacks
write_policy 1 ""
run_case "blocks command chaining with semicolon" 1 "invalid characters" "git-upload-pack 'owner/repo.git;id'"
run_case "blocks command substitution" 1 "invalid characters" "git-upload-pack 'owner/\$(id)'"
run_case "blocks backticks" 1 "invalid characters" "git-upload-pack 'owner/\`id\`'"
run_case "blocks embedded single quote escape" 1 "invalid characters" "git-upload-pack 'owner/repo' && id '"
run_case "blocks unquoted repo" 1 "unquoted repository path" "git-upload-pack owner/repo.git"
run_case "blocks path traversal" 1 "unsafe repository path" "git-upload-pack 'owner/../secret'"
run_case "blocks option injection leading dash" 1 "unsafe repository path" "git-upload-pack '-oProxyCommand/repo'"
run_case "blocks leading slash then dash" 1 "unsafe repository path" "git-upload-pack '/-evil/repo'"
run_case "blocks dash on repo component" 1 "unsafe repository path" "git-upload-pack 'owner/-repo'"
run_case "blocks dot owner component" 1 "unsafe repository path" "git-upload-pack './repo'"
run_case "blocks dot repo component" 1 "unsafe repository path" "git-upload-pack 'owner/.'"
run_case "blocks equals sign in repo path" 1 "invalid characters" "git-upload-pack 'owner/repo=bad'"
run_case "blocks nested path with extra slash" 1 "repository must be owner/repo" "git-upload-pack 'a/b/c'"
run_case "blocks single component path" 1 "repository must be owner/repo" "git-upload-pack 'justrepo'"
run_case "blocks newline injection" 1 "control character" "git-upload-pack 'owner/repo'
id"

# 6b. Glob expansion must not turn wildcard allowlist entries into matching repos
mkdir -p "$TMP_DIR/globcwd/org"
: > "$TMP_DIR/globcwd/org/secret"
write_policy 1 "org/*"
(cd "$TMP_DIR/globcwd" && run_case "disables glob expansion in allowlist" 1 "repo not in allowlist" "git-upload-pack 'org/secret'")

# 7. Entrypoint stages policy marker cleanly (using stub chown on PATH)
cat > "$STUB_BIN/chown" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$STUB_BIN/chown"
printf 'FAKEKEY\n' > "$TMP_DIR/src-key"
out_entry="$(env -i \
  PATH="$STUB_BIN:/usr/bin:/bin" \
  AGY_GITGW_POLICY_FILE="$TMP_DIR/staged-policy.env" \
  AGY_GITGW_KEY_SRC="$TMP_DIR/src-key" \
  AGY_GITGW_KEY_DST="$TMP_DIR/dst-key" \
  AGY_GITGW_SSHD="$STUB_BIN/sshd" \
  AGY_GITGW_SSHD_CFG="$TMP_DIR/sshd.conf" \
  AGY_GITGW_PUSH=1 \
  AGY_GITGW_REPOS="lmmx/agy-container" \
  sh "$ENTRY_SCRIPT")"
case "$out_entry" in
  *"SSHD_EXEC:-D -e -f"*) PASS=$((PASS + 1)) ;;
  *) FAIL=$((FAIL + 1)); echo "FAIL: entrypoint did not exec sshd" >&2 ;;
esac
if grep -q '^AGY_GITGW_POLICY_OK=1$' "$TMP_DIR/staged-policy.env" && grep -q "lmmx/agy-container" "$TMP_DIR/staged-policy.env"; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1)); echo "FAIL: entrypoint did not write policy file" >&2
fi

echo "git-policy tests: pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
