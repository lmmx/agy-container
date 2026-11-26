# agy-container

Run [Google Antigravity CLI (`agy`)](https://antigravity.google/) inside a hardened rootless Podman container with default-deny egress, SSRF protection, credential isolation, and full concurrency.

A single zero-dependency Rust binary (`std` only; no external crates in [`Cargo.toml`](Cargo.toml)). All containerfiles, Squid configurations, SSH gateway policy scripts, and boundary verification scripts are compiled into the binary and materialized on demand into `${XDG_CACHE_HOME:-~/.cache}/agy-container/assets/`.

## Why `agy-container` Exists Independently of `claude-container`

`agy-container` is a clean-room sibling to [`lmmx/claude-container`](https://github.com/lmmx/claude-container), not a thin fork or shared wrapper. Although both enforce a rootless Podman `--internal` network with a sibling Squid egress gateway and an SSH git-gateway sidecar, Google Antigravity CLI differs structurally from Claude Code across four axes:

1. **Multi-agent native execution (`/swarm`, `/boost`, `/teamwork`, subagents).** Antigravity CLI spawns parallel worker processes and embedded loopback gRPC/HTTP servers inside a single session, requiring higher memory (`8g`) and process (`4096`) envelopes plus explicit `NO_PROXY=localhost,127.0.0.1,::1,proxy,git-gateway` routing.
2. **Authentication surface and blast radius.** Antigravity supports four distinct auth paths (personal Google OAuth, `GEMINI_API_KEY`, Gemini Enterprise / GCP OAuth, and Application Default Credentials). Personal OAuth tokens currently carry Google's full `cloud-platform` scope ([`google-antigravity/antigravity-cli#592`](https://github.com/google-antigravity/antigravity-cli/issues/592)), demanding isolated container-only profiles, egress exclusion of GCP control-plane APIs, and a zero-MITM reverse-proxy API key broker on Squid port `3129`.
3. **Direct Podman orchestration for true concurrency.** `claude-container` uses a fixed `podman-compose` project name, which causes concurrent runs to collide on a single proxy and tear each other down. `agy-container` drops `podman-compose` entirely and creates per-run `agy-caged-<run_id>` / `agy-egress-<run_id>` networks and `agy-proxy-<run_id>` / `agy-gitgw-<run_id>` sidecars with RAII teardown and cooperative `SIGTERM` cleanup.
4. **Native CLI ergonomics.** `agy` ships first-class subcommands (`models`, `mcp`, `plugin`, `acp`, `agents`, `changelog`, `remote-control`) and `-w/--workspace` defaults cleanly to the current working directory instead of requiring a mandatory positional path that collides with subcommands.

See [`docs/comparison.md`](docs/comparison.md) for the full architectural decision matrix and [`docs/threat-model.md`](docs/threat-model.md) for the Antigravity-specific threat model.

---

## Architecture Overview

```
       Trusted Host                                             External APIs
  +---------------------+                                 +-----------------------+
  | agy-container (Rust)|  isolated profiles, squid.conf, | Google Antigravity /  |
  |  (per-run run_id)   |  GEMINI_API_KEY, host SSH key   | Gemini APIs, GitHub   |
  +----------+----------+                                 +-----------^-----------+
             | per-run mounts & fragments                             |
             v                                                        |
  +---------------------+          +---------------------+            |
  | agy-gitgw-<run_id>  |----+---->| agy-egress-<run_id> |------------+
  | (optional sidecar)  |    |     +---------------------+            |
  | port 2222, real key |    |     +---------------------+            |
  +----------^----------+    +---->| agy-proxy-<run_id>  |------------+
             |                     | Squid :3128 forward |
             |                     | Squid :3129 API key |
             |                     +----------^----------+
             |                                |
             |   agy-caged-<run_id> (--internal, no default route)
             |                                |
  +----------+--------------------------------+----------+
  |                  agy-work-<run_id>                   |
  |   Untrusted workspace (/workspace) + /usr/local/bin/agy
  |   --cap-drop=ALL, no-new-privileges, no host ~/.gemini
  +------------------------------------------------------+
```

- The workspace container (`agy-work-<run_id>`) attaches **only** to the per-run `--internal` network (`agy-caged-<run_id>`), which has no default route to the internet or host LAN.
- Sidecar IPs (`proxy`, `git-gateway`) are pinned into `/etc/hosts` via `--add-host`, so internal DNS is not needed.
- Both `squid.conf` and `squid.permissive.conf` enforce `acl private_dst` before any `http_access allow` rule, blocking loopback, RFC 1918 LANs, CGNAT, and cloud metadata endpoints (`169.254.169.254`).

---

## Requirements

- **Podman** (rootless; tested on Podman 4.x / 5.x; no `podman-compose` required)
- **Rust 1.80+** (`cargo` / `rustc`) to build from source
- **OpenSSH (`ssh-keygen`)** on the host when using `--github`

---

## Quickstart & Installation

### 1. Build and install

```shell
cargo install --path .
```

The binary is self-contained. On first run it materializes its embedded `Containerfile.*` and config assets to `${XDG_CACHE_HOME:-~/.cache}/agy-container/assets/` (preserving mtimes so Podman's layer cache stays warm) and seeds a user-editable Squid policy at `${XDG_CONFIG_HOME:-~/.config}/agy-container/squid.conf`. Set `AGY_CONTAINER_DIR=/path/to/assets` during development to load assets directly from a checkout.

### 2. Verify host isolation (`doctor` and `--precondition`)

Before trusting the boundary, prove that rootless Podman honors `--internal` networks and inspect your host's `subuid`/`subgid`, cgroup v2 delegation, SELinux posture, image status, and profile auth state:

```shell
agy-container doctor
```

To run only the kernel/network isolation check (verifies no default route and blocks `1.1.1.1:443` and `1.1.1.1:53` on a fresh `--internal` network):

```shell
agy-container --precondition
```

### 3. Authenticate

**Option A — Zero-MITM brokered `GEMINI_API_KEY` (narrowest credential blast radius):**

```shell
export GEMINI_API_KEY="AIza..."
agy-container --auth api-key -p "Summarize this repository"
```

Or read the key from a `0600` file (automatically implies `--auth api-key`):

```shell
agy-container --api-key-file ~/.secrets/gemini.key -p "Audit tests"
```

**Option B — Interactive headless OAuth (`agy-container login`):**

```shell
agy-container login
```

`agy-container login` temporarily enables the `google-auth` egress group and invokes `agy acp --login` with `NO_BROWSER=true` and `SSH_CONNECTION="agy-container 0 agy-container 0"`. Because `agy` detects a remote environment, it prints an `accounts.google.com` authorization URL instead of trying to open a browser or bind `localhost:36742`:

1. Open the printed URL in your host browser and complete Google sign-in.
2. Google redirects to `http://localhost:36742/oauth-callback?code=...` (which will not load — this is expected).
3. Copy the full callback URL (or authorization code) from your browser's address bar and paste it back into the terminal prompt.
4. The resulting token is saved **only** inside the isolated container profile (`${XDG_DATA_HOME:-~/.local/share}/agy-container/profiles/<profile>/gemini/antigravity-cli/antigravity-oauth-token`), never in your host `~/.gemini`.

---

## Core Workflows

By default, `agy-container` mounts the current directory at `/workspace` (read-write) and launches `agy` with `--dangerously-skip-permissions --mode accept-edits` because the outer rootless Podman container + internal network + Squid proxy form the security boundary. Pass `--strict-permissions` to disable automatic approval flags and revert to interactive tool prompts.

### Interactive session

```shell
agy-container
agy-container -w ~/projects/my-app
```

### Gemini 4 Neon & Orchestrator

Native `agy` model and reasoning-effort flags are forwarded directly:

```shell
# Gemini 4 Neon (Extra High reasoning)
agy-container --model gemini-4-neon-xhigh

# Explicit effort override
agy-container --model gemini-4-neon --effort xhigh

# Orchestrator (Neon planner + Hydrogen executor)
agy-container --model "Orchestrator (Neon)"
```

### Native `/swarm` (multi-worker parallel execution)

Start an interactive session (or Orchestrator session) and invoke `/swarm` inside `agy`:

```shell
agy-container --model gemini-4-neon-xhigh
# Inside agy:
# /swarm Split the test migration across modules A, B, and C with a verifier
```

`agy-container` sizes default resource limits (`--memory 8g`, `--pids-limit 4096`) and sets `NO_PROXY=localhost,127.0.0.1,::1,proxy,git-gateway` so all `/swarm` workers, subagents, and Antigravity's embedded loopback language server run inside a single contained boundary without tripping cgroup caps or proxy loops. See [`docs/adr/002-single-container-per-swarm.md`](docs/adr/002-single-container-per-swarm.md).

### Headless single-turn execution (`-p` / `--print` / `--prompt`)

`agy-container` automatically drops the TTY for headless runs and prints its boundary summary exclusively to `stderr`, keeping `stdout` clean for pipelines and JSON consumers:

```shell
agy-container -p "List all public functions in src/ and check for unwrap() calls"
agy-container -p "Return module count" --output-format json
agy-container -p "Audit Dockerfile" --output-format json --json-schema '{"type":"object","properties":{"issues":{"type":"array"}}}'
```

### Streaming NDJSON (`--input-format stream-json --output-format stream-json`)

When `--input-format stream-json` is passed, `agy-container` keeps container `stdin` open without allocating a PTY (`-i` without `-t`), enabling programmatic bi-directional JSON streaming:

```shell
printf '%s\n' '{"type":"user","message":{"role":"user","content":"Check Cargo.toml"}}' \
  | agy-container --input-format stream-json --output-format stream-json
```

### Session resumption (`-c`, `-r`)

Because each profile persists isolated Antigravity state under `~/.local/share/agy-container/profiles/<profile>/`, sessions can be continued or resumed across container runs:

```shell
# Continue the most recent conversation
agy-container -c

# Resume a specific conversation ID
agy-container -r <CONVERSATION_ID>
agy-container --resume <CONVERSATION_ID>
```

### Native `agy` subcommands & `--` passthrough

Recognized native `agy` subcommands (`acp`, `agent`, `agents`, `changelog`, `mcp`, `models`, `plugin`, `plugins`, `remote-control`) are forwarded verbatim with all trailing arguments:

```shell
agy-container models
agy-container agents
agy-container changelog
agy-container mcp list
agy-container mcp add --type stdio my-tool -- npx foo
agy-container plugin list
agy-container acp
```

Notes:
- `acp` runs headless with `stdin` kept open (`-i`), receives `--dangerously-skip-permissions` (unless `--strict-permissions`), and receives `--add-dir /mnt/<name>` for extra mounts.
- `models`, `agent`, `agents`, and `changelog` automatically run headless (no TTY).
- Anything after `--` bypasses `agy-container` option parsing completely and is forwarded verbatim to `agy` (e.g., `agy-container -- --help` prints `agy`'s own help text, and `agy-container -- --ro /etc` forwards `--ro /etc` literally without mounting `/etc`).
- Use `--shell` to drop into `/bin/bash` inside the exact hardened container environment (for debugging or running `verify-boundary`).

---

## Authentication Modes & Security Trade-Offs

Select an auth mode with `--auth <MODE>`:

| Mode | Flag | Real Secret Visible to Agent? | Credential Blast Radius | Implied Egress |
| --- | --- | --- | --- | --- |
| **API Key (brokered)** | `--auth api-key` (or `--api-key-file <PATH>`) | **No** (sentinel only) | Scoped to Gemini Developer API (`/v1/` & `/v1beta/` on `generativelanguage.googleapis.com`) | Core allowlist + port `3129` broker |
| **Personal OAuth** (default) | `--auth oauth` | **Yes** (inside isolated profile mount) | **Broad** — carries Google `cloud-platform` scope ([`#592`](https://github.com/google-antigravity/antigravity-cli/issues/592)) | Core allowlist (`google-auth` only during `login`) |
| **GCP / Enterprise OAuth** | `--auth gcp --gcp-project <ID>` | **Yes** (inside isolated profile mount) | Scoped to GCP user/enterprise OAuth session + project/location | Core + `gcp-enterprise` |
| **ADC (read-only mount)** | `--auth adc` | **Yes** (read-only `~/.config/gcloud` mount) | Broad — full host ADC permissions | Core + `gcp-enterprise` |

### Zero-MITM `GEMINI_API_KEY` Broker (`--auth api-key`)

In `--auth api-key` mode, the workspace container **never** receives the real `GEMINI_API_KEY`:

1. `agy-container` reads `GEMINI_API_KEY` from the host environment or `--api-key-file <PATH>`, validates it strictly against Squid injection characters (only ASCII alphanumerics and `-_.+/=`, max 512 chars), and renders a per-run `/etc/squid/conf.d/api-broker.conf` mounted **only** inside the Squid sidecar.
2. Inside the workspace container, `agy-container` sets:
   - `GEMINI_API_KEY=agy-container-proxy-managed` (a worthless sentinel)
   - `GOOGLE_GEMINI_BASE_URL=http://proxy:3129`
   - `--settings '{"modelProvider":"gemini"}'` (ephemeral per-session override; does not mutate the profile's `settings.json`)
3. Squid listens on port `3129` in reverse-proxy (`accel`) mode (`defaultsite=generativelanguage.googleapis.com no-vhost`), denies `CONNECT`, denies `private_dst`, restricts paths strictly to `^/v1(beta)?/`, strips any client-supplied `X-Goog-Api-Key`, injects the real `X-Goog-Api-Key` header, and forwards exclusively over system-CA-verified TLS to `https://generativelanguage.googleapis.com:443`.
4. No MITM root CA is generated or injected into the workspace. `--auth api-key` requires the gateway and conflicts with `--no-gateway`.

### Warning: Personal OAuth `cloud-platform` Scope (`antigravity-cli#592`)

> **SECURITY WARNING (`google-antigravity/antigravity-cli#592`):**
> As of `agy` 1.5.x, the OAuth token issued during personal Google sign-in carries `https://www.googleapis.com/auth/cloud-platform` — Google's broadest GCP scope (full Cloud Run, GCS, Secret Manager, Compute, and IAM access for any GCP project accessible to that Google account), even though the consent screen displays only Antigravity branding.
>
> **How `agy-container` mitigates this — and what remains:**
> - **Mitigated in restricted mode:** `assets/squid.conf` deliberately excludes GCP control-plane APIs (`compute.googleapis.com`, `iam.googleapis.com`, `secretmanager.googleapis.com`, `storage.googleapis.com`, etc.), so an agent running inside the default restricted boundary cannot directly call GCP management endpoints or exfiltrate the token to arbitrary external hosts.
> - **Not mitigated when egress is widened:** Combining `--auth oauth` with `-n` / `--unrestricted-network`, `--no-gateway`, or `--allow updater` (which opens `storage.googleapis.com`) exposes an exfiltration path for the token file inside `/home/agy/.gemini/antigravity-cli/antigravity-oauth-token`. `agy-container` prints an explicit warning whenever `--unrestricted-network` is combined with `--auth oauth`.
> - **Recommended hardening:** Prefer `--auth api-key` for automated/untrusted repos, or sign in with a dedicated Google account that has no GCP billing/IAM privileges.

### GCP Enterprise & ADC Modes

```shell
# Gemini Enterprise / GCP OAuth (--gcp-project is required; --gcp-location defaults to "global")
agy-container --auth gcp --gcp-project my-gcp-project --gcp-location us

# Application Default Credentials (mounts ${CLOUDSDK_CONFIG:-~/.config/gcloud} read-only)
gcloud auth application-default login
agy-container --auth adc --gcp-project my-gcp-project
```

Both modes automatically enable the `gcp-enterprise` egress group.

### Isolated Profiles (`--profile`, `--isolated`)

`agy-container` **never** mounts your host `~/.gemini` or `~/.config/antigravity`. State lives under:

```
${XDG_DATA_HOME:-~/.local/share}/agy-container/profiles/<profile>/
  ├── gemini/              -> /home/agy/.gemini (rw)
  └── config-antigravity/  -> /home/agy/.config/antigravity (rw)
```

- `--profile <NAME>` (default: `default`): Selects a named isolated profile (ASCII letters, digits, `.`, `_`, `-`). Use separate profiles for personal vs. work accounts or untrusted repos.
- `--isolated`: Creates an ephemeral `0700` state directory under `/tmp/agy-container-state-<run_id>-<pid>-<stamp>` for this run and deletes it on exit (`Drop`). In `oauth`/`gcp` modes, **only** `antigravity-cli/antigravity-oauth-token` is copied (`0600`) from the named profile — SQLite databases, conversation histories, and mutable settings are not shared, preventing cross-session hook persistence and SQLite WAL lock contention during concurrent runs.

---

## Network Containment & Egress Auditing

### Network modes

| Mode | Flags | Network | Squid Policy | Private IPs Blocked? | Logged to `egress.log`? |
| --- | --- | --- | --- | --- | --- |
| **Restricted** (default) | *(none)* | `--internal` (`agy-caged-<run_id>`) | Core Antigravity domains + `--allow` / `--allow-host` | Yes (`private_dst`) | Yes |
| **Unrestricted (observed)** | `-n` / `--unrestricted-network` | `--internal` (`agy-caged-<run_id>`) | All public HTTPS/HTTP (`squid.permissive.conf`) | Yes (`private_dst`) | Yes |
| **Probe** | `--probe` | `--internal` (`agy-caged-<run_id>`) | Permissive + deadline (`--probe-timeout`, default `60`s) + traffic summary | Yes (`private_dst`) | Yes |
| **Bypass** | `--no-gateway` | Host default Podman network | None (no Squid sidecar) | **No** | **No** |

### Default core allowlist (`assets/squid.conf`)

Only HTTPS `CONNECT` to port `443` on these 8 domains is allowed by default:

- `daily-cloudcode-pa.googleapis.com`
- `cloudcode-pa.googleapis.com`
- `cloudaicompanion.googleapis.com`
- `generativelanguage.googleapis.com`
- `aicode.googleapis.com`
- `antigravity-unleash.goog`
- `oauth2.googleapis.com`
- `www.googleapis.com`

All non-`CONNECT` requests (outside port `3129`), non-`443` `CONNECT` ports, and private/metadata destinations (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `0.0.0.0/8`, `::1`, `fc00::/7`, `fe80::/10`) are denied **before** any allow rule.

### Opt-in egress groups (`--allow`) and ad-hoc domains (`--allow-host`)

Pass `--allow <GROUP>` (repeatable or comma-separated) or `--allow-host <DOMAIN>` (strictly validated FQDN; rejects schemes, ports, paths, `*`, whitespace/control chars, single labels, and raw IPv4 literals):

| Group | Domains Opened | Purpose / Auto-Enabled By |
| --- | --- | --- |
| `google-auth` | `accounts.google.com`, `lh3.googleusercontent.com`, `play.googleapis.com`, `antigravity.google` | Interactive OAuth sign-in (auto-enabled by `login`) |
| `gcp-enterprise` | `businessaicode.googleapis.com`, `businessaicode.us.rep.googleapis.com`, `businessaicode.eu.rep.googleapis.com`, `aiplatform.googleapis.com`, `aiplatform.us.rep.googleapis.com`, `aiplatform.eu.rep.googleapis.com`, `discoveryengine.googleapis.com` | Gemini Enterprise & Vertex AI (auto-enabled by `--auth gcp` / `--auth adc`) |
| `github` | `github.com`, `api.github.com`, `uploads.github.com`, `objects.githubusercontent.com`, `raw.githubusercontent.com` | GitHub HTTPS & API (auto-enabled by `--github`) |
| `npm` | `registry.npmjs.org` | npm registry |
| `pypi` | `pypi.org`, `files.pythonhosted.org` | PyPI package index |
| `crates` | `crates.io`, `static.crates.io`, `index.crates.io` | Rust crates.io |
| `go` | `proxy.golang.org`, `sum.golang.org` | Go module proxy & sumdb |
| `telemetry` | `firebaselogging-pa.googleapis.com`, `feedback-pa.googleapis.com`, `play.googleapis.com` | Antigravity telemetry & feedback |
| `updater` | `antigravity-cli-auto-updater-974169037036.us-central1.run.app`, `storage.googleapis.com`, `antigravity.google` | Antigravity CLI release manifest & download bucket |
| `remote-control` | `.antigravity.google.com`, `antigravity.google` | Antigravity browser Remote Control relay |

```shell
agy-container --allow crates,github --allow-host docs.rs -p "Update dependencies and run cargo test"
```

User edits to `~/.config/agy-container/squid.conf` take effect on the next run without rebuilding images; `agy-container` validates that both `include /etc/squid/conf.d/allow.conf` and `include /etc/squid/conf.d/api-broker.conf` remain present.

### Probing & empirical verification (`--probe`, `--self-test`, `verify-boundary`)

```shell
# Built-in positive/negative boundary probe (tests API reachability, public proxy,
# 169.254.169.254 SSRF denial, and direct 1.1.1.1:443 route blocking)
agy-container --probe --self-test

# Observe what domains an agy command actually requests under a 90s deadline
agy-container --probe --probe-timeout 90 -p "Run the test suite"

# Run the full in-container empirical verifier (capabilities, NoNewPrivs, binary
# immutability, Squid denials, SSRF denials, /dev/tcp route checks, mount writability,
# and secret-shaped file scan)
agy-container --shell -- -c verify-boundary
```

### Egress audit log (`egress.log`)

Every gateway run appends a UTC-timestamped session header, the Squid access log, and (if enabled) `git-gateway` allow/deny decisions to:

```
${XDG_STATE_HOME:-~/.local/state}/agy-container/egress.log
```

Override the destination with `AGY_EGRESS_LOG`. Each header records timestamp, run ID, network mode, auth mode, and canonical workspace path:

```
=== 2026-11-26T15:00:00Z run=agy-deadbeef net=restricted (default-deny) auth=api-key dir=/path/to/repo ===
```

---

## Workspace Mounts & SSH `--github` Sidecar

### Workspace and extra mounts

| Flag | Container Path | Mode | Notes |
| --- | --- | --- | --- |
| `-w, --workspace <DIR>` | `/workspace` | `rw` (default) | Defaults to current working directory |
| `--ro-workspace` | `/workspace` | `ro` | Kernel VFS read-only (`EROFS` on write) |
| `--ro <DIR>` (repeatable) | `/mnt/<basename>` | `ro` | Automatically passed via `--add-dir /mnt/<basename>` |
| `--rw <DIR>` (repeatable) | `/mnt/<basename>` | `rw` | Automatically passed via `--add-dir /mnt/<basename>` |

Guardrails enforced by [`src/mounts.rs`](src/mounts.rs):
- Refuses to mount filesystem root `/`.
- Refuses extra mounts duplicating the workspace directory.
- Refuses duplicate basenames (two paths mapping to `/mnt/<same-name>`).
- Automatically appends `,z` on SELinux-enforcing hosts (never `:Z`, which would relabel host trees exclusively).

### Local git & GitHub SSH gateway sidecar (`--git`, `--github[=push]`)

```shell
# Local commits only (mounts ~/.gitconfig read-only; scans and warns on inline tokens,
# credential.helper, or unmounted [include]/[includeIf] paths)
agy-container --git

# Private clone/fetch + GitHub HTTPS/API (read-only SSH gateway; push refused)
agy-container --github

# Enable push, scoped to specific repositories and a dedicated deploy key
agy-container --github=push --git-repo lmmx/agy-container --git-key ~/.ssh/deploy_agy
```

How the SSH `git-gateway` sidecar works:
- `--github` automatically implies `--git` and `--allow github` (conflicts with `--no-gateway`).
- Your real host SSH key (default `~/.ssh/id_ed25519`, overridable via `--git-key`) is mounted **only** into `agy-gitgw-<run_id>` at `/run/secrets/git-key:ro` and **never** into the workspace container. Passphrase-encrypted keys are detected and rejected upfront because the sidecar runs non-interactively (`BatchMode=yes`).
- Per-run throwaway ed25519 client and sidecar host keypairs are generated on the host, pinned via `StrictHostKeyChecking yes` against `[git-gateway]:2222`, and deleted on `Drop`.
- Inside the workspace, `GIT_CONFIG_SYSTEM=/home/agy/.gitconfig-gateway` rewrites `git@github.com:`, `ssh://git@github.com/`, and `https://github.com/` to `git-gateway:`.
- `sshd` inside the sidecar listens on unprivileged port `2222` with all forwarding disabled (`PermitTTY no`, `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `PermitTunnel no`, `AllowAgentForwarding no`, `X11Forwarding no`, `Subsystem sftp /bin/false`) and enforces `ForceCommand /usr/local/bin/git-policy` (plus `restrict,command="/usr/local/bin/git-policy"` in `authorized_keys`).
- [`assets/git-policy`](assets/git-policy) parses `SSH_ORIGINAL_COMMAND` without `eval`, fails closed if the entrypoint policy marker `AGY_GITGW_POLICY_OK=1` is absent, permits only `git-upload-pack` / `git-upload-archive` (and `git-receive-pack` only when `--github=push`), enforces `--git-repo` allowlist entries (with shell globbing disabled via `set -f`), logs `ALLOW`/`DENY` decisions to `egress.log`, and connects to GitHub with build-time pinned `/etc/ssh/github_known_hosts` (verified unconditionally against `GITHUB_SSH_FINGERPRINT`, eliminating build-time `ssh-keyscan` TOFU).
- If `--github` (read-only) is passed without `~/.ssh/id_ed25519` present, the sidecar is skipped with a note while public HTTPS access via `--allow github` remains active. `--github=push` or an explicit `--git-key` fails closed if the key is missing.

---

## Resource Limits, Concurrency & Image Updates

### Resource limits

| Flag | Env Var | Default | Behavior When cgroup v2 Controller Is Undelegated |
| --- | --- | --- | --- |
| `--memory <SIZE>` | `AGY_CONTAINER_MEM` | `8g` (`none` to disable) | Sets `--memory` and `--memory-swap` equally; skips with stderr note if undelegated |
| `--cpus <N>` | `AGY_CONTAINER_CPUS` | *(unset)* | Sets `--cpus`; skips with stderr note if undelegated |
| `--pids-limit <N>` | `AGY_CONTAINER_PIDS` | `4096` | Enforces `--pids-limit` when delegated; automatically falls back to `--ulimit nproc=<N>:<N>` when undelegated |

Sidecars carry fixed tight limits: Squid (`512m` memory, `256` pids/nproc, `--read-only` rootfs with `noexec,nosuid` tmpfs); git-gateway (`256m` memory, `256` pids/nproc).

### Concurrency & cleanup

Every invocation generates a unique `run_id` (`agy-<8hex>`) and owns its own:
- Internal & egress networks (`agy-caged-<run_id>`, `agy-egress-<run_id>`)
- Sidecar containers (`agy-proxy-<run_id>`, `agy-gitgw-<run_id>`)
- Workspace container (`agy-work-<run_id>`)
- Ephemeral temp directories (`0700`)

Multiple `agy-container` instances can run simultaneously without network or proxy collisions. For concurrent sessions sharing a profile, pass `--isolated` to avoid SQLite WAL contention on Antigravity's local database.

Signal handling:
- `SIGINT` (Ctrl-C) is forwarded to `agy` inside the container while the parent runner stays alive to capture egress logs and tear down sidecars/networks.
- `SIGTERM` triggers cooperative graceful stop (`podman stop --time 10`), log capture, full topology teardown, and exits with code `143`.

### Image builds & updating `agy`

Images build automatically on first use. Antigravity's background self-updater is disabled (`AGY_CLI_DISABLE_AUTO_UPDATE=true`), and `/usr/local/bin/agy` is installed `root:root 0555` with SHA-512 verification against Google's official release manifest (`https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/${platform}.json`).

```shell
# Rebuild all three images without cache to pull the latest verified agy release
agy-container update-image

# Rebuild images with cache before launching a session
agy-container -b

# Rebuild with --no-cache before launching a session
agy-container --update
```

Set `AGY_BASE_IMAGE` to override the Debian base image for `localhost/agy-container-agy:latest` (scoped strictly to the workspace image; Alpine sidecars keep their pinned base), and `GITHUB_SSH_FINGERPRINT` to override the pinned SHA-256 GitHub host key fingerprint checked unconditionally when building `localhost/agy-container-gitgateway:latest`.

---

## Known Limits & Manual OAuth Validation

### Known limits

1. **OAuth token resides inside the container in `oauth`/`gcp`/`adc` modes.** Only `--auth api-key` keeps the real secret completely out of the workspace via the port-`3129` reverse proxy. See [`docs/adr/003-auth-isolation-and-brokerage.md`](docs/adr/003-auth-isolation-and-brokerage.md).
2. **CONNECT host allowlisting is destination-level, not operation-level.** Squid inspects SNI/`CONNECT` hostnames only; any HTTPS path on an allowed domain (e.g., `github.com` under `--allow github`) is reachable. Operation-level git enforcement happens exclusively through the SSH `git-gateway` sidecar.
3. **Persistent profile directories survive `--rm`.** Without `--isolated`, `/home/agy/.gemini` is writable across sessions, which includes `settings.json` and `~/.gemini/config/hooks.json`. Use `--isolated` or dedicated `--profile <NAME>` directories for untrusted repositories.
4. **Single-mapping rootless mode (missing `/etc/subuid` / `/etc/subgid`).** On hosts without subordinate UID/GID ranges (such as minimal CI/devbox VMs), Podman cannot use `--userns=keep-id:uid=1000,gid=1000`. When `crun` is installed, `agy-container` runs strictly non-root using single-UID mapping (`--runtime crun --uidmap 1000:0:1 --user 1000:1000` for `agy` and `31:0:1 --user 31:31` for Squid, with matching `net.ipv4.ping_group_range`, `--cap-drop=ALL`, and `no-new-privileges`). In single-mapping mode the single mapped UID owns image files (so `/usr/local/bin/agy` immutability against `chmod` requires `/etc/subuid` + `--userns=keep-id`), and `--github` `git-gateway` requires `/etc/subuid` for `sshd` privilege separation (`gitgw`).
5. **Nested `--sandbox` is incompatible with hardened containers.** Antigravity's built-in Linux terminal sandbox (`bubblewrap`/user namespaces) cannot create nested user namespaces under `--cap-drop=ALL --security-opt=no-new-privileges:true`. `agy-container` warns if you pass `--sandbox`; see [`docs/adr/004-nested-sandboxing.md`](docs/adr/004-nested-sandboxing.md).
6. **`--remote-agent` crosses outside the local container.** Passing `--remote-agent` delegates tool execution to Google-managed cloud VMs outside `agy-container`'s network and filesystem boundary. `agy-container` emits an explicit notice.
7. **Read-only mounts stop writes, not reads.** Secret-shaped files (`.env`, `*.pem`, keys) inside `/workspace` or `--ro` mounts remain readable by the agent. Run `verify-boundary` inside `--shell` to audit mounted trees.
8. **`SIGKILL` (`kill -9`) bypasses RAII cleanup.** If the runner is forcibly killed, clean up any orphaned resources with:
   ```shell
   podman ps -a --filter label=agy-container.run -q | xargs -r podman rm -f
   podman network ls --format '{{.Name}}' | grep -E '^agy-(caged|egress)-' | xargs -r podman network rm -f
   ```

### Manual OAuth validation steps

Automated CI and `tests/podman_live.sh` verify image builds, SHA-512 manifest verification, Squid config parsing across all 10 `--allow` groups and the port-`3129` broker, kernel capabilities, SSRF blocking, mount boundaries, concurrent runs, and `SIGTERM` cleanup. Because personal Google OAuth requires interactive browser sign-in against a live Google account, validate OAuth manually after installing:

1. **Check host preconditions:**
   ```shell
   agy-container doctor
   ```
2. **Complete headless OAuth login into a test profile:**
   ```shell
   agy-container --profile oauth-check login
   ```
   Open the printed `accounts.google.com` URL in your host browser, sign in, copy the `http://localhost:36742/oauth-callback?...` URL from the address bar, and paste it back into the terminal.
3. **Verify host isolation:** Confirm `~/.gemini` on your host was not created or modified, and that the token exists solely at `~/.local/share/agy-container/profiles/oauth-check/gemini/antigravity-cli/antigravity-oauth-token`.
4. **Verify inference under default-deny egress (without `google-auth`):**
   ```shell
   agy-container --profile oauth-check --model gemini-4-neon-xhigh -p "Reply with exactly OK"
   ```
5. **Verify hourly refresh & audit log:** Inspect `~/.local/state/agy-container/egress.log` to confirm only `agy_core` domains (such as `daily-cloudcode-pa.googleapis.com` / `cloudcode-pa.googleapis.com` / `oauth2.googleapis.com`) were contacted and no unexpected denials occurred.
6. **Verify `--isolated` token-only copy:**
   ```shell
   agy-container --profile oauth-check --isolated -p "Reply with exactly OK"
   ```
   Confirm the run succeeds without writing a new conversation entry into `profiles/oauth-check/`.

---

## Testing

```shell
# Unit & end-to-end tests (stub Podman, runs anywhere without containers)
cargo test

# Standalone POSIX git-policy security test suite
sh assets/git-policy-test.sh

# Live rootless Podman verification suite (builds all 3 images & verifies real boundaries)
bash tests/podman_live.sh
```

## License

MIT — see [`LICENSE`](LICENSE).
