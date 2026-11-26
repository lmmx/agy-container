# Threat Model: `agy-container`

This document defines the trust boundaries, Antigravity-specific attack vectors, implemented mitigations, and residual risks of `agy-container`.

One-sentence security invariant: **an untrusted Antigravity CLI workspace (including all `/swarm` workers, subagents, build scripts, and MCP tools it spawns) runs without host credentials or a direct route to the network, and can reach external services only through hardened, per-run sidecars that it cannot reconfigure.**

---

## 1. Trust Boundaries

```
+===========================================================================+
| ZONE 1: TRUSTED HOST                                                      |
|  - agy-container Rust binary (zero external crates)                       |
|  - Host ~/.gemini, ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube (never mounted)      |
|  - Real GEMINI_API_KEY (env or --api-key-file)                            |
|  - Real host SSH key (--git-key / ~/.ssh/id_ed25519)                      |
|  - User-editable ~/.config/agy-container/squid.conf                       |
|  - Isolated profiles (~/.local/share/agy-container/profiles/<name>/)      |
|  - Egress audit log (~/.local/state/agy-container/egress.log)             |
+=====================================+=====================================+
                                      | bind mounts & generated fragments
                                      v
+===========================================================================+
| ZONE 2: TRUSTED SIDECARS (HIGH-VALUE TARGETS)                             |
|  Straddle agy-egress-<run_id> (routed) and agy-caged-<run_id> (--internal)|
|                                                                           |
|  +----------------------------------+  +-------------------------------+  |
|  | agy-proxy-<run_id> (Squid 6.9)   |  | agy-gitgw-<run_id> (OpenSSH)  |  |
|  | - USER squid, --read-only rootfs |  | - port 2222, ForceCommand     |  |
|  | - --cap-drop=ALL, NNP, 512m/256  |  | - real host SSH key (0400)    |  |
|  | - :3128 forward CONNECT proxy    |  | - pinned GitHub host key      |  |
|  | - :3129 zero-MITM API key broker |  | - git-policy (no eval)        |  |
|  +----------------+-----------------+  +---------------+---------------+  |
+===================|====================================|==================+
                    |  agy-caged-<run_id> (--internal)   |
                    |  no default route; pinned /etc/hosts
                    v                                    v
+===========================================================================+
| ZONE 3: UNTRUSTED WORKSPACE (agy-work-<run_id>)                           |
|  - /usr/local/bin/agy (SHA-512 verified, root:root 0555)                  |
|  - /workspace (rw or --ro-workspace) + explicit --ro / --rw at /mnt/<name>|
|  - /home/agy/.gemini & /home/agy/.config/antigravity (isolated profile)   |
|  - All /swarm workers, subagents, shell commands, compilers, MCP servers  |
|  - --cap-drop=ALL, no-new-privileges, no setuid/setgid, 8g/4096 limits    |
+===========================================================================+
                                      | (via Zone 2 only)
                                      v
+===========================================================================+
| ZONE 4: EXTERNAL SERVICES                                                 |
|  - Google Antigravity / Gemini APIs (agy_core + optional gcp-enterprise)  |
|  - GitHub SSH (git@github.com) & HTTPS APIs (if --github / --allow github)|
|  - Opt-in package registries (--allow npm|pypi|crates|go) or --allow-host |
+===========================================================================+
```

### Trust assumptions

- **Zone 1 (Host) is trusted.** `agy-container` does not defend against a compromised host kernel, host root compromise, or a malicious user editing their own `~/.config/agy-container/squid.conf`.
- **Zone 2 (Proxy & Git-Gateway sidecars) are trusted enforcers and therefore high-value attack targets.** Because Zone 2 holds the real `GEMINI_API_KEY` (in `--auth api-key` mode) and/or the real host SSH key (in `--github` mode) and bridges `agy-caged-<run_id>` to `agy-egress-<run_id>`, any vulnerability in Squid (`6.9-r0`), OpenSSH (`9.7_p1-r6`), or [`assets/git-policy`](../assets/git-policy) compromises containment. Both sidecars are hardened accordingly: pinned Alpine package versions, `--cap-drop=ALL` (with only the minimal `SETUID`, `SETGID`, `CHOWN`, `DAC_OVERRIDE`, `SYS_CHROOT`, `KILL` added back to `sshd`), `--security-opt=no-new-privileges:true`, tight memory/PID limits, and `--read-only` rootfs with `noexec,nosuid` tmpfs on Squid.
- **Zone 3 (Workspace container) is fully untrusted.** Assume prompt injection, malicious repo scripts, or a compromised subagent can execute arbitrary commands as the container user, read every file mounted into `/workspace`, `/mnt/*`, and `/home/agy/`, and actively attempt lateral movement or exfiltration.
- **Zone 4 (External Google & GitHub APIs) are external trust anchors.** TLS certificates are verified against the standard CA bundle (`ca-certificates`); GitHub's published SSH ed25519 host key is baked directly into `/etc/ssh/github_known_hosts` and verified unconditionally against `GITHUB_SSH_FINGERPRINT` at build time (no build-time `ssh-keyscan` TOFU).

---

## 2. Antigravity-Specific Threats & Mitigations

### 2.1 Over-Broad OAuth Scope (`cloud-platform`, `antigravity-cli#592`)

- **Threat:** Personal Google OAuth sign-in in `agy` issues a token carrying `https://www.googleapis.com/auth/cloud-platform` (verified via Google's `tokeninfo` endpoint in [`google-antigravity/antigravity-cli#592`](https://github.com/google-antigravity/antigravity-cli/issues/592)), alongside `userinfo.email`, `userinfo.profile`, `cclog`, and `experimentsandconfigs`. The consent screen displays only Antigravity branding. If an untrusted process inside the workspace reads `/home/agy/.gemini/antigravity-cli/antigravity-oauth-token`, that token grants full GCP control-plane authority (Cloud Run, Compute Engine, Cloud Storage, Secret Manager, IAM) across projects accessible to that Google account.
- **Mitigations in `agy-container`:**
  1. **Zero-MITM API key brokerage (`--auth api-key`):** Completely eliminates the OAuth token from the container. The real `GEMINI_API_KEY` lives exclusively in Squid's per-run `/etc/squid/conf.d/api-broker.conf` on port `3129`, blocking `CONNECT` and dot-segment traversal (`..` / `%2e`), scoped solely to `^/v1(beta)?/` on `https://generativelanguage.googleapis.com`.
  2. **GCP control-plane API exclusion in default egress:** `assets/squid.conf`'s `agy_core` ACL admits only the 8 Antigravity/Gemini inference, feature-flag, and OAuth refresh domains (`daily-cloudcode-pa.googleapis.com`, `cloudcode-pa.googleapis.com`, `cloudaicompanion.googleapis.com`, `generativelanguage.googleapis.com`, `aicode.googleapis.com`, `antigravity-unleash.goog`, `oauth2.googleapis.com`, `www.googleapis.com`). Control-plane endpoints such as `compute.googleapis.com`, `iam.googleapis.com`, `secretmanager.googleapis.com`, `run.googleapis.com`, and `storage.googleapis.com` are denied (`403`), empirically verified by [`assets/verify-boundary.sh`](../assets/verify-boundary.sh) and [`tests/podman_live.sh`](../tests/podman_live.sh).
  3. **Container-only profile isolation:** Host `~/.gemini` is never mounted, so an existing host Antigravity session cannot be silently harvested.
  4. **Explicit blast-radius warning:** Combining `--unrestricted-network` (`-n`) with `--auth oauth` triggers an explicit stderr warning referencing `#592` and recommending `--allow <group>` or `--auth api-key`.
- **Residual risk:** In `--auth oauth` mode, the token file *is* readable inside the container. If the user opens arbitrary egress (`-n`, `--no-gateway`), allows a writable exfiltration sink (`--github=push`, `--allow updater` which includes `storage.googleapis.com`), or uses a Google account with production GCP IAM roles, the token can be exfiltrated and replayed from outside the container.

### 2.2 Multi-Worker `/swarm` Blast Radius & Workspace Copies

- **Threat:** Antigravity's `/swarm` orchestrator (and custom subagents via `invoke_subagent`) spawns multiple parallel workers on a shared task board. By default, `/swarm` workers share the same workspace directory; optionally, the coordinator can assign separate repository copies or Git worktrees. Because `agy-container` enables autonomous execution (`--dangerously-skip-permissions --mode accept-edits`) unless `--strict-permissions` is passed, a prompt injection encountered by *one* worker (for example, a researcher reading an untrusted dependency or web fixture) can:
  - Modify files read or executed by sibling workers in `/workspace`.
  - Write malicious hooks into `/workspace/.agents/hooks.json` or `/home/agy/.gemini/config/hooks.json` that execute on every subsequent worker tool call.
  - Exhaust host CPU, memory, or PID tables across parallel compiler/test invocations.
- **Mitigations in `agy-container`:**
  1. **Uniform outer containment:** Every `/swarm` worker, subagent, and worktree executes inside the same rootless Podman container (`agy-work-<run_id>`), inheriting `--cap-drop=ALL`, `no-new-privileges`, internal-only networking, and mount restrictions (`--ro-workspace`, `--ro`). No worker can escape to the host filesystem or open a direct socket.
  2. **Swarm-sized hard resource ceilings:** Default `--memory 8g` (`--memory-swap=8g`) and `--pids-limit 4096` (with `--ulimit nproc` fallback when cgroup v2 `pids` is undelegated) bound the aggregate footprint of the entire swarm.
  3. **Ephemeral state isolation (`--isolated`):** Prevents a compromised worker from leaving persistent hooks or poisoned settings in the reusable profile directory.
- **Residual risk:** Within a single container, `agy-container` does not isolate `/swarm` workers from *each other*. All workers share `/workspace` (unless read-only), `/home/agy/.gemini`, and the same container UID. See [`docs/adr/002-single-container-per-swarm.md`](adr/002-single-container-per-swarm.md).

### 2.3 `--remote-agent` Boundary Shift

- **Threat:** Passing `--remote-agent` instructs `agy` to delegate tool execution to Google-managed cloud VMs rather than running tools locally. Any workspace context uploaded to a remote agent leaves the local Podman container's network egress policy, filesystem read-only enforcement, and local audit log (`egress.log`).
- **Mitigations in `agy-container`:**
  - `agy-container` explicitly recognizes `--remote-agent` and prints a clear boundary-shift notice on stderr (`--remote-agent delegates tool execution to Google-managed cloud VMs outside this local container boundary`).
  - Default egress only permits `agy_core` domains; if remote-control relays (`.antigravity.google.com`) are needed, they require explicit `--allow remote-control`.
- **Residual risk:** Because `--remote-agent` communicates over the already-permitted Google Antigravity control channel (`agy_core`), `agy-container` cannot inspect or filter what happens inside a Google-managed cloud VM once the user opts into `--remote-agent`.

### 2.4 Prompt Injection & Untrusted Dependencies

- **Threat:** Malicious instructions embedded in repository files (`README.md`, comments, test fixtures, git commit messages), fetched packages (`npm` `postinstall`, Cargo `build.rs`, Python `setup.py`), or tool outputs can hijack the agent into running arbitrary shell commands inside `/workspace`.
- **Mitigations in `agy-container`:**
  1. **Default-deny egress:** Even with full arbitrary shell execution inside the container, `curl https://attacker.example` returns `403` from Squid, and raw TCP/UDP/DNS (`/dev/tcp/1.1.1.1/443`, `dig @1.1.1.1`) fails at the kernel routing layer because `agy-caged-<run_id>` has no default route.
  2. **Immutable CLI binary:** `/usr/local/bin/agy` is installed `root:root 0555` after SHA-512 verification against Google's manifest (protected against modification and `chmod` when `--userns=keep-id:uid=1000,gid=1000` is active), and `AGY_CLI_DISABLE_AUTO_UPDATE=true` disables background self-modification.
  3. **Credential separation:** Host `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, and `~/.gemini` are never mounted. Under `--auth api-key` and `--github`, neither the Gemini API key nor the host SSH key ever enters the workspace container.
  4. **Kernel-enforced read-only mounts:** `--ro-workspace` and `--ro <DIR>` enforce `EROFS` at the VFS layer, unaffected by in-process agent permissions.
- **Residual risk:**
  - **Covert exfiltration via allowed channels:** Any text the agent reads in `/workspace` or `--ro` mounts can be included in prompts sent to Google's APIs, or pushed to a writable GitHub repo if `--github=push` is enabled.
  - **Writable workspace tampering:** In default read-write mode, prompt injection can still modify files inside `/workspace` (including `.git/hooks/` or build scripts that a developer might later execute on the host). Review `git diff` / `git status` on the host before running host-side commands after an untrusted session.

### 2.5 SSRF, DNS Rebinding & Cloud Metadata Probing

- **Threat:** An agent or compromised build tool may attempt to pivot through the Squid proxy (which *does* sit on `agy-egress-<run_id>` with host routing) to reach host loopback services (`127.0.0.1`), host LAN / corporate intranet hosts (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`), cloud instance metadata (`169.254.169.254`), or use a public domain that resolves to a private IP (DNS rebinding).
- **Mitigations in `agy-container`:**
  1. **`private_dst` ACL enforced in BOTH restricted and permissive modes:** Both [`assets/squid.conf`](../assets/squid.conf) and [`assets/squid.permissive.conf`](../assets/squid.permissive.conf) define:
     ```
     acl private_dst dst 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 0.0.0.0/8 ::1 fc00::/7 fe80::/10
     http_access deny  private_dst
     ```
     Because Squid evaluates `dst` ACLs against the resolved destination IP address **before** every `http_access allow` rule (verified by unit tests in [`src/assets.rs`](../src/assets.rs)), both literal private IPs and domains resolving to private IPs are blocked with HTTP `403`.
  2. **Strict `--allow-host` validation ([`src/allow.rs`](../src/allow.rs)):** Rejects raw IPv4 literals, single-label hostnames (`localhost`), wildcards (`*`), ports, paths, schemes, and whitespace/control characters (preventing Squid config injection).
  3. **Port-`3129` broker hardening:** The API key broker explicitly denies `CONNECT`, denies `private_dst`, denies paths outside `^/v1(beta)?/`, and forces `cache_peer` to `generativelanguage.googleapis.com:443` with `never_direct allow gemini_broker_port`.
  4. **Direct route isolation:** Because `agy-caged-<run_id>` is `--internal`, direct connections to `169.254.169.254:80` or host LAN IPs fail without leaving the network namespace.
- **Residual risk:** Classical time-of-check/time-of-use (TOCTOU) DNS rebinding across a 0-TTL record between Squid's ACL resolution and connection establishment is reduced by Squid's internal DNS cache, but only in `-n` / `--allow-host <untrusted-domain>` modes; in default restricted mode only Google-controlled `agy_core` domains are allowed.

### 2.6 MCP Servers & Lifecycle Hooks (`hooks.json`)

- **Threat:** Antigravity supports:
  - **Lifecycle hooks** configured globally at `~/.gemini/config/hooks.json` (and `~/.gemini/antigravity-cli/hooks.json`) or per-workspace at `<workspace>/.agents/hooks.json` (`PreInvocation`, `PreToolUse`, `PostToolUse`, `PostInvocation`, `Stop`), which execute arbitrary shell commands.
  - **MCP servers** (configured via `agy mcp add` or workspace plugins/agents), which spawn local stdio processes or connect to remote HTTP endpoints.
  An untrusted repository containing `.agents/hooks.json` or `.agents/agents/*.md` with `mcpServers`, or a compromised session writing a persistent hook into `/home/agy/.gemini/config/hooks.json`, can achieve silent persistence across runs in the same profile.
- **Mitigations in `agy-container`:**
  1. **Host hooks & MCP configs are untouched:** Host `~/.gemini` is never mounted, so container runs cannot poison host `agy` sessions, and host MCP servers with host credentials are invisible inside the container.
  2. **Hook & MCP processes stay inside the container boundary:** Any command launched by `hooks.json` or a stdio MCP server runs inside `agy-work-<run_id>` under the same `--cap-drop=ALL`, `no-new-privileges`, and Squid egress containment. Remote MCP endpoints are blocked unless explicitly allowlisted via `--allow-host`.
  3. **Cross-session persistence eliminated by `--isolated`:** Passing `--isolated` mounts an ephemeral `/tmp/agy-container-state-*` directory deleted on `Drop`, so any hook or MCP registration written during a run cannot survive into future sessions.
- **Residual risk:** In persistent profile mode (default, without `--isolated`), `/home/agy/.gemini` is writable across sessions. A compromised run can write a malicious hook to `~/.local/share/agy-container/profiles/<profile>/gemini/config/hooks.json` that executes in future sessions sharing that same profile. Use `--isolated` or per-repo `--profile <name>` when working with untrusted codebases.

### 2.7 Browser & External Tools

- **Threat:** Antigravity supports `/browser` automation (connecting to Chrome or launching a local browser) and opening host browsers for OAuth flows (`localhost:36742`). Exposing host display sockets (X11/Wayland), D-Bus, or Chrome debugging ports into a container breaks host isolation.
- **Mitigations in `agy-container`:**
  - `agy-container` **never** mounts X11 (`/tmp/.X11-unix`), Wayland sockets, D-Bus, or host Chrome profiles, and does not install a browser in [`assets/Containerfile.agy`](../assets/Containerfile.agy).
  - Sets `NO_BROWSER=true` and `SSH_CONNECTION="agy-container 0 agy-container 0"` unconditionally so `agy` never attempts to spawn a browser or bind a local OAuth callback server.
- **Residual risk:** Workflows requiring `/browser` UI verification cannot use the host browser from inside `agy-container` (by design).

### 2.8 SQLite WAL Cross-Session Interference

- **Threat:** Antigravity stores conversation history, state, and metadata in local SQLite databases (often in WAL mode) under `~/.gemini/`. Running two concurrent `agy-container` sessions against the same mutable profile directory can cause SQLite `SQLITE_BUSY` / lock contention, WAL corruption, or unintended cross-session state bleed (including background OAuth token refresh clobbering).
- **Mitigations in `agy-container`:**
  - Every run gets completely independent Podman networks and sidecar containers (`run_id = agy-<8hex>`), so concurrent runs never collide at the container/network layer.
  - Passing `--isolated` creates a fresh per-run state directory and copies **only** `antigravity-cli/antigravity-oauth-token` (`0600`) in `oauth`/`gcp` modes — never the SQLite database, WAL files, conversation transcripts, or mutable `settings.json`.
  - Users can also assign dedicated `--profile <name>` directories per project or worker pool.
- **Residual risk:** Running multiple concurrent sessions *without* `--isolated` against the same `--profile` still shares the bind-mounted `~/.local/share/agy-container/profiles/<profile>/gemini` directory; pass `--isolated` (or distinct `--profile` values) for parallel runs.

### 2.9 Resource Exhaustion

- **Threat:** Runaway `/swarm` fan-out, recursive builds, fork bombs, or memory leaks can freeze or OOM-kill the host workstation.
- **Mitigations in `agy-container`:**
  - Workspace defaults: `--memory=8g` and `--memory-swap=8g` (preventing swap thrashing when cgroup v2 `memory` is delegated), optional `--cpus`, and `--pids-limit=4096` (automatically falling back to `--ulimit nproc=4096:4096` when cgroup v2 `pids` is undelegated).
  - Sidecar caps: Squid (`512m`, `256` pids/nproc, bounded tmpfs `16m`/`8m`/`16m`); git-gateway (`256m`, `256` pids/nproc).
  - Probe wall-clock deadline: `--probe-timeout` (default `60`s) stops hung sessions automatically.
- **Residual risk:**
  - On Linux hosts where systemd has **not** delegated the cgroup v2 `memory` or `cpu` controller to the user slice (`/sys/fs/cgroup/user.slice/user-<uid>.slice/cgroup.controllers`), rootless Podman cannot enforce `--memory` or `--cpus`. `agy-container` detects this via [`src/host.rs`](../src/host.rs), reports it in `agy-container doctor`, prints a stderr note, and still enforces `RLIMIT_NPROC` for process limits.
  - Disk quota on `/workspace` and container overlayfs is not capped by `agy-container`; a runaway process writing gigabytes into `/workspace` can fill the host filesystem.

---

## 3. Summary of Guarantees vs. Non-Guarantees

### What `agy-container` Guarantees

- **No direct internet or host-LAN route from the workspace** (when `--no-gateway` is not used and `--precondition` passes).
- **No host secrets mounted by default** (`~/.gemini`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube` are never mounted).
- **Zero-exposure `GEMINI_API_KEY` in `--auth api-key` mode:** the real key never enters the workspace container, environment, or command line; Squid injects `X-Goog-Api-Key` only for `^/v1(beta)?/` on `generativelanguage.googleapis.com:443` over verified TLS without MITM CAs.
- **Zero-exposure host SSH key in `--github` mode:** the host SSH private key is mounted only in `agy-gitgw-<run_id>`; the workspace holds only a per-run throwaway keypair, and `git-policy` enforces read-only vs. push and optional `--git-repo` allowlists without `eval`.
- **SSRF / private-IP / cloud-metadata blocking across all Squid modes** (restricted, `-n`, and `--probe`), enforced before allow rules.
- **Kernel-enforced privilege reduction:** `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, stripped setuid/setgid bits, and kernel VFS `:ro` mounts for `--ro-workspace` and `--ro`.
- **Per-run isolation and deterministic cleanup:** distinct networks/sidecars per `run_id`, RAII `Drop` cleanup, and cooperative `SIGTERM` teardown.

### What `agy-container` Does NOT Guarantee

- **Does not hide OAuth tokens inside the workspace in `--auth oauth`, `--auth gcp`, or `--auth adc` modes.** Use `--auth api-key` (or a GCP-privilege-free Google account) when operating on untrusted repositories.
- **Does not inspect TLS payloads on port `3128`.** Any HTTPS operation permitted by a destination domain (e.g., creating a public GitHub gist under `--allow github`) passes through an opaque `CONNECT` tunnel.
- **Does not filter payload contents on `--github=push`.** A push carrying leaked `.env` secrets is indistinguishable at the git protocol layer from a legitimate code push. Always scope `--github=push` with `--git-repo <owner/repo>` and a dedicated deploy key (`--git-key`).
- **Does not prevent reading secrets already inside `/workspace` or `--ro` mounts.** Read-only mounts stop writes, not reads. Audit mounts with `verify-boundary`.
- **Does not isolate `/swarm` workers from each other** inside the same container.
- **Does not protect against a host kernel exploit or container breakout.** With `--userns=keep-id:uid=1000,gid=1000`, a container escape lands as your host UID (not root, and not a separate subuid). In single-mapping mode (when `/etc/subuid` is missing and `crun` maps the host UID to non-root UID `1000`), that single mapped UID owns image files as well, so `/usr/local/bin/agy` can be `chmod`'d inside the ephemeral overlay layer and `--github` `git-gateway` requires `/etc/subuid` for `sshd` privilege separation.
- **Does not govern execution inside `--remote-agent` cloud VMs** or when `--no-gateway` is explicitly passed.
- **Does not enforce memory/CPU limits on hosts without cgroup v2 delegation** (reported explicitly by `agy-container doctor`).
- **Cannot run RAII cleanup after `SIGKILL` (`kill -9`).**
