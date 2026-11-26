# ADR-004: Outer Container as the Security Boundary (No Nested Linux Sandboxing)

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Google Antigravity includes a built-in OS-level terminal sandbox for host installations (using Seatbelt/`sandbox-exec` on macOS, AppContainer process security environments on Windows, and Linux kernel namespaces / `bubblewrap` on Linux — also discussed in the community alongside Antigravity desktop's `exebox` terminal isolation). On Linux hosts, `agy --sandbox` or `"enableTerminalSandbox": true` (and `auto` mode) spawns shell commands inside unprivileged Linux user, mount, PID, and network namespaces to hide `~/.ssh`, `.env`, and host files from agent commands.

When running `agy` inside a hardened rootless Podman container, we evaluated whether to enable Antigravity's inner Linux terminal sandbox (`--sandbox` / `bubblewrap`) alongside the outer Podman container.

Empirical behavior and Linux kernel mechanics revealed a fundamental conflict:

1. **Blocked by container hardening:** `agy-work-<run_id>` runs with `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, and stripped setuid/setgid binaries inside an already-nested rootless Podman user namespace. Creating an additional layer of unprivileged user/mount namespaces (`unshare(CLONE_NEWUSER | CLONE_NEWNS)` / `bwrap`) is blocked by seccomp/AppArmor/kernel restrictions inside hardened containers and causes Antigravity's own sandbox capability probe to detect that the sandbox is unavailable (as documented in [Google Antigravity Terminal Sandbox docs](https://antigravity.google/docs/sandbox/) for containers that block unprivileged user namespaces).
2. **Enabling nested namespaces would weaken the outer boundary:** Making `bubblewrap` work inside the container would require relaxing container confinement (such as adding `CAP_SYS_ADMIN`, disabling seccomp or AppArmor confinement, or loosening `no-new-privileges`), which expands the kernel attack surface far beyond what an inner process-level sandbox protects.
3. **Deprecated `unsandboxed(*)` rules cause warnings:** Newer Antigravity CLI versions deprecate `unsandboxed(*)` permission rules in `settings.json` in favor of plain `command(*)` allow rules for personal accounts.

## Decision

`agy-container` treats the **outer rootless Podman container + `--internal` network + Squid egress gateway** as the sole OS-level security boundary and **does not** attempt to run nested Linux user-namespace sandboxing inside the container:

1. **Default `settings.json` omits `enableTerminalSandbox` and `unsandboxed(*)`.** [`render_default_settings`](../../src/auth.rs) seeds clean container-appropriate defaults (`agentMode: "accept-edits"`, `artifactReviewPolicy: "always-proceed"`, `toolPermission: "always-proceed"`, `allowNonWorkspaceAccess: "allow"`, `permissions.allow` with `command(*)`, `execute_url(*)`, `mcp(*)`, `read_file(*)`, `read_url(*)`, `write_file(*)`, and `trustedWorkspaces: ["/workspace"]`) unless `--strict-permissions` is specified.
2. **Outer container stays maximally hardened.** `agy-work-<run_id>` always runs with `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, stripped setuid/setgid bits, and no `sudo`/`iptables`/`bubblewrap` installed in [`assets/Containerfile.agy`](../../assets/Containerfile.agy).
3. **Auto-approval paired cleanly with outer containment.** Unless `--strict-permissions` is passed, `agy-container` forwards `--dangerously-skip-permissions --mode accept-edits` (matching both tool approval and edit approval in `agy`) so interactive and `/swarm` sessions run without approval deadlocks inside the outer sandbox.
4. **Explicit user warning on `--sandbox`.** If the user explicitly passes `--sandbox`, `agy-container` still forwards it to `agy` (respecting user intent) while emitting a clear stderr warning explaining that `--sandbox` relies on Linux user namespaces (`bubblewrap`/`exebox`) which are blocked under `--cap-drop=ALL --no-new-privileges`, and that the outer Podman container + Squid gateway is the enforced boundary.

## Consequences

### Positive

- **Stronger, simpler kernel posture:** The workspace container retains `--cap-drop=ALL`, `no-new-privileges:true`, default Podman seccomp filtering, and zero setuid binaries.
- **No silent sandbox failures or `unsandboxed(*)` deprecation warnings:** `agy` starts cleanly in both interactive and headless modes without falling back unpredictably or hanging on blocked `unshare()` calls.
- **Clear separation of responsibilities:** Host-level isolation (network routes, host `~/.ssh`, credential brokerage, read-only mounts) is enforced outside the container by the kernel and sidecars, where nothing inside the workspace can disable or bypass it.

### Negative / Trade-offs

- **No in-container `.env` hiding from `agy` commands:** On a bare host, Antigravity's terminal sandbox can mask `.env` inside the project tree from shell commands. Inside `agy-container`, any file present inside `/workspace` (or `--ro`/`--rw` mounts) is readable by commands running in the container. Users must audit mounted trees (assisted by `verify-boundary`'s secret-shaped file scan) and avoid mounting parent directories containing unrelated secrets.
- **No defense-in-depth between `agy` and its own child shell commands:** If a user wants human-in-the-loop approval before individual commands execute inside the container, they must pass `--strict-permissions` (or `--mode plan`).
