# ADR-002: Single Container per `/swarm` Session

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Google Antigravity CLI (`agy`) natively supports multi-agent orchestration inside a single CLI session:
- **`/swarm`**: turns a conversation into a coordinator that spawns named parallel workers and a verifier sharing a live message board and (by default) the workspace directory, or optional separate working copies / Git worktrees.
- **`/boost` and `/teamwork`**: run multi-stage reasoning and milestone audit pipelines using concurrent background subagents.
- **Custom subagents (`invoke_subagent`)**: spawn asynchronous subagents (up to nesting depth 10) executing shell commands, compilers, and test runners concurrently.

When designing `agy-container`, we evaluated two containerization topologies for multi-agent runs:

1. **Container-per-worker:** Attempt to intercept Antigravity's subagent spawning (or require users to launch separate containers manually and wire them via ACP/MCP) so every `/swarm` worker gets its own container.
2. **Single container per `agy` session (and therefore per `/swarm`):** Run the primary `agy` coordinator, its embedded local language server, and all `/swarm` workers / subagents inside one hardened workspace container (`agy-work-<run_id>`), sized appropriately for parallel workloads, while supporting full concurrency across *separate* `agy-container` sessions.

## Decision

`agy-container` adopts **one hardened container per `agy` session (single container per `/swarm`)**, configured specifically for Antigravity's multi-worker execution model:

1. **Swarm-sized default resource limits:**
   - Memory default raised from `4g` (`claude-container`) to **`8g`** (`--memory=8g --memory-swap=8g`, configurable via `--memory` / `AGY_CONTAINER_MEM`).
   - Process limit default raised from `2048` (`claude-container`) to **`4096`** (`--pids-limit=4096`, configurable via `--pids-limit` / `AGY_CONTAINER_PIDS`, with automatic `--ulimit nproc` fallback when cgroup v2 `pids` is undelegated).
   - Optional CPU quota via `--cpus` / `AGY_CONTAINER_CPUS`.
2. **Loopback proxy bypass for internal IPC:** Sets `NO_PROXY=localhost,127.0.0.1,::1,proxy,git-gateway` (and lowercase `no_proxy`) so Antigravity's embedded loopback gRPC/HTTP server and subagent IPC never traverse Squid port `3128` (where `private_dst` would reject loopback).
3. **Uniform security boundary across all workers:** Every `/swarm` worker, verifier, Git worktree, and stdio MCP server inherits the outer container's `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--internal` network (`agy-caged-<run_id>`), Squid egress policy, and kernel VFS `:ro` mounts without requiring Docker/Podman socket access inside the container.
4. **No container socket mounting:** `agy-container` explicitly refuses to mount a Podman or Docker socket into the workspace (which would be required for a container-per-worker spawn model and would effectively grant host escape).
5. **Cross-session isolation via per-run topologies + `--isolated`:** Users who want completely separate blast radii for independent tasks can run multiple concurrent `agy-container --isolated` sessions side by side, each with its own networks, sidecars, and ephemeral state directory.

## Consequences

### Positive

- **Zero friction with native `/swarm`, `/boost`, `/teamwork`, and `invoke_subagent`:** Antigravity's built-in coordinator, shared message board, worktrees, and `/agents` panel work unmodified out of the box.
- **No Podman/Docker socket exposure:** Avoids the catastrophic security regression of giving an untrusted agent access to a container runtime socket to spawn sibling containers.
- **Aggregate resource protection:** One memory ceiling (`8g`) and one PID/nproc ceiling (`4096`) reliably bound the total host impact of an entire `/swarm` fan-out.
- **Unified egress auditing:** Every worker's outbound HTTPS request flows through `agy-proxy-<run_id>` and is recorded under one session header in `egress.log`.

### Negative / Trade-offs

- **No worker-to-worker isolation within a single `/swarm`:** If one worker is compromised by prompt injection (e.g., while inspecting an untrusted dependency), it shares `/workspace`, `/home/agy/.gemini`, and the container UID with sibling workers in the same swarm.
- **Coarse-grained per-worker egress:** All workers in a `/swarm` share the same Squid allowlist (`--allow` / `--allow-host`) for that run; you cannot, for instance, grant `crates` egress to Worker A while denying it to Worker B within a single `/swarm` invocation. When strict per-task isolation is required, split tasks across separate `agy-container --isolated` runs with distinct `--allow` flags and `--ro` / `--rw` mounts.
