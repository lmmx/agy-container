# ADR-001: Direct Podman Orchestration Over `podman-compose`

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

`lmmx/claude-container` orchestrates its workspace container, Squid proxy, and SSH git-gateway via `podman-compose` using four YAML layers (`compose.yml`, `compose.locked.yml`, `compose.headless.yml`, `compose.gitgateway.yml`) and a generated override file. While Compose YAML is concise for a single developer running one interactive session at a time, running `podman-compose` in practice exposed five structural weaknesses:

1. **Broken concurrency under a fixed project name.** `claude-container` fixes `COMPOSE_PROJECT_NAME=claude-container` (avoiding per-project image rebuilds). Consequently, two concurrent invocations share one proxy container (`claude-container_proxy_1`): the first session to exit tears down the other session's gateway and attributes both sessions' traffic to the wrong `egress.log` entry.
2. **External Python dependency and interpolator quirks.** Requiring `podman-compose` drags Python and a third-party Compose implementation into the host prerequisites, and `podman-compose` has version-sensitive interpolation quirks (e.g., nested `${HOME}` defaults) and subtle differences from `docker compose` (`--in-pod`).
3. **Lost diagnostics on immediate sidecar failure.** As documented in `claude-container`'s README, `podman logs` has been observed returning empty output for a compose-created proxy that exited immediately during `squid.conf` parsing, whereas a container created directly with `podman` retains `FATAL:` stderr in full.
4. **Static YAML cannot express conditional host capabilities cleanly.** Rootless Podman hosts vary in cgroup v2 controller delegation (`memory`, `pids`, `cpu`), `/etc/subuid` availability (multi-mapping `--userns=keep-id:uid=1000,gid=1000` vs. `crun` single-UID non-root mapping `--uidmap 1000:0:1`), and SELinux enforcement (`,z`). Expressing conditional flags in Rust is direct; generating temporary YAML overrides to work around Compose limitations adds indirection.
5. **Incomplete cleanup on `SIGTERM`.** Layered `podman compose run` + `podman compose down` invocations leave orphaned containers when a terminal closes or CI sends `SIGTERM`.

## Decision

`agy-container` drops `podman-compose` completely and orchestrates containers and networks directly through the `podman` CLI, encapsulated in an RAII lifecycle guard ([`RunTopology`](../../src/podman.rs)):

- **Unique per-run topology (`run_id = agy-<8hex>`):** Every invocation creates dedicated networks (`agy-caged-<run_id>` with `--internal --disable-dns`, `agy-egress-<run_id>` with `--disable-dns`) and dedicated containers (`agy-proxy-<run_id>`, optional `agy-gitgw-<run_id>`, and `agy-work-<run_id>`), all tagged with `agy-container.run=<run_id>` and `agy-container.role=<role>`.
- **Shared pre-built images, zero per-run rebuilds:** Images are built once under stable tags (`localhost/agy-container-agy:latest`, `localhost/agy-container-proxy:latest`, `localhost/agy-container-gitgateway:latest`) via `podman build`, completely decoupling image lifecycle from per-run network/container naming.
- **Explicit network attachment & `/etc/hosts` pinning:** Sidecars are created on `agy-egress-<run_id>`, attached to `agy-caged-<run_id>` via `podman network connect --alias <proxy|git-gateway>`, and started. The runner inspects each sidecar's IP on `agy-caged-<run_id>` and pins `--add-host proxy:<ip>` and `--add-host git-gateway:<ip>` on `agy-work-<run_id>`. Passing `--disable-dns` avoids `aardvark-dns` failures on non-systemd hosts and removes internal DNS listeners from `caged`.
- **Cooperative signal handling and RAII `Drop`:** Parent ignores `SIGINT` (restoring `SIG_DFL` in children via `pre_exec`) and catches `SIGTERM` via an atomic flag, gracefully stopping the workspace (`podman stop --time 10`), capturing Squid/git-gateway logs before removal, and tearing down all containers, networks, and atomic `0700` temp dirs in `RunTopology::teardown()` (and `Drop`).

## Consequences

### Positive

- **Full concurrency out of the box:** Parallel `agy-container` runs (verified by `tests/end_to_end.rs` and `tests/podman_live.sh`) have completely isolated networks, sidecars, and per-run `egress.log` attribution.
- **Zero host dependencies beyond Podman (and `ssh-keygen` for `--github`):** No Python, no `podman-compose`, no Compose YAML generation or interpolation edge cases.
- **Reliable dead-sidecar diagnostics:** Startup checks surface full `stdout`/`stderr` via `podman logs` whenever Squid or `sshd` exits early (including during IP inspection).
- **Adaptive rootless portability:** [`build_workspace_podman_args`](../../src/main.rs) conditionally emits `--userns=keep-id:uid=1000,gid=1000` vs. `crun` single-UID non-root mapping (`--uidmap 1000:0:1 --user 1000:1000`), `--pids-limit` vs. `--ulimit nproc`, `--memory`/`--memory-swap`, and `--cpus` based on live host probes in [`src/host.rs`](../../src/host.rs).
- **Deterministic teardown on `SIGTERM`:** Zero orphaned containers or networks after graceful cancellation (verified in `tests/podman_live.sh`).

### Negative / Trade-offs

- **More orchestration code in Rust:** [`src/podman.rs`](../../src/podman.rs) and [`src/main.rs`](../../src/main.rs) explicitly sequence `network create`, `create`, `network connect`, `start`, `inspect`, `run`, `logs`, and `rm` instead of delegating to a declarative YAML file.
- **Static YAML inspection is replaced by Rust + tests:** Users wishing to inspect exact container flags read `src/podman.rs` / `src/main.rs` or run with stub Podman tests (`tests/end_to_end.rs`) rather than reading a `compose.yml`.
- **`SIGKILL` still bypasses `Drop`:** If the runner receives `kill -9`, manual cleanup via `agy-container.run` labels is still required.
