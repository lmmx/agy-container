# ADR-003: Authentication Isolation and Zero-MITM API Key Brokerage

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Google Antigravity CLI (`agy`) supports multiple authentication mechanisms — personal Google OAuth, Gemini API key (`GEMINI_API_KEY`), Gemini Enterprise / GCP OAuth, and Application Default Credentials (ADC) — and stores local session state under `~/.gemini` and `~/.config/antigravity`.

Two security findings shaped our authentication architecture:

1. **Broad `cloud-platform` OAuth scope (`google-antigravity/antigravity-cli#592`).** Personal Google OAuth tokens issued by `agy` carry `https://www.googleapis.com/auth/cloud-platform`, granting full GCP control-plane permissions (Cloud Run, Compute Engine, GCS, Secret Manager, IAM) across projects accessible to the signed-in Google account, even though the consent screen presents only Antigravity branding.
2. **MITM OAuth proxy trade-offs (`shelajev/agy-sbx-kit` evaluation).** Docker Sandboxes hides OAuth tokens from its microVM by intercepting Google TLS traffic on the host with a custom MITM root CA, capturing OAuth exchanges, and swapping sentinel tokens in `Authorization` headers. Adopting a MITM proxy in `agy-container` would require generating and injecting a custom root CA into the workspace, terminating TLS for Google's HTTP/2 + gRPC endpoints (`daily-cloudcode-pa.googleapis.com`, `cloudcode-pa.googleapis.com`, `oauth2.googleapis.com`), and maintaining a security-critical TLS-intercepting proxy daemon.

Meanwhile, for `GEMINI_API_KEY`, `agy` honors `GOOGLE_GEMINI_BASE_URL` and sends the key in the `X-Goog-Api-Key` HTTP header to `generativelanguage.googleapis.com` under `/v1/` and `/v1beta/`.

## Decision

`agy-container` implements a **layered, zero-MITM authentication model** across four explicit `--auth` modes ([`src/auth.rs`](../../src/auth.rs)):

1. **Never mount host `~/.gemini` or `~/.config/antigravity`.**
   All container state is stored under `${XDG_DATA_HOME:-~/.local/share}/agy-container/profiles/<profile>/` (`gemini/` and `config-antigravity/`, created `0700`). Headless OAuth sign-in is provided via `agy-container login`, which temporarily enables `--allow google-auth` and invokes `agy acp --login` with `NO_BROWSER=true` and `SSH_CONNECTION="agy-container 0 agy-container 0"` so `agy` uses its copy/paste URL flow instead of binding `localhost:36742`.
2. **Zero-MITM `GEMINI_API_KEY` brokerage on Squid port `3129` (`--auth api-key` / `--api-key-file`).**
   - The real `GEMINI_API_KEY` is read on the host, strictly validated against Squid directive/macro injection (ASCII alphanumerics and `-_.+/=`, max 512 chars), and rendered into a per-run `/etc/squid/conf.d/api-broker.conf` mounted **only** inside `agy-proxy-<run_id>`.
   - The workspace container receives only the worthless sentinel `GEMINI_API_KEY=agy-container-proxy-managed`, `GOOGLE_GEMINI_BASE_URL=http://proxy:3129`, and an ephemeral `--settings '{"modelProvider":"gemini"}'` CLI flag (leaving the profile's `settings.json` unmutated).
   - Squid listens on port `3129` in `accel` reverse-proxy mode (`defaultsite=generativelanguage.googleapis.com no-vhost`), denies `CONNECT`, denies `private_dst`, restricts URL paths to `^/v1(beta)?/`, strips any client `X-Goog-Api-Key`, adds the real key via `request_header_add`, and forwards exclusively over standard system-CA-verified TLS (`ca-certificates`) to `https://generativelanguage.googleapis.com:443`.
   - Conflicts with `--no-gateway` (fails closed).
3. **Egress containment + explicit warnings for `oauth` (`#592`), `gcp`, and `adc`.**
   - Default `assets/squid.conf` (`agy_core`) deliberately excludes GCP control-plane domains (`compute.googleapis.com`, `iam.googleapis.com`, `secretmanager.googleapis.com`, `storage.googleapis.com`, etc.), containing `cloud-platform` blast radius while restricted egress is active.
   - Combining `-n` / `--unrestricted-network` with `--auth oauth` prints an explicit warning referencing `antigravity-cli#592`.
   - `--auth gcp` requires `--gcp-project <ID>` (optional `--gcp-location`, default `global`), seeds `gcp` metadata in `settings.json`, and auto-enables `gcp-enterprise`.
   - `--auth adc` verifies `${CLOUDSDK_CONFIG:-~/.config/gcloud}/application_default_credentials.json`, mounts that directory read-only at `/home/agy/.config/gcloud`, sets `AGY_ADC_AUTH=true`, and auto-enables `gcp-enterprise`.
4. **Ephemeral per-run state via `--isolated`.**
   Creates a `0700` temp directory under `/tmp/agy-container-state-*` deleted on `Drop`. For `oauth` and `gcp`, copies **only** `antigravity-cli/antigravity-oauth-token` (`0600`) from the named profile, preventing SQLite WAL contention during concurrent runs and preventing cross-session hook persistence.

## Consequences

### Positive

- **Zero secret exposure for `--auth api-key` with zero MITM:** No custom CA, no TLS interception, no HTTP/2 gRPC breakage, and no secret in workspace env/filesystem/process args (verified by both `tests/end_to_end.rs` and `tests/podman_live.sh`).
- **Host Antigravity credentials remain completely untouched:** Compromise of a container session cannot read or tamper with host `~/.gemini` or `~/.config/antigravity`.
- **Clean multi-account and concurrent usage:** `--profile <NAME>` separates personal, work, and untrusted-repo state; `--isolated` enables parallel sessions without SQLite corruption.

### Negative / Trade-offs

- **OAuth tokens are still present in the container under `--auth oauth` / `--auth gcp` / `--auth adc`.** Until Google either narrows the OAuth scope (`#592`) or supports a non-MITM base-URL override for consumer OAuth endpoints, users running untrusted repos with wide egress (`-n`, `--github=push`) should use `--auth api-key` or a GCP-privilege-free Google account.
- **Workspace-to-proxy leg on port `3129` is plaintext HTTP over the private `--internal` network.** This leg never leaves the host kernel's per-run `agy-caged-<run_id>` virtual bridge and carries only the sentinel key, while the outbound leg from Squid to `generativelanguage.googleapis.com:443` uses full system-CA TLS verification.
- **No automatic token refresh writeback under `--isolated`.** Because `--isolated` copies `antigravity-oauth-token` into an ephemeral temp directory that is deleted on exit, a refreshed access token obtained during an `--isolated` run is discarded at exit (the long-lived refresh token in the source profile remains valid for subsequent runs).
