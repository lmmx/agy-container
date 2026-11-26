use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use agy_container::allow;
use agy_container::assets::MaterializedAssets;
use agy_container::auth::AuthSession;
use agy_container::cli::{self, Action, AuthMode, Config, GitHubMode};
use agy_container::egress;
use agy_container::gitgateway::GitGatewaySession;
use agy_container::host::{self, HostEnv};
use agy_container::mounts;
use agy_container::podman::{self, RunTopology, IMAGE_AGY, IMAGE_GITGW, IMAGE_PROXY};
use agy_container::probe;

fn main() -> ExitCode {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match cli::parse_args(raw_args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("agy-container: error: {msg}");
            return ExitCode::from(2);
        }
    };

    match cfg.action {
        Action::Help => {
            print!("{}", cli::help_text());
            return ExitCode::SUCCESS;
        }
        Action::Version => {
            println!("agy-container {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    podman::install_signal_handlers();

    match run(cfg) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("agy-container: error: {msg}");
            ExitCode::from(1)
        }
    }
}

fn run(mut cfg: Config) -> Result<ExitCode, String> {
    let host = HostEnv::resolve()?;

    if cfg.action == Action::Precondition {
        podman::run_precondition_check(&host)?;
        return Ok(ExitCode::SUCCESS);
    }

    if cfg.action == Action::Doctor {
        return run_doctor(&host, &cfg);
    }

    let assets = MaterializedAssets::prepare(&host.cache_dir, &host.config_dir)?;

    if cfg.action == Action::UpdateImage {
        podman::ensure_images(&assets, true, true, true, true)?;
        println!("agy-container: container images updated successfully.");
        return Ok(ExitCode::SUCCESS);
    }

    // Resolve workspace directory (default: current working directory).
    let raw_workspace = match &cfg.workspace {
        Some(p) => p.clone(),
        None => std::env::current_dir()
            .map_err(|e| format!("failed to determine current directory: {e}"))?,
    };
    let workspace = host::resolve_dir(&raw_workspace, &host.home)?;

    // Validate extra --ro / --rw mounts.
    let extra_mounts =
        mounts::collect_mounts(&workspace, &cfg.ro_mounts, &cfg.rw_mounts, &host.home)?;

    // Implied opt-ins:
    // - `login` temporarily enables `google-auth` egress for interactive OAuth.
    // - `--auth gcp` / `--auth adc` enable `gcp-enterprise` endpoints.
    // - `--github` implies `--git` and `--allow github`.
    if cfg.action == Action::Login {
        push_unique(&mut cfg.allow_groups, "google-auth");
    }
    if matches!(cfg.auth_mode, AuthMode::Gcp | AuthMode::Adc) {
        push_unique(&mut cfg.allow_groups, "gcp-enterprise");
    }
    if cfg.github.is_some() {
        cfg.git = true;
        push_unique(&mut cfg.allow_groups, "github");
    }

    // Warn on Antigravity-specific boundary shifts.
    if cfg.user_set_sandbox {
        eprintln!(
            "agy-container: warning: --sandbox uses Linux user namespaces (bubblewrap/exebox), which are blocked inside hardened --cap-drop=ALL --no-new-privileges containers. The outer Podman container + Squid gateway is the security boundary."
        );
    }
    if cfg.user_set_remote_agent {
        eprintln!(
            "agy-container: note: --remote-agent delegates tool execution to Google-managed cloud VMs outside this local container boundary."
        );
    }
    if cfg.unrestricted_network && cfg.auth_mode == AuthMode::Oauth {
        eprintln!(
            "agy-container: warning: --unrestricted-network with --auth oauth allows outbound HTTPS to any public host while an OAuth token (carrying cloud-platform scope, antigravity-cli#592) resides in container state. Prefer --allow <group> or --auth api-key."
        );
    }

    // Compile per-run allowlist fragment before touching containers.
    let allow_fragment = allow::compile_allow_fragment(&cfg.allow_groups, &cfg.allow_hosts)?;

    // Verify user squid.conf includes our fragments when using restricted mode.
    let use_gateway = !cfg.no_gateway;
    let use_permissive_squid = cfg.unrestricted_network || cfg.probe;
    let squid_conf_path = if use_permissive_squid {
        assets.path("squid.permissive.conf")
    } else {
        let user_conf = fs::read_to_string(&assets.user_squid_conf)
            .map_err(|e| format!("failed to read '{}': {e}", assets.user_squid_conf.display()))?;
        allow::check_squid_conf_includes(&user_conf)?;
        assets.user_squid_conf.clone()
    };

    // Prepare per-run identifiers and isolated auth/state directory.
    let run_id = podman::generate_run_id();
    let auth_session = AuthSession::prepare(&cfg, &host.data_dir, &host.home, &run_id)?;

    // Prepare optional per-run SSH git-gateway sidecar material.
    let git_gateway = if let Some(mode) = cfg.github {
        GitGatewaySession::prepare(
            &run_id,
            mode,
            cfg.git_key.as_deref(),
            &cfg.git_repos,
            &host.home,
        )?
    } else {
        None
    };

    // Optional host ~/.gitconfig mount with credential leakage warnings.
    let host_gitconfig = if cfg.git {
        let found = host::host_gitconfig(&host.home);
        if let Some(ref p) = found {
            if let Ok(text) = fs::read_to_string(p) {
                for w in host::gitconfig_warnings(&text) {
                    eprintln!("agy-container: gitconfig warning ({}): {w}", p.display());
                }
            }
        }
        found
    } else {
        None
    };

    // Ensure required container images exist (or rebuild if --build / --update).
    podman::ensure_images(
        &assets,
        use_gateway,
        git_gateway.is_some(),
        cfg.build,
        cfg.update,
    )?;

    if !host.has_subuid_mapping {
        eprintln!(
            "agy-container: note: no /etc/subuid range found for current user; running in single-mapping rootless mode"
        );
    }

    // Create per-run isolated topology guard (cleaned up automatically on Drop).
    let mut topo = RunTopology::new(run_id.clone())?;

    // Stage per-run Squid fragments inside the 0700 run temp dir (0644 files so
    // non-root `USER squid` can read them while no other host user can traverse).
    let allow_conf_path = topo.write_run_file("allow.conf", &allow_fragment, 0o644)?;
    let broker_conf_path =
        topo.write_run_file("api-broker.conf", &auth_session.api_broker_conf, 0o644)?;

    let mut proxy_ip: Option<String> = None;
    let mut gitgw_ip: Option<String> = None;

    if use_gateway {
        topo.create_networks()?;
        let p_ip =
            topo.start_proxy(&squid_conf_path, &allow_conf_path, &broker_conf_path, &host)?;
        proxy_ip = Some(p_ip);

        if !cfg.probe && !topo.wait_sidecar_alive(topo.proxy_name.as_deref().unwrap(), 350) {
            let (out, err) = topo.container_logs(topo.proxy_name.as_deref().unwrap());
            return Err(format!(
                "Squid egress proxy exited immediately.\n--- stdout ---\n{}\n--- stderr ---\n{}\nhint: verify '{}' or retry with --build",
                out.trim(),
                err.trim(),
                squid_conf_path.display()
            ));
        }

        if let Some(ref gw) = git_gateway {
            let g_ip = topo.start_git_gateway(gw, &host)?;
            gitgw_ip = Some(g_ip);
            if !topo.wait_sidecar_alive(topo.gitgw_name.as_deref().unwrap(), 300) {
                let (out, err) = topo.container_logs(topo.gitgw_name.as_deref().unwrap());
                return Err(format!(
                    "git-gateway sidecar exited immediately.\n--- stdout ---\n{}\n--- stderr ---\n{}\nhint: retry with --build",
                    out.trim(),
                    err.trim()
                ));
            }
        }
    }

    // Print concise boundary summary to stderr (keeps stdout pure for `-p` / `stream-json`!).
    let net_mode_label = if !use_gateway {
        "no-gateway (unobserved)"
    } else if cfg.probe {
        "probe (permissive + logged)"
    } else if cfg.unrestricted_network {
        "unrestricted (logged, private IPs blocked)"
    } else {
        "restricted (default-deny)"
    };
    print_boundary_summary(
        &run_id,
        &workspace,
        net_mode_label,
        &cfg,
        git_gateway.as_ref(),
        &extra_mounts,
    );

    // Assemble direct `podman run` arguments for the hardened workspace container.
    let tty_mode = !cfg.headless && podman::stdin_is_tty() && podman::stdout_is_tty();
    let keep_stdin = tty_mode || cfg.stream_stdin || (cfg.headless && !podman::stdin_is_tty());

    let podman_args = build_workspace_podman_args(
        &cfg,
        &host,
        &topo,
        &workspace,
        &extra_mounts,
        &auth_session,
        git_gateway.as_ref(),
        host_gitconfig.as_deref(),
        proxy_ip.as_deref(),
        gitgw_ip.as_deref(),
        tty_mode,
        keep_stdin,
    );

    let start = Instant::now();
    let mut child = podman::spawn_workspace(&podman_args, tty_mode, keep_stdin)?;
    let timeout = if cfg.probe && cfg.probe_timeout > 0 {
        Some(Duration::from_secs(cfg.probe_timeout))
    } else {
        None
    };

    let (status, timed_out) = podman::wait_workspace(&mut child, &topo, timeout)?;
    let elapsed_secs = start.elapsed().as_secs();

    // Capture egress & git-gateway logs before tearing down sidecars.
    if use_gateway {
        let proxy_name = topo.proxy_name.clone();
        let gitgw_name = topo.gitgw_name.clone();

        let (proxy_running, proxy_out, proxy_err) = if let Some(ref p) = proxy_name {
            let running = topo.is_running(p);
            let (out, err) = topo.container_logs(p);
            (running, out, err)
        } else {
            (false, String::new(), String::new())
        };

        let gitgw_logs = gitgw_name.as_deref().map(|g| {
            let (out, err) = topo.container_logs(g);
            if err.trim().is_empty() {
                out
            } else if out.trim().is_empty() {
                err
            } else {
                format!("{out}\n{err}")
            }
        });

        if cfg.probe {
            let tally = probe::tally_squid_logs(&proxy_out);
            let report = probe::render_probe_report(
                proxy_running,
                &tally,
                elapsed_secs,
                timed_out,
                cfg.self_test,
            );
            eprint!("{report}");
            if !proxy_running && !proxy_err.trim().is_empty() {
                eprintln!("proxy stderr:\n{}", proxy_err.trim());
            }
        }

        let ts = egress::utc_timestamp_now();
        let header = egress::session_header(
            &ts,
            &run_id,
            net_mode_label,
            cfg.auth_mode.as_str(),
            &workspace,
        );
        if let Err(e) = egress::append_session_log(
            &host.egress_log_path(),
            &header,
            &proxy_out,
            gitgw_logs.as_deref(),
        ) {
            eprintln!("agy-container: warning: failed to append egress log: {e}");
        }
    }

    // Explicit teardown (also enforced by Drop).
    topo.teardown();

    if timed_out {
        return Ok(ExitCode::from(124));
    }
    if podman::sigterm_received() {
        return Ok(ExitCode::from(143));
    }
    match status.code() {
        Some(c) => Ok(ExitCode::from((c & 0xff) as u8)),
        None => Ok(ExitCode::from(130)),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_workspace_podman_args(
    cfg: &Config,
    host: &HostEnv,
    topo: &RunTopology,
    workspace: &Path,
    extra_mounts: &[mounts::ExtraMount],
    auth_session: &AuthSession,
    git_gateway: Option<&GitGatewaySession>,
    host_gitconfig: Option<&std::path::Path>,
    proxy_ip: Option<&str>,
    gitgw_ip: Option<&str>,
    tty_mode: bool,
    keep_stdin: bool,
) -> Vec<String> {
    let se = host.selinux_volume_suffix();
    let mut args: Vec<String> = Vec::new();
    if !host.has_subuid_mapping && host.has_crun {
        args.push("--runtime".into());
        args.push("crun".into());
    }
    args.extend([
        "run".into(),
        "--rm".into(),
        "--name".into(),
        topo.work_name.clone(),
        "--label".into(),
        format!("agy-container.run={}", topo.run_id),
        "--label".into(),
        "agy-container.role=workspace".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges:true".into(),
        "--workdir".into(),
        "/workspace".into(),
    ]);

    if tty_mode {
        args.push("-it".into());
    } else if keep_stdin {
        args.push("-i".into());
    }

    if host.has_subuid_mapping {
        args.push("--userns=keep-id:uid=1000,gid=1000".into());
    } else if host.has_crun {
        args.push("--uidmap".into());
        args.push("1000:0:1".into());
        args.push("--gidmap".into());
        args.push("1000:0:1".into());
        args.push("--user".into());
        args.push("1000:1000".into());
        args.push("--sysctl".into());
        args.push("net.ipv4.ping_group_range=1000 1000".into());
    } else {
        args.push("--user".into());
        args.push("0:0".into());
    }

    // Resource limits: enforce cgroup v2 controls when delegated, fall back to
    // RLIMIT_NPROC for process limits and warn clearly if memory/cpu are undelegated.
    if host.cgroups.pids {
        args.push(format!("--pids-limit={}", cfg.pids_limit));
    } else {
        args.push("--ulimit".into());
        args.push(format!("nproc={}:{}", cfg.pids_limit, cfg.pids_limit));
    }

    if !cfg.memory.eq_ignore_ascii_case("none") {
        if host.cgroups.memory {
            args.push(format!("--memory={}", cfg.memory));
            args.push(format!("--memory-swap={}", cfg.memory));
        } else {
            eprintln!(
                "agy-container: note: cgroup v2 memory controller not delegated for this user; skipping --memory={}",
                cfg.memory
            );
        }
    }

    if let Some(ref cpus) = cfg.cpus {
        if host.cgroups.cpu {
            args.push(format!("--cpus={cpus}"));
        } else {
            eprintln!(
                "agy-container: note: cgroup v2 cpu controller not delegated for this user; skipping --cpus={cpus}"
            );
        }
    }

    // Networking: attach workspace ONLY to the per-run `--internal` network and pin
    // sidecar IPs into `/etc/hosts` so resolution works without internal DNS.
    if let Some(ref caged) = topo.caged_net {
        args.push("--network".into());
        args.push(caged.clone());
        if let Some(ip) = proxy_ip {
            args.push("--add-host".into());
            args.push(format!("proxy:{ip}"));
        }
        if let Some(ip) = gitgw_ip {
            args.push("--add-host".into());
            args.push(format!("git-gateway:{ip}"));
        }
        args.push("-e".into());
        args.push("HTTP_PROXY=http://proxy:3128".into());
        args.push("-e".into());
        args.push("HTTPS_PROXY=http://proxy:3128".into());
        args.push("-e".into());
        args.push("http_proxy=http://proxy:3128".into());
        args.push("-e".into());
        args.push("https_proxy=http://proxy:3128".into());
        // Keep loopback (embedded agy gRPC/HTTP language server) and direct sidecar
        // links (API key broker on proxy:3129, SSH git-gateway) off the HTTP proxy.
        args.push("-e".into());
        args.push("NO_PROXY=localhost,127.0.0.1,::1,proxy,git-gateway".into());
        args.push("-e".into());
        args.push("no_proxy=localhost,127.0.0.1,::1,proxy,git-gateway".into());
    }

    // Antigravity container environment invariants.
    args.push("-e".into());
    args.push("HOME=/home/agy".into());
    args.push("-e".into());
    args.push("NO_BROWSER=true".into());
    args.push("-e".into());
    args.push("SSH_CONNECTION=agy-container 0 agy-container 0".into());
    args.push("-e".into());
    args.push("AGY_CLI_DISABLE_AUTO_UPDATE=true".into());
    if let Ok(term) = std::env::var("TERM") {
        if !term.is_empty() {
            args.push("-e".into());
            args.push(format!("TERM={term}"));
        }
    }
    if let Ok(ct) = std::env::var("COLORTERM") {
        if !ct.is_empty() {
            args.push("-e".into());
            args.push(format!("COLORTERM={ct}"));
        }
    }

    for (k, v) in &auth_session.workspace_env {
        args.push("-e".into());
        args.push(format!("{k}={v}"));
    }

    // Workspace mount.
    let ws_mode = if cfg.ro_workspace { "ro" } else { "rw" };
    args.push("-v".into());
    args.push(format!("{}:/workspace:{ws_mode}{se}", workspace.display()));

    // Isolated Antigravity state mounts (never host ~/.gemini or ~/.config/antigravity).
    args.push("-v".into());
    args.push(format!(
        "{}:/home/agy/.gemini:rw{se}",
        auth_session.gemini_dir.display()
    ));
    args.push("-v".into());
    args.push(format!(
        "{}:/home/agy/.config/antigravity:rw{se}",
        auth_session.config_antigravity_dir.display()
    ));

    if let Some(ref gcloud) = auth_session.adc_gcloud_dir {
        args.push("-v".into());
        args.push(format!(
            "{}:/home/agy/.config/gcloud:ro{se}",
            gcloud.display()
        ));
    }

    // Extra reference/working directories.
    let mut add_dirs = Vec::new();
    for m in extra_mounts {
        args.push("-v".into());
        args.push(m.volume_arg(se));
        add_dirs.push(m.container_path.clone());
    }

    // Optional host ~/.gitconfig (read-only).
    if let Some(gc) = host_gitconfig {
        args.push("-v".into());
        args.push(format!("{}:/home/agy/.gitconfig:ro{se}", gc.display()));
    }

    // Optional SSH git-gateway throwaway client material (real host key NEVER mounted here).
    if let Some(gw) = git_gateway {
        args.push("-v".into());
        args.push(format!(
            "{}:/home/agy/.ssh/gitgw_key:ro{se}",
            gw.client_key.display()
        ));
        args.push("-v".into());
        args.push(format!(
            "{}:/home/agy/.ssh/gitgw_known_hosts:ro{se}",
            gw.client_known_hosts.display()
        ));
        args.push("-v".into());
        args.push(format!(
            "{}:/home/agy/.ssh/gitgw_config:ro{se}",
            gw.client_ssh_config.display()
        ));
        args.push("-v".into());
        args.push(format!(
            "{}:/home/agy/.gitconfig-gateway:ro{se}",
            gw.client_gitconfig_gateway.display()
        ));
        args.push("-e".into());
        args.push("GIT_CONFIG_SYSTEM=/home/agy/.gitconfig-gateway".into());
    }

    // Entrypoint selection: --shell, --probe --self-test, login, or normal agy invocation.
    if cfg.shell {
        args.push("--entrypoint".into());
        args.push("/bin/bash".into());
        args.push(IMAGE_AGY.into());
        args.extend(cfg.passthrough.iter().cloned());
    } else if cfg.probe && cfg.self_test {
        args.push("--entrypoint".into());
        args.push("/bin/bash".into());
        args.push(IMAGE_AGY.into());
        args.push("-c".into());
        args.push(probe::SELF_TEST_CMD.into());
    } else if cfg.action == Action::Login {
        args.push(IMAGE_AGY.into());
        args.push("acp".into());
        args.push("--login".into());
    } else {
        args.push(IMAGE_AGY.into());
        args.extend(cfg.build_agy_command(&add_dirs));
    }

    args
}

fn print_boundary_summary(
    run_id: &str,
    workspace: &std::path::Path,
    net_mode: &str,
    cfg: &Config,
    git_gateway: Option<&GitGatewaySession>,
    extra_mounts: &[mounts::ExtraMount],
) {
    eprintln!("agy-container [{run_id}]");
    eprintln!(
        "  WORKSPACE  : {} ({})",
        workspace.display(),
        if cfg.ro_workspace { "ro" } else { "rw" }
    );
    eprintln!("  EGRESS     : {net_mode}");
    if !cfg.allow_groups.is_empty() || !cfg.allow_hosts.is_empty() {
        let mut items = cfg.allow_groups.clone();
        items.extend(cfg.allow_hosts.iter().cloned());
        eprintln!("  ALLOW      : {}", items.join(", "));
    }
    eprintln!(
        "  AUTH       : {} (profile={}{})",
        cfg.auth_mode.as_str(),
        cfg.profile,
        if cfg.isolated { ", isolated" } else { "" }
    );
    if !extra_mounts.is_empty() {
        let desc: Vec<String> = extra_mounts
            .iter()
            .map(|m| {
                format!(
                    "{} -> {} ({})",
                    m.host_path.display(),
                    m.container_path,
                    m.mode.podman_flag()
                )
            })
            .collect();
        eprintln!("  MOUNTS     : {}", desc.join("; "));
    }
    if let Some(gw) = git_gateway {
        let mode_str = match cfg.github {
            Some(GitHubMode::Push) => "push",
            _ => "read-only",
        };
        let repos = if gw.allowed_repos.is_empty() {
            "all repos reachable by key".to_string()
        } else {
            gw.allowed_repos.join(", ")
        };
        eprintln!("  GIT GATEWAY: {mode_str} ({repos})");
    }
}

fn run_doctor(host: &HostEnv, cfg: &Config) -> Result<ExitCode, String> {
    println!("agy-container doctor ({})", env!("CARGO_PKG_VERSION"));
    let (st, ver, err) = podman::run_capture(["--version"])?;
    if !st.success() {
        return Err(format!("podman not usable: {}", err.trim()));
    }
    println!("  podman          : {}", ver.trim());
    println!(
        "  subuid/subgid   : {}",
        if host.has_subuid_mapping {
            "configured (keep-id enabled)"
        } else {
            "missing (single-mapping rootless fallback)"
        }
    );
    println!(
        "  cgroup v2       : memory={} pids={} cpu={}",
        host.cgroups.memory, host.cgroups.pids, host.cgroups.cpu
    );
    println!(
        "  SELinux         : {}",
        if host.selinux_enforcing {
            "Enforcing (,z)"
        } else {
            "Permissive/Disabled"
        }
    );
    println!(
        "  images          : agy={} proxy={} git-gateway={}",
        podman::image_exists(IMAGE_AGY),
        podman::image_exists(IMAGE_PROXY),
        podman::image_exists(IMAGE_GITGW)
    );
    let profile_tok = host
        .data_dir
        .join("profiles")
        .join(&cfg.profile)
        .join("gemini/antigravity-cli/antigravity-oauth-token");
    println!(
        "  profile '{}' : OAuth token {}",
        cfg.profile,
        if profile_tok.is_file() {
            "present"
        } else {
            "not found (run `agy-container login` or use `--auth api-key`)"
        }
    );
    print!("  internal net    : ");
    podman::run_precondition_check(host)?;
    Ok(ExitCode::SUCCESS)
}

fn push_unique(list: &mut Vec<String>, item: &str) {
    if !list.iter().any(|x| x == item) {
        list.push(item.to_string());
    }
}
