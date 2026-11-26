use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_sandbox(label: &str) -> PathBuf {
    let n = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("agy-e2e-{label}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write a stub `podman` script that records every invocation and simulates
/// image checks, network creation, IP inspection, proxy logs, and workspace runs.
fn install_stub_podman(bin_dir: &Path, log_file: &Path, proxy_logs: &str, proxy_running: bool) {
    fs::create_dir_all(bin_dir).unwrap();
    let stub = bin_dir.join("podman");
    let running_str = if proxy_running { "true" } else { "false" };
    let script = format!(
        r#"#!/bin/sh
printf 'CALL:%s\n' "$*" >> "{log}"
if [ "${{1:-}}" = "--runtime" ]; then
  shift 2
fi
cmd="${{1:-}}"
case "$cmd" in
  --version)
    echo "podman version 5.0.0-stub"
    exit 0
    ;;
  image)
    exit 0
    ;;
  network)
    exit 0
    ;;
  create)
    echo "stub-container-id"
    exit 0
    ;;
  start)
    exit 0
    ;;
  inspect)
    case "$*" in
      *IPAddress*) echo "10.89.0.2" ;;
      *State.Running*) echo "{running}" ;;
    esac
    exit 0
    ;;
  logs)
    cat <<'LOGEOF'
{plogs}
LOGEOF
    exit 0
    ;;
  run)
    # Record any mounted broker/allow configs if visible in args
    exit 0
    ;;
  stop|rm)
    exit 0
    ;;
esac
exit 0
"#,
        log = log_file.display(),
        running = running_str,
        plogs = proxy_logs
    );
    fs::write(&stub, script).unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
}

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_agy-container")
}

#[test]
fn end_to_end_lifecycle_and_api_key_brokerage_never_exposes_real_key_to_workspace() {
    let root = temp_sandbox("api-broker");
    let bin_dir = root.join("bin");
    let ws = root.join("workspace");
    let ref_dir = root.join("docs");
    let home = root.join("home");
    let calls_log = root.join("podman.calls");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&ref_dir).unwrap();
    fs::create_dir_all(&home).unwrap();

    let squid_log = "1795705200.100 12 10.89.0.3 TCP_MISS/200 512 POST http://generativelanguage.googleapis.com/v1beta/models - FIRSTUP_PARENT/generativelanguage.googleapis.com application/json";
    install_stub_podman(&bin_dir, &calls_log, squid_log, true);

    let real_secret = "AIzaSuperSecretRealKey987654321";
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let out = Command::new(bin_path())
        .args([
            "--workspace",
            ws.to_str().unwrap(),
            "--ro",
            ref_dir.to_str().unwrap(),
            "--auth",
            "api-key",
            "--model",
            "gemini-4-neon-xhigh",
            "-p",
            "Summarize repo",
        ])
        .env("PATH", &path_env)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .env("GEMINI_API_KEY", real_secret)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let calls = fs::read_to_string(&calls_log).unwrap();

    // Verify lifecycle order: internal network -> egress network -> create proxy -> connect -> start -> run -> teardown.
    let net_pos = calls
        .find("network create --internal --disable-dns agy-caged-")
        .unwrap();
    let proxy_pos = calls.find("create --name agy-proxy-").unwrap();
    let run_pos = calls.find("run --rm --name agy-work-").unwrap();
    let rm_pos = calls.find("rm -f agy-proxy-").unwrap();
    assert!(net_pos < proxy_pos && proxy_pos < run_pos && run_pos < rm_pos);

    // CRITICAL SECURITY INVARIANT: the real GEMINI_API_KEY must NEVER appear in the workspace podman run call!
    let run_line = calls
        .lines()
        .find(|l| l.contains("run --rm --name agy-work-"))
        .unwrap();
    assert!(
        !run_line.contains(real_secret),
        "real API key leaked into workspace run args: {run_line}"
    );
    assert!(run_line.contains("GEMINI_API_KEY=agy-container-proxy-managed"));
    assert!(run_line.contains("GOOGLE_GEMINI_BASE_URL=http://proxy:3129"));
    assert!(run_line.contains("--cap-drop=ALL"));
    assert!(run_line.contains("--security-opt=no-new-privileges:true"));
    assert!(run_line.contains("--add-host proxy:10.89.0.2"));
    assert!(run_line.contains("--add-dir /mnt/docs"));
    assert!(run_line.contains("--model gemini-4-neon-xhigh"));

    // Verify egress log recorded the session header and Squid line.
    let egress_log =
        fs::read_to_string(home.join(".local/state/agy-container/egress.log")).unwrap();
    assert!(egress_log.contains("auth=api-key"));
    assert!(egress_log.contains("generativelanguage.googleapis.com"));

    // Verify isolated profile was seeded (and host ~/.gemini was NOT touched!).
    assert!(!home.join(".gemini").exists());
    assert!(home
        .join(".local/share/agy-container/profiles/default/gemini/antigravity-cli/settings.json")
        .is_file());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn end_to_end_probe_reports_denied_and_dead_gateway() {
    let root = temp_sandbox("probe");
    let bin_dir = root.join("bin");
    let ws = root.join("workspace");
    let home = root.join("home");
    let calls_log = root.join("podman.calls");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&home).unwrap();

    // Case 1: Dead gateway under --probe reports GATEWAY DID NOT START.
    install_stub_podman(&bin_dir, &calls_log, "", false);
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let out = Command::new(bin_path())
        .args([
            "--workspace",
            ws.to_str().unwrap(),
            "--probe",
            "--self-test",
        ])
        .env("PATH", &path_env)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("GATEWAY DID NOT START"),
        "expected GATEWAY DID NOT START in stderr, got:\n{stderr}"
    );

    // Case 2: Live gateway with denied private metadata target reports DENIED.
    let logs = "1795705201.000 5 10.89.0.3 TCP_DENIED/403 3901 GET http://169.254.169.254/latest/meta-data/ - HIER_NONE/- text/html";
    install_stub_podman(&bin_dir, &calls_log, logs, true);

    let out2 = Command::new(bin_path())
        .args([
            "--workspace",
            ws.to_str().unwrap(),
            "--probe",
            "--self-test",
        ])
        .env("PATH", &path_env)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .output()
        .unwrap();

    let stderr2 = String::from_utf8_lossy(&out2.stderr);
    assert!(
        stderr2.contains("verdict: DENIED"),
        "expected DENIED verdict, got:\n{stderr2}"
    );
    assert!(stderr2.contains("169.254.169.254"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn end_to_end_concurrent_invocations_use_distinct_networks_and_sidecars() {
    let root = temp_sandbox("concurrent");
    let bin_dir = root.join("bin");
    let ws = root.join("workspace");
    let home = root.join("home");
    let calls_log = root.join("podman.calls");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&home).unwrap();
    install_stub_podman(&bin_dir, &calls_log, "", true);

    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut children = Vec::new();
    for _ in 0..3 {
        let c = Command::new(bin_path())
            .args(["--workspace", ws.to_str().unwrap(), "--isolated", "models"])
            .env("PATH", &path_env)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_STATE_HOME", home.join(".local/state"))
            .spawn()
            .unwrap();
        children.push(c);
    }

    for mut c in children {
        assert!(c.wait().unwrap().success());
    }

    let calls = fs::read_to_string(&calls_log).unwrap();
    let caged_nets: std::collections::HashSet<&str> = calls
        .lines()
        .filter_map(|l| l.strip_prefix("CALL:network create --internal --disable-dns "))
        .collect();
    assert_eq!(
        caged_nets.len(),
        3,
        "each concurrent invocation must create its own isolated internal network: {caged_nets:?}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn end_to_end_github_sidecar_never_mounts_host_ssh_key_into_workspace() {
    let root = temp_sandbox("gitgw");
    let bin_dir = root.join("bin");
    let ws = root.join("workspace");
    let home = root.join("home");
    let ssh_dir = home.join(".ssh");
    let calls_log = root.join("podman.calls");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&ssh_dir).unwrap();

    let host_key = ssh_dir.join("id_ed25519");
    fs::write(
        &host_key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    install_stub_podman(&bin_dir, &calls_log, "", true);

    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let out = Command::new(bin_path())
        .args([
            "--workspace",
            ws.to_str().unwrap(),
            "--github=push",
            "--git-repo",
            "lmmx/agy-container",
            "models",
        ])
        .env("PATH", &path_env)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let calls = fs::read_to_string(&calls_log).unwrap();
    let gw_line = calls
        .lines()
        .find(|l| l.contains("create --name agy-gitgw-"))
        .expect("git-gateway sidecar created");
    assert!(gw_line.contains(host_key.to_str().unwrap()));
    assert!(gw_line.contains("AGY_GITGW_PUSH=1"));
    assert!(gw_line.contains("AGY_GITGW_REPOS=lmmx/agy-container"));

    let work_line = calls
        .lines()
        .find(|l| l.contains("run --rm --name agy-work-"))
        .expect("workspace run");
    assert!(
        !work_line.contains(host_key.to_str().unwrap()),
        "host SSH private key must NEVER be mounted into workspace container"
    );
    assert!(work_line.contains("GIT_CONFIG_SYSTEM=/home/agy/.gitconfig-gateway"));

    let _ = fs::remove_dir_all(&root);
}
