use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::assets::MaterializedAssets;
use crate::host::HostEnv;

pub const IMAGE_AGY: &str = "localhost/agy-container-agy:latest";
pub const IMAGE_PROXY: &str = "localhost/agy-container-proxy:latest";
pub const IMAGE_GITGW: &str = "localhost/agy-container-gitgateway:latest";

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;

static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);
static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
    fn isatty(fd: i32) -> i32;
}

extern "C" fn handle_sigterm(_sig: i32) {
    SIGTERM_RECEIVED.store(true, Ordering::SeqCst);
}

pub fn sigterm_received() -> bool {
    SIGTERM_RECEIVED.load(Ordering::SeqCst)
}

/// Ignore `SIGINT` in the parent runner while restoring `SIG_DFL` in every
/// spawned child, and catch `SIGTERM` cooperatively so container teardown
/// always completes cleanly.
pub fn install_signal_handlers() {
    unsafe {
        signal(SIGINT, SIG_IGN);
        signal(SIGTERM, handle_sigterm as *const () as usize);
    }
}

pub fn stdin_is_tty() -> bool {
    unsafe { isatty(0) == 1 }
}

pub fn stdout_is_tty() -> bool {
    unsafe { isatty(1) == 1 }
}

/// Generate a collision-free per-run identifier (`agy-<8hex>`) so concurrent
/// `agy-container` invocations have completely independent networks & sidecars.
pub fn generate_run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let seq = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mix = nanos ^ (pid.wrapping_mul(0x9e37_79b9_7f4a_7c15)) ^ seq.wrapping_shl(32);
    format!("agy-{:08x}", (mix ^ (mix >> 32)) as u32)
}

/// Build a `podman` command that restores default signal disposition in the child.
pub fn podman_cmd() -> Command {
    let mut cmd = Command::new("podman");
    unsafe {
        cmd.pre_exec(|| {
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            Ok(())
        });
    }
    cmd
}

pub fn run_capture<I, S>(args: I) -> Result<(ExitStatus, String, String), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = podman_cmd()
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute podman: {e}"))?;
    Ok((
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

pub fn image_exists(image: &str) -> bool {
    run_capture(["image", "exists", image])
        .map(|(st, _, _)| st.success())
        .unwrap_or(false)
}

pub fn build_image(
    tag: &str,
    containerfile: &Path,
    context_dir: &Path,
    no_cache: bool,
) -> Result<(), String> {
    let mut cmd = podman_cmd();
    cmd.args(["build", "-t", tag, "-f"]).arg(containerfile);
    if no_cache {
        cmd.arg("--no-cache");
    }
    if let Ok(base) = std::env::var("AGY_BASE_IMAGE") {
        if !base.trim().is_empty() && tag == IMAGE_AGY {
            cmd.args(["--build-arg", &format!("BASE_IMAGE={base}")]);
        }
    }
    if let Ok(fp) = std::env::var("GITHUB_SSH_FINGERPRINT") {
        if !fp.trim().is_empty() && tag == IMAGE_GITGW {
            cmd.args(["--build-arg", &format!("GITHUB_SSH_FINGERPRINT={fp}")]);
        }
    }
    cmd.arg(context_dir);

    eprintln!("agy-container: building {tag} ...");
    let status = cmd
        .status()
        .map_err(|e| format!("failed to run podman build for {tag}: {e}"))?;
    if !status.success() {
        return Err(format!("podman build failed for {tag} (exit {status})"));
    }
    Ok(())
}

pub fn ensure_images(
    assets: &MaterializedAssets,
    need_proxy: bool,
    need_gitgw: bool,
    force_build: bool,
    no_cache: bool,
) -> Result<(), String> {
    if force_build || !image_exists(IMAGE_AGY) {
        build_image(
            IMAGE_AGY,
            &assets.path("Containerfile.agy"),
            &assets.dir,
            no_cache,
        )?;
    }
    if need_proxy && (force_build || !image_exists(IMAGE_PROXY)) {
        build_image(
            IMAGE_PROXY,
            &assets.path("Containerfile.proxy"),
            &assets.dir,
            no_cache,
        )?;
    }
    if need_gitgw && (force_build || !image_exists(IMAGE_GITGW)) {
        build_image(
            IMAGE_GITGW,
            &assets.path("Containerfile.gitgateway"),
            &assets.dir,
            no_cache,
        )?;
    }
    Ok(())
}

/// RAII container & network lifecycle guard for one `agy-container` run.
/// Ensures all per-run containers, networks, and ephemeral config files are
/// cleaned up on normal exit, error, timeout, or `SIGTERM`.
#[derive(Debug)]
pub struct RunTopology {
    pub run_id: String,
    pub caged_net: Option<String>,
    pub egress_net: Option<String>,
    pub proxy_name: Option<String>,
    pub gitgw_name: Option<String>,
    pub work_name: String,
    pub run_temp_dir: PathBuf,
}

impl RunTopology {
    pub fn new(run_id: String) -> Result<Self, String> {
        let run_temp_dir =
            crate::host::create_private_temp_dir(&format!("agy-container-run-{run_id}"))?;

        let work_name = format!("agy-work-{run_id}");
        Ok(Self {
            run_id,
            caged_net: None,
            egress_net: None,
            proxy_name: None,
            gitgw_name: None,
            work_name,
            run_temp_dir,
        })
    }

    pub fn write_run_file(&self, name: &str, content: &str, mode: u32) -> Result<PathBuf, String> {
        let path = self.run_temp_dir.join(name);
        fs::write(&path, content)
            .map_err(|e| format!("failed to write '{}': {e}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .map_err(|e| format!("failed to chmod '{}': {e}", path.display()))?;
        Ok(path)
    }

    /// Create the per-run isolated `--internal` network and egress network.
    /// `--disable-dns` avoids aardvark-dns failures on hosts without systemd/D-Bus
    /// and removes the internal DNS listener from `caged` (sidecars are pinned via
    /// immutable `--add-host` entries instead).
    pub fn create_networks(&mut self) -> Result<(String, String), String> {
        let caged = format!("agy-caged-{}", self.run_id);
        let egress = format!("agy-egress-{}", self.run_id);

        let (st, _, err) =
            run_capture(["network", "create", "--internal", "--disable-dns", &caged])?;
        if !st.success() {
            return Err(format!(
                "failed to create internal network '{caged}': {}",
                err.trim()
            ));
        }
        self.caged_net = Some(caged.clone());

        let (st, _, err) = run_capture(["network", "create", "--disable-dns", &egress])?;
        if !st.success() {
            return Err(format!(
                "failed to create egress network '{egress}': {}",
                err.trim()
            ));
        }
        self.egress_net = Some(egress.clone());

        Ok((caged, egress))
    }

    /// Start the hardened Squid proxy straddling `egress` and `caged`, returning
    /// its IP address on `caged` for immutable `/etc/hosts` pinning.
    pub fn start_proxy(
        &mut self,
        squid_conf: &Path,
        allow_conf: &Path,
        broker_conf: &Path,
        host: &HostEnv,
    ) -> Result<String, String> {
        let caged = self
            .caged_net
            .clone()
            .ok_or_else(|| "internal error: caged network not created".to_string())?;
        let egress = self
            .egress_net
            .clone()
            .ok_or_else(|| "internal error: egress network not created".to_string())?;
        let name = format!("agy-proxy-{}", self.run_id);
        let se = host.selinux_volume_suffix();

        let mut args: Vec<String> = Vec::new();
        if !host.has_subuid_mapping {
            if !host.has_crun {
                return Err(
                    "rootless Podman requires either /etc/subuid+/etc/subgid ranges or `crun` installed on PATH to run Squid as non-root".to_string(),
                );
            }
            args.push("--runtime".into());
            args.push("crun".into());
        }
        args.extend([
            "create".into(),
            "--name".into(),
            name.clone(),
            "--label".into(),
            format!("agy-container.run={}", self.run_id),
            "--label".into(),
            "agy-container.role=proxy".into(),
            "--network".into(),
            egress,
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges:true".into(),
            "--read-only".into(),
            "--tmpfs".into(),
            "/var/cache/squid:rw,noexec,nosuid,size=16m".into(),
            "--tmpfs".into(),
            "/var/run:rw,noexec,nosuid,size=8m".into(),
            "--tmpfs".into(),
            "/tmp:rw,noexec,nosuid,size=16m".into(),
            "-v".into(),
            format!("{}:/etc/squid/squid.conf:ro{se}", squid_conf.display()),
            "-v".into(),
            format!(
                "{}:/etc/squid/conf.d/allow.conf:ro{se}",
                allow_conf.display()
            ),
            "-v".into(),
            format!(
                "{}:/etc/squid/conf.d/api-broker.conf:ro{se}",
                broker_conf.display()
            ),
        ]);

        if host.cgroups.pids {
            args.push("--pids-limit=256".into());
        } else {
            args.push("--ulimit".into());
            args.push("nproc=256:256".into());
        }
        if host.cgroups.memory {
            args.push("--memory=512m".into());
            args.push("--memory-swap=512m".into());
        }
        if !host.has_subuid_mapping {
            args.push("--uidmap".into());
            args.push("31:0:1".into());
            args.push("--gidmap".into());
            args.push("31:0:1".into());
            args.push("--user".into());
            args.push("31:31".into());
            args.push("--sysctl".into());
            args.push("net.ipv4.ping_group_range=31 31".into());
        }
        args.push(IMAGE_PROXY.into());

        let (st, _, err) = run_capture(&args)?;
        if !st.success() {
            return Err(format!("failed to create proxy container: {}", err.trim()));
        }
        self.proxy_name = Some(name.clone());

        let (st, _, err) = run_capture(["network", "connect", "--alias", "proxy", &caged, &name])?;
        if !st.success() {
            return Err(format!(
                "failed to attach proxy to internal network: {}",
                err.trim()
            ));
        }

        let (st, _, err) = run_capture(["start", &name])?;
        if !st.success() {
            return Err(format!("failed to start proxy container: {}", err.trim()));
        }

        inspect_container_ip(&name, &caged).map_err(|ip_err| {
            let (out, err) = self.container_logs(&name);
            format!(
                "{ip_err} (proxy exited immediately)\n--- stdout ---\n{}\n--- stderr ---\n{}",
                out.trim(),
                err.trim()
            )
        })
    }

    /// Start the per-run SSH `git-gateway` sidecar straddling `egress` and `caged`,
    /// returning its IP address on `caged`.
    pub fn start_git_gateway(
        &mut self,
        gw: &crate::gitgateway::GitGatewaySession,
        host: &HostEnv,
    ) -> Result<String, String> {
        let caged = self
            .caged_net
            .clone()
            .ok_or_else(|| "internal error: caged network not created".to_string())?;
        let egress = self
            .egress_net
            .clone()
            .ok_or_else(|| "internal error: egress network not created".to_string())?;
        let name = format!("agy-gitgw-{}", self.run_id);
        let se = host.selinux_volume_suffix();

        let mut args: Vec<String> = vec![
            "create".into(),
            "--name".into(),
            name.clone(),
            "--label".into(),
            format!("agy-container.run={}", self.run_id),
            "--label".into(),
            "agy-container.role=git-gateway".into(),
            "--network".into(),
            egress,
            "--cap-drop=ALL".into(),
            "--cap-add=SETUID".into(),
            "--cap-add=SETGID".into(),
            "--cap-add=CHOWN".into(),
            "--cap-add=DAC_OVERRIDE".into(),
            "--cap-add=SYS_CHROOT".into(),
            "--cap-add=KILL".into(),
            "--security-opt=no-new-privileges:true".into(),
            "-e".into(),
            format!("AGY_GITGW_PUSH={}", if gw.push_enabled { "1" } else { "0" }),
            "-e".into(),
            format!("AGY_GITGW_REPOS={}", gw.repos_csv()),
            "-v".into(),
            format!("{}:/run/secrets/git-key:ro{se}", gw.host_ssh_key.display()),
            "-v".into(),
            format!(
                "{}:/run/secrets/host_key:ro{se}",
                gw.sidecar_host_key.display()
            ),
            "-v".into(),
            format!(
                "{}:/run/secrets/authorized_keys:ro{se}",
                gw.authorized_keys.display()
            ),
        ];

        if host.cgroups.pids {
            args.push("--pids-limit=256".into());
        } else {
            args.push("--ulimit".into());
            args.push("nproc=256:256".into());
        }
        if host.cgroups.memory {
            args.push("--memory=256m".into());
            args.push("--memory-swap=256m".into());
        }
        args.push(IMAGE_GITGW.into());

        let (st, _, err) = run_capture(&args)?;
        if !st.success() {
            return Err(format!(
                "failed to create git-gateway container: {}",
                err.trim()
            ));
        }
        self.gitgw_name = Some(name.clone());

        let (st, _, err) = run_capture([
            "network",
            "connect",
            "--alias",
            "git-gateway",
            &caged,
            &name,
        ])?;
        if !st.success() {
            return Err(format!(
                "failed to attach git-gateway to internal network: {}",
                err.trim()
            ));
        }

        let (st, _, err) = run_capture(["start", &name])?;
        if !st.success() {
            return Err(format!(
                "failed to start git-gateway container: {}",
                err.trim()
            ));
        }

        inspect_container_ip(&name, &caged).map_err(|ip_err| {
            let (out, err) = self.container_logs(&name);
            let subuid_hint = if !host.has_subuid_mapping {
                "\nhint: --github git-gateway requires subordinate UID/GID ranges in /etc/subuid and /etc/subgid for sshd privilege separation (user `gitgw`)"
            } else {
                ""
            };
            format!(
                "{ip_err} (git-gateway exited immediately)\n--- stdout ---\n{}\n--- stderr ---\n{}{subuid_hint}",
                out.trim(),
                err.trim()
            )
        })
    }

    pub fn is_running(&self, name: &str) -> bool {
        run_capture(["inspect", "-f", "{{.State.Running}}", name])
            .map(|(st, out, _)| st.success() && out.trim() == "true")
            .unwrap_or(false)
    }

    pub fn container_logs(&self, name: &str) -> (String, String) {
        run_capture(["logs", name])
            .map(|(_, out, err)| (out, err))
            .unwrap_or_default()
    }

    /// Wait briefly to verify a sidecar process stays alive after startup.
    pub fn wait_sidecar_alive(&self, name: &str, settle_ms: u64) -> bool {
        std::thread::sleep(Duration::from_millis(settle_ms));
        self.is_running(name)
    }

    pub fn stop_workspace_gracefully(&self) {
        let _ = run_capture(["stop", "--time", "10", &self.work_name]);
    }

    /// Explicitly tear down all per-run containers, networks, and temp files.
    pub fn teardown(&mut self) {
        let _ = run_capture(["rm", "-f", &self.work_name]);
        if let Some(gw) = self.gitgw_name.take() {
            let _ = run_capture(["rm", "-f", &gw]);
        }
        if let Some(proxy) = self.proxy_name.take() {
            let _ = run_capture(["rm", "-f", &proxy]);
        }
        if let Some(net) = self.caged_net.take() {
            let _ = run_capture(["network", "rm", "-f", &net]);
        }
        if let Some(net) = self.egress_net.take() {
            let _ = run_capture(["network", "rm", "-f", &net]);
        }
        let _ = fs::remove_dir_all(&self.run_temp_dir);
    }
}

impl Drop for RunTopology {
    fn drop(&mut self) {
        self.teardown();
    }
}

pub fn inspect_container_ip(container: &str, network: &str) -> Result<String, String> {
    let tpl = format!("{{{{(index .NetworkSettings.Networks \"{network}\").IPAddress}}}}");
    let (st, out, err) = run_capture(["inspect", "-f", &tpl, container])?;
    if !st.success() {
        return Err(format!(
            "failed to inspect IP of '{container}' on '{network}': {}",
            err.trim()
        ));
    }
    let ip = out.trim().to_string();
    if ip.is_empty() {
        return Err(format!(
            "container '{container}' has no IP address on network '{network}'"
        ));
    }
    Ok(ip)
}

/// Wait for a spawned workspace container with optional wall-clock timeout and
/// cooperative `SIGTERM` handling.
pub fn wait_workspace(
    child: &mut Child,
    topo: &RunTopology,
    timeout: Option<Duration>,
) -> Result<(ExitStatus, bool), String> {
    let start = Instant::now();
    loop {
        if sigterm_received() {
            eprintln!("agy-container: SIGTERM received; stopping container cleanly...");
            topo.stop_workspace_gracefully();
            let _ = child.kill();
            let status = child
                .wait()
                .map_err(|e| format!("failed waiting for workspace process: {e}"))?;
            return Ok((status, false));
        }

        if let Some(limit) = timeout {
            if start.elapsed() >= limit {
                topo.stop_workspace_gracefully();
                let _ = child.kill();
                let status = child
                    .wait()
                    .map_err(|e| format!("failed waiting after timeout: {e}"))?;
                return Ok((status, true));
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, false)),
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("error polling workspace process: {e}")),
        }
    }
}

/// Verify that host rootless Podman genuinely enforces `--internal` networks
/// (no default route, no TCP egress to `1.1.1.1:443`, no DNS via `1.1.1.1`).
pub fn run_precondition_check(host: &HostEnv) -> Result<(), String> {
    let net = format!("agy-precond-{}", generate_run_id());
    let (st, _, err) = run_capture(["network", "create", "--internal", "--disable-dns", &net])?;
    if !st.success() {
        return Err(format!(
            "precondition failed: could not create --internal network: {}",
            err.trim()
        ));
    }

    // Prefer already-built local proxy image (Alpine) to avoid registry pulls when offline.
    let probe_image = if image_exists(IMAGE_PROXY) {
        IMAGE_PROXY
    } else {
        "mirror.gcr.io/library/alpine:3.20"
    };

    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network".to_string(),
        net.clone(),
        "--cap-drop=ALL".to_string(),
        "--security-opt=no-new-privileges:true".to_string(),
        "--entrypoint".to_string(),
        "/bin/sh".to_string(),
    ];
    if !host.has_subuid_mapping {
        args.push("--user".to_string());
        args.push("0:0".to_string());
    }
    args.push(probe_image.to_string());
    args.push("-c".to_string());
    args.push(
        "if ip route 2>/dev/null | grep -q '^default '; then echo 'FAIL: default route present'; exit 1; fi; \
         if nc -z -w 2 1.1.1.1 443 2>/dev/null; then echo 'FAIL: 1.1.1.1:443 reachable'; exit 1; fi; \
         if nc -z -w 2 1.1.1.1 53 2>/dev/null; then echo 'FAIL: 1.1.1.1:53 reachable'; exit 1; fi; \
         echo 'PASS: internal network has no default route and blocks 1.1.1.1:443 and 1.1.1.1:53'"
            .to_string(),
    );

    let result = run_capture(&args);
    let _ = run_capture(["network", "rm", "-f", &net]);

    let (st, out, err) = result?;
    if !st.success() {
        return Err(format!(
            "precondition failed:\nstdout: {}\nstderr: {}",
            out.trim(),
            err.trim()
        ));
    }
    println!("{}", out.trim());
    Ok(())
}

/// Spawn the workspace container using direct `podman run` flags.
#[allow(clippy::too_many_arguments)]
pub fn spawn_workspace(
    args: &[String],
    interactive_tty: bool,
    keep_stdin_open: bool,
) -> Result<Child, String> {
    let mut cmd = podman_cmd();
    cmd.args(args);
    if interactive_tty || keep_stdin_open {
        cmd.stdin(Stdio::inherit());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    cmd.spawn()
        .map_err(|e| format!("failed to launch workspace container: {e}"))
}
