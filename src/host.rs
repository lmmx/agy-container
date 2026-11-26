use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically create a private (`0700`) directory using `mkdir` without
/// `create_dir_all` so pre-existing directories or symlinks fail with `EEXIST`
/// and there is zero umask window before `0700` takes effect.
pub fn create_private_temp_dir(prefix: &str) -> Result<PathBuf, String> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0..16u64 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("{prefix}-{pid}-{nanos:x}-{seq}-{attempt}"));
        match DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "failed to atomically create private temp dir '{}': {e}",
                    candidate.display()
                ))
            }
        }
    }
    Err(format!(
        "failed to allocate unique private temp directory with prefix '{prefix}'"
    ))
}

/// RAII cleanup guard for an atomic temporary directory during multi-step setup.
#[derive(Debug)]
pub struct TempDirGuard {
    path: Option<PathBuf>,
}

impl TempDirGuard {
    pub fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub fn path(&self) -> &Path {
        self.path.as_deref().expect("TempDirGuard already disarmed")
    }

    pub fn disarm(mut self) -> PathBuf {
        self.path.take().expect("TempDirGuard already disarmed")
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_dir_all(p);
        }
    }
}

/// Delegated cgroup v2 controllers available to the current user for rootless Podman.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CgroupSupport {
    pub memory: bool,
    pub pids: bool,
    pub cpu: bool,
}

/// Resolved host directories and runtime environment capabilities.
#[derive(Debug, Clone)]
pub struct HostEnv {
    pub home: PathBuf,
    pub config_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub selinux_enforcing: bool,
    pub cgroups: CgroupSupport,
    pub has_subuid_mapping: bool,
    pub has_crun: bool,
}

impl HostEnv {
    pub fn resolve() -> Result<Self, String> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "HOME environment variable is not set".to_string())?;

        let config_dir = xdg_dir("XDG_CONFIG_HOME", &home.join(".config")).join("agy-container");
        let cache_dir = xdg_dir("XDG_CACHE_HOME", &home.join(".cache")).join("agy-container");
        let data_dir = xdg_dir("XDG_DATA_HOME", &home.join(".local/share")).join("agy-container");
        let state_dir = xdg_dir("XDG_STATE_HOME", &home.join(".local/state")).join("agy-container");

        let euid = current_euid();
        let username = current_username(&home);

        Ok(Self {
            home,
            config_dir,
            cache_dir,
            data_dir,
            state_dir,
            selinux_enforcing: detect_selinux_enforcing(),
            cgroups: detect_cgroup_support(euid),
            has_subuid_mapping: detect_subuid_mapping(euid, username.as_deref()),
            has_crun: detect_crun(),
        })
    }

    pub fn selinux_volume_suffix(&self) -> &'static str {
        if self.selinux_enforcing {
            ",z"
        } else {
            ""
        }
    }

    pub fn egress_log_path(&self) -> PathBuf {
        if let Ok(custom) = std::env::var("AGY_EGRESS_LOG") {
            if !custom.trim().is_empty() {
                return PathBuf::from(custom);
            }
        }
        self.state_dir.join("egress.log")
    }
}

fn xdg_dir(var: &str, fallback: &Path) -> PathBuf {
    match std::env::var(var) {
        Ok(val) if !val.trim().is_empty() => PathBuf::from(val),
        _ => fallback.to_path_buf(),
    }
}

pub fn expand_tilde(path: &Path, home: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = s.strip_prefix("~/") {
        return home.join(rest);
    }
    path.to_path_buf()
}

pub fn resolve_dir(path: &Path, home: &Path) -> Result<PathBuf, String> {
    let expanded = expand_tilde(path, home);
    let canon = fs::canonicalize(&expanded)
        .map_err(|e| format!("cannot resolve directory '{}': {e}", expanded.display()))?;
    if !canon.is_dir() {
        return Err(format!("'{}' is not a directory", canon.display()));
    }
    Ok(canon)
}

pub fn current_euid() -> u32 {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(euid_str) = rest.split_whitespace().nth(1) {
                    if let Ok(id) = euid_str.parse::<u32>() {
                        return id;
                    }
                }
            }
        }
    }
    1000
}

fn current_username(home: &Path) -> Option<String> {
    if let Ok(u) = std::env::var("USER") {
        if !u.trim().is_empty() {
            return Some(u);
        }
    }
    home.file_name().map(|s| s.to_string_lossy().into_owned())
}

fn detect_selinux_enforcing() -> bool {
    Command::new("getenforce")
        .output()
        .ok()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .eq_ignore_ascii_case("enforcing")
        })
        .unwrap_or(false)
}

fn detect_crun() -> bool {
    Command::new("crun")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Probe cgroups v2 delegation for the current user slice so rootless Podman
/// never crashes when memory/pids/cpu controllers are undelegated.
pub fn detect_cgroup_support(euid: u32) -> CgroupSupport {
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
        return CgroupSupport::default();
    }
    if euid == 0 {
        return CgroupSupport {
            memory: true,
            pids: true,
            cpu: true,
        };
    }

    // Check systemd user slice delegation first (standard rootless Podman path).
    let slice_path = format!("/sys/fs/cgroup/user.slice/user-{euid}.slice/cgroup.controllers");
    if let Ok(controllers) = fs::read_to_string(&slice_path) {
        return parse_controllers(&controllers);
    }

    CgroupSupport::default()
}

pub fn parse_controllers(controllers: &str) -> CgroupSupport {
    let mut support = CgroupSupport::default();
    for tok in controllers.split_whitespace() {
        match tok {
            "memory" => support.memory = true,
            "pids" => support.pids = true,
            "cpu" => support.cpu = true,
            _ => {}
        }
    }
    support
}

/// Check whether `/etc/subuid` and `/etc/subgid` grant subordinate ID ranges to
/// the invoking user. When absent, rootless Podman operates in single-mapping
/// mode where `--userns=keep-id:uid=1000,gid=1000` fails.
pub fn detect_subuid_mapping(euid: u32, username: Option<&str>) -> bool {
    if euid == 0 {
        return true;
    }
    let uid_str = euid.to_string();
    has_subid_entry("/etc/subuid", &uid_str, username)
        && has_subid_entry("/etc/subgid", &uid_str, username)
}

pub fn has_subid_entry(path: &str, uid_str: &str, username: Option<&str>) -> bool {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    parse_subid_content(&content, uid_str, username)
}

pub fn parse_subid_content(content: &str, uid_str: &str, username: Option<&str>) -> bool {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split(':');
        let Some(owner) = parts.next() else { continue };
        let Some(_start) = parts.next() else { continue };
        let Some(count_str) = parts.next() else {
            continue;
        };
        let count: u64 = count_str.parse().unwrap_or(0);
        if count == 0 {
            continue;
        }
        if owner == uid_str || username.is_some_and(|u| u == owner) {
            return true;
        }
    }
    false
}

/// Locate the user's global `.gitconfig` if it exists as a regular file.
pub fn host_gitconfig(home: &Path) -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("GIT_CONFIG_GLOBAL") {
        let p = PathBuf::from(custom);
        if p.is_file() {
            return Some(p);
        }
    }
    let default = home.join(".gitconfig");
    if default.is_file() {
        return Some(default);
    }
    None
}

/// Scan a `.gitconfig` file for patterns that could leak credentials or pull in
/// unmounted host files when bind-mounted into the workspace container.
pub fn gitconfig_warnings(content: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut in_credential = false;
    let mut in_include = false;

    for (i, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let lower = line.to_ascii_lowercase();
            in_credential = lower.starts_with("[credential");
            in_include = lower.starts_with("[include");
            if lower.contains("@github.com")
                || lower.contains("ghp_")
                || lower.contains("github_pat_")
                || (lower.starts_with("[url \"https://") && lower.contains('@'))
            {
                warnings.push(format!(
                    "line {}: URL section may contain an inline credential",
                    i + 1
                ));
            }
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if in_credential && lower.starts_with("helper") {
            warnings.push(format!(
                "line {}: credential.helper configured (check that no host token store is exposed)",
                i + 1
            ));
        }
        if in_include && lower.starts_with("path") {
            warnings.push(format!(
                "line {}: [include]/[includeIf] path may reference files outside the container",
                i + 1
            ));
        }
        if lower.contains("ghp_") || lower.contains("github_pat_") || lower.contains("glpat-") {
            warnings.push(format!(
                "line {}: possible personal access token detected in gitconfig",
                i + 1
            ));
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cgroup_controllers() {
        let c = parse_controllers("cpuset cpu io memory pids");
        assert!(c.memory && c.pids && c.cpu);
        let c2 = parse_controllers("memory");
        assert!(c2.memory && !c2.pids && !c2.cpu);
    }

    #[test]
    fn parses_subuid_entries() {
        let content = "# comment\nantigravity:100000:65536\n";
        assert!(parse_subid_content(content, "1001", Some("antigravity")));
        assert!(!parse_subid_content("", "1001", Some("antigravity")));
        assert!(!parse_subid_content(
            "other:100000:65536\n",
            "1001",
            Some("antigravity")
        ));
        assert!(parse_subid_content("1001:100000:65536\n", "1001", None));
    }

    #[test]
    fn detects_gitconfig_risks() {
        let sample = r#"
[user]
    name = Dev
[credential]
    helper = store
[includeIf "gitdir:~/work/"]
    path = ~/.gitconfig-work
[url "https://user:ghp_secret@github.com/"]
    insteadOf = https://github.com/
"#;
        let w = gitconfig_warnings(sample);
        assert_eq!(w.len(), 3);
    }
}
