use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::GitHubMode;
use crate::host::{create_private_temp_dir, expand_tilde, TempDirGuard};

pub const GIT_GATEWAY_PORT: u16 = 2222;

/// Per-run RAII material for the SSH `git-gateway` sidecar.
///
/// Generates fresh throwaway ed25519 client and host keypairs for every run,
/// pinning the sidecar's host key in advance so the workspace verifies the
/// sidecar strictly (`StrictHostKeyChecking yes`) and never sees the real
/// host SSH key. Deletes all throwaway files on `Drop`.
#[derive(Debug)]
pub struct GitGatewaySession {
    pub temp_dir: PathBuf,
    pub host_ssh_key: PathBuf,
    pub sidecar_host_key: PathBuf,
    pub authorized_keys: PathBuf,
    pub client_key: PathBuf,
    pub client_known_hosts: PathBuf,
    pub client_ssh_config: PathBuf,
    pub client_gitconfig_gateway: PathBuf,
    pub push_enabled: bool,
    pub allowed_repos: Vec<String>,
}

impl GitGatewaySession {
    pub fn prepare(
        run_id: &str,
        mode: GitHubMode,
        explicit_key: Option<&Path>,
        repos: &[String],
        home: &Path,
    ) -> Result<Option<Self>, String> {
        let key_path = match explicit_key {
            Some(p) => expand_tilde(p, home),
            None => home.join(".ssh/id_ed25519"),
        };

        if !key_path.is_file() {
            if mode == GitHubMode::Push || explicit_key.is_some() {
                return Err(format!(
                    "SSH private key '{}' not found (required for --github=push or explicit --git-key)",
                    key_path.display()
                ));
            }
            eprintln!(
                "agy-container: note: '{}' not found; skipping SSH git-gateway sidecar (public HTTPS reads via --allow github remain available)",
                key_path.display()
            );
            return Ok(None);
        }

        // Refuse passphrase-encrypted keys loudly because the sidecar runs in BatchMode=yes.
        if let Ok(raw) = fs::read_to_string(&key_path) {
            if is_encrypted_ssh_key(&raw) {
                return Err(format!(
                    "SSH key '{}' appears passphrase-encrypted; git-gateway runs non-interactively (BatchMode=yes). Use a dedicated unencrypted deploy key via --git-key",
                    key_path.display()
                ));
            }
        }

        // Validate repo allowlist entries strictly before passing into sidecar env.
        let mut normalized_repos = Vec::new();
        for r in repos {
            normalized_repos.push(validate_github_repo(r)?);
        }

        let guard = TempDirGuard::new(create_private_temp_dir(&format!(
            "agy-container-gitgw-{run_id}"
        ))?);
        let temp_dir = guard.path().to_path_buf();

        let client_key = temp_dir.join("client_key");
        let sidecar_host_key = temp_dir.join("host_key");

        generate_ed25519(&client_key, "agy-container-client")?;
        generate_ed25519(&sidecar_host_key, "agy-container-gitgw-host")?;

        let client_pub = fs::read_to_string(temp_dir.join("client_key.pub"))
            .map_err(|e| format!("failed to read client public key: {e}"))?;
        let host_pub = fs::read_to_string(temp_dir.join("host_key.pub"))
            .map_err(|e| format!("failed to read sidecar host public key: {e}"))?;

        let authorized_keys = temp_dir.join("authorized_keys");
        let auth_line = format!(
            "restrict,command=\"/usr/local/bin/git-policy\" {}\n",
            client_pub.trim()
        );
        fs::write(&authorized_keys, auth_line)
            .map_err(|e| format!("failed to write authorized_keys: {e}"))?;
        fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("failed to chmod authorized_keys: {e}"))?;

        let client_known_hosts = temp_dir.join("known_hosts");
        let known_line = format!("[git-gateway]:{GIT_GATEWAY_PORT} {}\n", host_pub.trim());
        fs::write(&client_known_hosts, known_line)
            .map_err(|e| format!("failed to write known_hosts: {e}"))?;
        fs::set_permissions(&client_known_hosts, fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("failed to chmod known_hosts: {e}"))?;

        let client_ssh_config = temp_dir.join("ssh_config");
        let ssh_cfg = format!(
            "\
Host git-gateway
    HostName git-gateway
    Port {GIT_GATEWAY_PORT}
    User gitgw
    IdentityFile /home/agy/.ssh/gitgw_key
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /home/agy/.ssh/gitgw_known_hosts
"
        );
        fs::write(&client_ssh_config, ssh_cfg)
            .map_err(|e| format!("failed to write ssh_config: {e}"))?;
        fs::set_permissions(&client_ssh_config, fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("failed to chmod ssh_config: {e}"))?;

        let client_gitconfig_gateway = temp_dir.join("gitconfig-gateway");
        let git_cfg = "\
[core]
    sshCommand = ssh -F /home/agy/.ssh/gitgw_config
[url \"git-gateway:\"]
    insteadOf = git@github.com:
    insteadOf = ssh://git@github.com/
    insteadOf = https://github.com/
";
        fs::write(&client_gitconfig_gateway, git_cfg)
            .map_err(|e| format!("failed to write gitconfig-gateway: {e}"))?;
        fs::set_permissions(&client_gitconfig_gateway, fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("failed to chmod gitconfig-gateway: {e}"))?;

        Ok(Some(Self {
            temp_dir: guard.disarm(),
            host_ssh_key: key_path,
            sidecar_host_key,
            authorized_keys,
            client_key,
            client_known_hosts,
            client_ssh_config,
            client_gitconfig_gateway,
            push_enabled: mode == GitHubMode::Push,
            allowed_repos: normalized_repos,
        }))
    }

    pub fn repos_csv(&self) -> String {
        self.allowed_repos.join(",")
    }
}

impl Drop for GitGatewaySession {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

fn generate_ed25519(path: &Path, comment: &str) -> Result<(), String> {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .status()
        .map_err(|e| format!("failed to invoke ssh-keygen: {e}"))?;
    if !status.success() {
        return Err(format!("ssh-keygen failed with status {status}"));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod '{}': {e}", path.display()))?;
    Ok(())
}

pub fn validate_github_repo(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_start_matches('/').trim_end_matches(".git");
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(format!(
            "invalid --git-repo '{raw}': expected OWNER/REPO format"
        ));
    }
    for part in &parts {
        if *part == "."
            || *part == ".."
            || part.starts_with('-')
            || !part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(format!(
                "invalid --git-repo '{raw}': disallowed characters in '{part}'"
            ));
        }
    }
    Ok(format!("{}/{}", parts[0], parts[1]))
}

pub fn is_encrypted_ssh_key(pem: &str) -> bool {
    if pem.contains("ENCRYPTED") {
        return true;
    }
    // OpenSSH new-format keys store cipher name right after the "openssh-key-v1\0" header.
    // An unencrypted key uses ciphername "none"; anything else (e.g. aes256-ctr) is encrypted.
    if pem.contains("BEGIN OPENSSH PRIVATE KEY") {
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(str::trim)
            .collect();
        if let Some(bytes) = decode_base64_prefix(&b64, 64) {
            if let Some(rest) = bytes.strip_prefix(b"openssh-key-v1\0") {
                if rest.len() >= 8 {
                    let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                    if rest.len() >= 4 + len {
                        let cipher = &rest[4..4 + len];
                        return cipher != b"none";
                    }
                }
            }
        }
    }
    false
}

fn decode_base64_prefix(input: &str, max_bytes: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(max_bytes);
    let mut buf = [0u8; 4];
    let mut n = 0usize;
    for b in input.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        };
        buf[n] = v;
        n += 1;
        if n == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
            out.push((buf[2] << 6) | buf[3]);
            n = 0;
            if out.len() >= max_bytes {
                break;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_github_repos() {
        assert_eq!(
            validate_github_repo("lmmx/agy-container.git").unwrap(),
            "lmmx/agy-container"
        );
        assert_eq!(
            validate_github_repo("/lmmx/agy-container").unwrap(),
            "lmmx/agy-container"
        );
        assert!(validate_github_repo("justname").is_err());
        assert!(validate_github_repo("a/b/c").is_err());
        assert!(validate_github_repo("a/..").is_err());
        assert!(validate_github_repo("a/b;id").is_err());
    }

    #[test]
    fn client_port_matches_sshd_config() {
        let sshd = include_str!("../assets/sshd_gitgateway.conf");
        assert!(
            sshd.contains(&format!("Port {GIT_GATEWAY_PORT}")),
            "sshd_gitgateway.conf must listen on GIT_GATEWAY_PORT ({GIT_GATEWAY_PORT})"
        );
    }

    #[test]
    fn sshd_offers_single_pinned_host_key() {
        let sshd = include_str!("../assets/sshd_gitgateway.conf");
        let host_keys: Vec<&str> = sshd
            .lines()
            .filter(|l| l.trim_start().starts_with("HostKey "))
            .collect();
        assert_eq!(host_keys, vec!["HostKey /run/secrets/host_key"]);
    }
}
