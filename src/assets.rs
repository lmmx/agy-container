use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Embedded runtime assets compiled directly into the `agy-container` binary.
pub struct AssetSpec {
    pub name: &'static str,
    pub content: &'static str,
    pub executable: bool,
}

pub const ASSETS: &[AssetSpec] = &[
    AssetSpec {
        name: "Containerfile.agy",
        content: include_str!("../assets/Containerfile.agy"),
        executable: false,
    },
    AssetSpec {
        name: "Containerfile.proxy",
        content: include_str!("../assets/Containerfile.proxy"),
        executable: false,
    },
    AssetSpec {
        name: "Containerfile.gitgateway",
        content: include_str!("../assets/Containerfile.gitgateway"),
        executable: false,
    },
    AssetSpec {
        name: "squid.conf",
        content: include_str!("../assets/squid.conf"),
        executable: false,
    },
    AssetSpec {
        name: "squid.permissive.conf",
        content: include_str!("../assets/squid.permissive.conf"),
        executable: false,
    },
    AssetSpec {
        name: "sshd_gitgateway.conf",
        content: include_str!("../assets/sshd_gitgateway.conf"),
        executable: false,
    },
    AssetSpec {
        name: "git-gateway-entrypoint",
        content: include_str!("../assets/git-gateway-entrypoint"),
        executable: true,
    },
    AssetSpec {
        name: "git-policy",
        content: include_str!("../assets/git-policy"),
        executable: true,
    },
    AssetSpec {
        name: "verify-boundary.sh",
        content: include_str!("../assets/verify-boundary.sh"),
        executable: true,
    },
];

pub const DEFAULT_SQUID_CONF: &str = include_str!("../assets/squid.conf");

/// Materialized asset directory (either `$AGY_CONTAINER_DIR` or `~/.cache/agy-container/assets`).
#[derive(Debug, Clone)]
pub struct MaterializedAssets {
    pub dir: PathBuf,
    pub user_squid_conf: PathBuf,
}

impl MaterializedAssets {
    /// Materialize embedded assets without altering mtimes of unchanged files so
    /// Podman's layer cache stays warm. Seeds user-editable `squid.conf` once.
    pub fn prepare(cache_dir: &Path, config_dir: &Path) -> Result<Self, String> {
        let dir = if let Ok(override_dir) = std::env::var("AGY_CONTAINER_DIR") {
            let p = PathBuf::from(override_dir);
            if !p.is_dir() {
                return Err(format!(
                    "AGY_CONTAINER_DIR '{}' is not a readable directory",
                    p.display()
                ));
            }
            p
        } else {
            let target = cache_dir.join("assets");
            fs::create_dir_all(&target).map_err(|e| {
                format!(
                    "failed to create asset cache dir '{}': {e}",
                    target.display()
                )
            })?;
            for spec in ASSETS {
                write_if_changed(&target.join(spec.name), spec.content, spec.executable)?;
            }
            target
        };

        fs::create_dir_all(config_dir).map_err(|e| {
            format!(
                "failed to create config dir '{}': {e}",
                config_dir.display()
            )
        })?;
        let user_squid_conf = config_dir.join("squid.conf");
        if !user_squid_conf.exists() {
            fs::write(&user_squid_conf, DEFAULT_SQUID_CONF)
                .map_err(|e| format!("failed to seed '{}': {e}", user_squid_conf.display()))?;
        }

        Ok(Self {
            dir,
            user_squid_conf,
        })
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

fn write_if_changed(path: &Path, content: &str, executable: bool) -> Result<(), String> {
    let needs_write = match fs::read_to_string(path) {
        Ok(existing) => existing != content,
        Err(_) => true,
    };
    if needs_write {
        fs::write(path, content)
            .map_err(|e| format!("failed to write '{}': {e}", path.display()))?;
    }
    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("failed to chmod '{}': {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_containerfile_copy_source_is_embedded() {
        let names: Vec<&str> = ASSETS.iter().map(|a| a.name).collect();
        for asset in ASSETS {
            if !asset.name.starts_with("Containerfile.") {
                continue;
            }
            for line in asset.content.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("COPY ") {
                    let src = rest.split_whitespace().next().unwrap_or("");
                    assert!(
                        names.contains(&src),
                        "{} references COPY source '{}' not in ASSETS",
                        asset.name,
                        src
                    );
                }
            }
        }
    }

    #[test]
    fn default_squid_configs_block_private_destinations() {
        for name in ["squid.conf", "squid.permissive.conf"] {
            let asset = ASSETS.iter().find(|a| a.name == name).unwrap();
            assert!(
                asset.content.contains("acl private_dst dst"),
                "{name} must define private_dst ACL"
            );
            assert!(
                asset.content.contains("http_access deny  private_dst"),
                "{name} must deny private_dst before allow rules"
            );
            let deny_pos = asset.content.find("http_access deny  private_dst").unwrap();
            let allow_pos = asset
                .content
                .find("http_access allow")
                .expect("must have allow rule");
            assert!(
                deny_pos < allow_pos,
                "{name}: private_dst deny must precede http_access allow"
            );
        }
    }

    #[test]
    fn default_squid_conf_includes_fragments_before_deny_all() {
        let conf = DEFAULT_SQUID_CONF;
        let allow_inc = conf
            .find("include /etc/squid/conf.d/allow.conf")
            .expect("missing allow.conf include");
        let broker_inc = conf
            .find("include /etc/squid/conf.d/api-broker.conf")
            .expect("missing api-broker.conf include");
        let deny_all = conf
            .find("http_access deny  all")
            .expect("missing deny all");
        assert!(allow_inc < deny_all);
        assert!(broker_inc < deny_all);
    }
}
