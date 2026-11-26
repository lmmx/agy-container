use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::host::resolve_dir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
}

impl AccessMode {
    pub fn podman_flag(self) -> &'static str {
        match self {
            Self::ReadOnly => "ro",
            Self::ReadWrite => "rw",
        }
    }
}

/// Validated extra directory mount exposed at `/mnt/<name>` and passed via `--add-dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraMount {
    pub host_path: PathBuf,
    pub container_path: String,
    pub mode: AccessMode,
}

impl ExtraMount {
    pub fn volume_arg(&self, selinux_suffix: &str) -> String {
        format!(
            "{}:{}:{}{}",
            self.host_path.display(),
            self.container_path,
            self.mode.podman_flag(),
            selinux_suffix
        )
    }
}

/// Resolve and validate all extra `--ro` and `--rw` mounts.
/// Rejects filesystem roots, duplicate basenames, paths containing `:`, and mounts
/// identical to the workspace root.
pub fn collect_mounts(
    workspace: &Path,
    ro_dirs: &[PathBuf],
    rw_dirs: &[PathBuf],
    home: &Path,
) -> Result<Vec<ExtraMount>, String> {
    let mut mounts = Vec::new();
    let mut seen_names: HashMap<String, PathBuf> = HashMap::new();

    let entries = ro_dirs
        .iter()
        .map(|p| (p, AccessMode::ReadOnly))
        .chain(rw_dirs.iter().map(|p| (p, AccessMode::ReadWrite)));

    for (raw_path, mode) in entries {
        let canon = resolve_dir(raw_path, home)?;
        if canon.to_string_lossy().contains(':') {
            return Err(format!(
                "extra mount path '{}' contains ':', which is unsupported in Podman -v volume specs",
                canon.display()
            ));
        }
        if canon == Path::new("/") {
            return Err("refusing to mount filesystem root '/' into the container".to_string());
        }
        if canon == workspace {
            return Err(format!(
                "extra mount '{}' duplicates the workspace directory (already mounted at /workspace)",
                canon.display()
            ));
        }
        let base = canon
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                format!(
                    "cannot derive valid UTF-8 mount name from '{}'",
                    canon.display()
                )
            })?
            .to_string();

        if let Some(prev) = seen_names.get(&base) {
            return Err(format!(
                "extra mount basename collision for '/mnt/{base}': '{}' and '{}'",
                prev.display(),
                canon.display()
            ));
        }
        seen_names.insert(base.clone(), canon.clone());

        mounts.push(ExtraMount {
            host_path: canon,
            container_path: format!("/mnt/{base}"),
            mode,
        });
    }

    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rejects_root_and_duplicate_basenames() {
        let base = std::env::temp_dir().join(format!("agy-mounts-test-{}", std::process::id()));
        let ws = base.join("ws");
        let a = base.join("one/shared");
        let b = base.join("two/shared");
        fs::create_dir_all(&ws).unwrap();
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();

        let err = collect_mounts(&ws, &[PathBuf::from("/")], &[], &base).unwrap_err();
        assert!(err.contains("filesystem root"));

        let err2 = collect_mounts(
            &ws,
            std::slice::from_ref(&a),
            std::slice::from_ref(&b),
            &base,
        )
        .unwrap_err();
        assert!(err2.contains("basename collision"));

        let ok = collect_mounts(&ws, std::slice::from_ref(&a), &[], &base).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].container_path, "/mnt/shared");
        assert_eq!(ok[0].mode, AccessMode::ReadOnly);

        let _ = fs::remove_dir_all(&base);
    }
}
