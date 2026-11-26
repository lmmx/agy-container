use std::collections::BTreeSet;

/// Named egress host groups opted into via `--allow <group>`.
pub struct HostGroup {
    pub name: &'static str,
    pub description: &'static str,
    pub domains: &'static [&'static str],
}

pub const GROUPS: &[HostGroup] = &[
    HostGroup {
        name: "google-auth",
        description: "Interactive Google OAuth sign-in domains (auto-enabled by `login`)",
        domains: &[
            "accounts.google.com",
            "lh3.googleusercontent.com",
            "play.googleapis.com",
            "antigravity.google",
        ],
    },
    HostGroup {
        name: "gcp-enterprise",
        description:
            "Gemini Enterprise & Vertex AI regional endpoints (auto-enabled by --auth gcp/adc)",
        domains: &[
            "businessaicode.googleapis.com",
            "businessaicode.us.rep.googleapis.com",
            "businessaicode.eu.rep.googleapis.com",
            "aiplatform.googleapis.com",
            "aiplatform.us.rep.googleapis.com",
            "aiplatform.eu.rep.googleapis.com",
            "discoveryengine.googleapis.com",
        ],
    },
    HostGroup {
        name: "github",
        description: "GitHub HTTPS & API endpoints (auto-enabled by --github)",
        domains: &[
            "github.com",
            "api.github.com",
            "uploads.github.com",
            "objects.githubusercontent.com",
            "raw.githubusercontent.com",
        ],
    },
    HostGroup {
        name: "npm",
        description: "npm package registry",
        domains: &["registry.npmjs.org"],
    },
    HostGroup {
        name: "pypi",
        description: "Python Package Index",
        domains: &["pypi.org", "files.pythonhosted.org"],
    },
    HostGroup {
        name: "crates",
        description: "Rust crates.io registry",
        domains: &["crates.io", "static.crates.io", "index.crates.io"],
    },
    HostGroup {
        name: "go",
        description: "Go module proxy and checksum database",
        domains: &["proxy.golang.org", "sum.golang.org"],
    },
    HostGroup {
        name: "telemetry",
        description: "Google Antigravity telemetry & feedback endpoints",
        domains: &[
            "firebaselogging-pa.googleapis.com",
            "feedback-pa.googleapis.com",
            "play.googleapis.com",
        ],
    },
    HostGroup {
        name: "updater",
        description: "Antigravity CLI release manifest and download bucket",
        domains: &[
            "antigravity-cli-auto-updater-974169037036.us-central1.run.app",
            "storage.googleapis.com",
            "antigravity.google",
        ],
    },
    HostGroup {
        name: "remote-control",
        description: "Antigravity browser Remote Control relay",
        domains: &[".antigravity.google.com", "antigravity.google"],
    },
];

pub fn find_group(name: &str) -> Option<&'static HostGroup> {
    GROUPS.iter().find(|g| g.name == name)
}

pub fn known_group_names() -> Vec<&'static str> {
    GROUPS.iter().map(|g| g.name).collect()
}

/// Strictly validate an `--allow-host` domain to prevent Squid directive injection,
/// wildcard abuse, IP literal bypasses, or control characters.
pub fn validate_host(raw: &str) -> Result<String, String> {
    let host = raw.trim().to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(format!("invalid --allow-host '{raw}': empty or too long"));
    }
    if host.contains("://") || host.contains('/') || host.contains(':') || host.contains('*') {
        return Err(format!(
            "invalid --allow-host '{raw}': specify a bare hostname (e.g. docs.rs or .example.com), without scheme, port, path, or '*'"
        ));
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "invalid --allow-host '{raw}': whitespace or control characters are forbidden"
        ));
    }

    let check = host.strip_prefix('.').unwrap_or(&host);
    if check.is_empty() || check.starts_with('.') || check.ends_with('.') || check.contains("..") {
        return Err(format!("invalid --allow-host '{raw}': malformed domain"));
    }
    let labels: Vec<&str> = check.split('.').collect();
    if labels.len() < 2 {
        return Err(format!(
            "invalid --allow-host '{raw}': must contain at least one dot (FQDN required)"
        ));
    }
    // Reject bare IPv4 / hex / octal IP literals (ICANN TLDs cannot be all-numeric or hex-prefixed).
    if let Some(tld) = labels.last() {
        if tld.chars().all(|c| c.is_ascii_digit()) || tld.starts_with("0x") {
            return Err(format!(
                "invalid --allow-host '{raw}': numeric or hex-literal hosts are not permitted"
            ));
        }
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(format!(
                "invalid --allow-host '{raw}': invalid DNS label '{label}'"
            ));
        }
    }
    Ok(host)
}

/// Remove entries covered by a broader leading-dot suffix in the same Squid
/// `dstdomain` ACL (Squid rejects overlapping domain/subdomain entries as fatal).
fn prune_squid_overlaps(domains: BTreeSet<String>) -> Vec<String> {
    let wildcards: Vec<String> = domains
        .iter()
        .filter(|d| d.starts_with('.'))
        .cloned()
        .collect();

    domains
        .into_iter()
        .filter(|entry| {
            let bare = entry.strip_prefix('.').unwrap_or(entry);
            !wildcards.iter().any(|wc| {
                if wc == entry {
                    return false;
                }
                let wc_bare = &wc[1..];
                bare == wc_bare || bare.ends_with(wc.as_str())
            })
        })
        .collect()
}

/// Render `/etc/squid/conf.d/allow.conf` for the selected groups and explicit hosts.
/// Always produces a syntactically valid Squid include file (comment-only when empty).
pub fn compile_allow_fragment(groups: &[String], hosts: &[String]) -> Result<String, String> {
    let mut domains = BTreeSet::new();

    for name in groups {
        let group = find_group(name).ok_or_else(|| {
            format!(
                "unknown --allow group '{name}'. Valid groups: {}",
                known_group_names().join(", ")
            )
        })?;
        for d in group.domains {
            domains.insert((*d).to_string());
        }
    }

    for h in hosts {
        let validated = validate_host(h)?;
        domains.insert(validated);
    }

    let pruned = prune_squid_overlaps(domains);
    if pruned.is_empty() {
        return Ok("# No extra egress host groups or domains enabled for this run.\n".to_string());
    }

    let mut out = String::from("# Generated per-run egress allowlist for agy-container.\n");
    for d in &pruned {
        out.push_str(&format!("acl agy_run_allow dstdomain {d}\n"));
    }
    out.push_str("http_access allow CONNECT agy_run_allow\n");
    Ok(out)
}

/// Check that a user-edited `squid.conf` contains active (uncommented) includes
/// for both `allow.conf` and `api-broker.conf`, with `allow.conf` preceding `deny all`.
pub fn check_squid_conf_includes(conf: &str) -> Result<(), String> {
    let mut allow_line: Option<usize> = None;
    let mut broker_line: Option<usize> = None;
    let mut deny_all_line: Option<usize> = None;

    for (idx, raw) in conf.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let collapsed: Vec<&str> = trimmed.split_whitespace().collect();
        if collapsed == ["include", "/etc/squid/conf.d/allow.conf"] {
            allow_line = Some(idx);
        } else if collapsed == ["include", "/etc/squid/conf.d/api-broker.conf"] {
            broker_line = Some(idx);
        } else if collapsed == ["http_access", "deny", "all"] {
            deny_all_line = Some(idx);
        }
    }

    let allow_idx = allow_line.ok_or_else(|| {
        "custom squid.conf is missing an active 'include /etc/squid/conf.d/allow.conf' before 'http_access deny all'".to_string()
    })?;
    if broker_line.is_none() {
        return Err(
            "custom squid.conf is missing an active 'include /etc/squid/conf.d/api-broker.conf'"
                .to_string(),
        );
    }
    if let Some(deny_idx) = deny_all_line {
        if allow_idx > deny_idx {
            return Err(
                "custom squid.conf places 'include /etc/squid/conf.d/allow.conf' after 'http_access deny all'".to_string()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_groups_compile_cleanly() {
        let all: Vec<String> = known_group_names().into_iter().map(String::from).collect();
        let frag = compile_allow_fragment(&all, &["docs.rs".to_string()]).unwrap();
        assert!(frag.contains("acl agy_run_allow dstdomain docs.rs"));
        assert!(frag.contains("acl agy_run_allow dstdomain accounts.google.com"));
        assert!(frag.contains("http_access allow CONNECT agy_run_allow"));
    }

    #[test]
    fn empty_fragment_is_comment_only() {
        let frag = compile_allow_fragment(&[], &[]).unwrap();
        assert!(frag.starts_with('#'));
        assert!(!frag.contains("http_access"));
    }

    #[test]
    fn host_validation_blocks_injection_and_ips() {
        assert!(validate_host("docs.rs").is_ok());
        assert!(validate_host(".example.org").is_ok());
        assert!(validate_host("127.0.0.1").is_err());
        assert!(validate_host("169.254.169.254").is_err());
        assert!(validate_host("evil.com\nhttp_access allow all").is_err());
        assert!(validate_host("https://docs.rs").is_err());
        assert!(validate_host("*.example.com").is_err());
        assert!(validate_host("localhost").is_err());
    }
}
