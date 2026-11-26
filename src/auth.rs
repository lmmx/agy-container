use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::cli::{AuthMode, Config};
use crate::host::{create_private_temp_dir, expand_tilde, TempDirGuard};

pub const API_KEY_SENTINEL: &str = "agy-container-proxy-managed";
pub const API_BROKER_PORT: u16 = 3129;

/// Prepared authentication & profile state for a single container run.
/// Automatically removes ephemeral isolated directories on `Drop`.
#[derive(Debug)]
pub struct AuthSession {
    pub gemini_dir: PathBuf,
    pub config_antigravity_dir: PathBuf,
    pub adc_gcloud_dir: Option<PathBuf>,
    pub api_broker_conf: String,
    pub workspace_env: Vec<(String, String)>,
    ephemeral_root: Option<PathBuf>,
}

impl AuthSession {
    pub fn prepare(
        cfg: &Config,
        data_dir: &Path,
        home: &Path,
        run_id: &str,
    ) -> Result<Self, String> {
        // Validate external auth inputs BEFORE creating any temporary directories so
        // missing credentials fail fast without leaking directories in /tmp.
        let mut workspace_env = Vec::new();
        let mut adc_gcloud_dir = None;
        let mut api_broker_conf =
            "# API key broker disabled for this run (--auth api-key not selected).\n".to_string();

        match cfg.auth_mode {
            AuthMode::Oauth => {}
            AuthMode::ApiKey => {
                let real_key = read_api_key(cfg, home)?;
                api_broker_conf = render_api_broker_conf(&real_key)?;
                workspace_env.push(("GEMINI_API_KEY".to_string(), API_KEY_SENTINEL.to_string()));
                workspace_env.push((
                    "GOOGLE_GEMINI_BASE_URL".to_string(),
                    format!("http://proxy:{API_BROKER_PORT}"),
                ));
            }
            AuthMode::Gcp => {
                if let Some(proj) = &cfg.gcp_project {
                    workspace_env.push(("GOOGLE_CLOUD_PROJECT".to_string(), proj.clone()));
                }
                workspace_env.push((
                    "GOOGLE_CLOUD_LOCATION".to_string(),
                    cfg.gcp_location.clone(),
                ));
            }
            AuthMode::Adc => {
                let gcloud_dir = std::env::var_os("CLOUDSDK_CONFIG")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join(".config/gcloud"));
                let adc_file = gcloud_dir.join("application_default_credentials.json");
                if !adc_file.is_file() {
                    return Err(format!(
                        "--auth adc requires Application Default Credentials at '{}'. Run `gcloud auth application-default login` first.",
                        adc_file.display()
                    ));
                }
                adc_gcloud_dir = Some(gcloud_dir);
                workspace_env.push(("AGY_ADC_AUTH".to_string(), "true".to_string()));
                if let Some(proj) = &cfg.gcp_project {
                    workspace_env.push(("GOOGLE_CLOUD_QUOTA_PROJECT".to_string(), proj.clone()));
                    workspace_env.push(("GOOGLE_CLOUD_PROJECT".to_string(), proj.clone()));
                }
                workspace_env.push((
                    "GOOGLE_CLOUD_LOCATION".to_string(),
                    cfg.gcp_location.clone(),
                ));
            }
        }

        let profile_root = data_dir.join("profiles").join(&cfg.profile);
        let profile_gemini = profile_root.join("gemini");
        let profile_cfg_agy = profile_root.join("config-antigravity");

        ensure_dir_mode(&profile_root, 0o700)?;
        ensure_dir_mode(&profile_gemini, 0o700)?;
        ensure_dir_mode(&profile_cfg_agy, 0o700)?;

        let mut guard: Option<TempDirGuard> = None;
        let (gemini_dir, config_antigravity_dir) = if cfg.isolated {
            let temp_root = create_private_temp_dir(&format!("agy-container-state-{run_id}"))?;
            let g = TempDirGuard::new(temp_root);
            let tmp_gemini = g.path().join("gemini");
            let tmp_cfg = g.path().join("config-antigravity");
            ensure_dir_mode(&tmp_gemini, 0o700)?;
            ensure_dir_mode(&tmp_cfg, 0o700)?;

            // In isolated OAuth/GCP mode, copy ONLY the OAuth token file (not SQLite DB,
            // conversations, or mutable settings) so concurrent runs never interfere.
            if matches!(cfg.auth_mode, AuthMode::Oauth | AuthMode::Gcp) {
                let src_tok = profile_gemini.join("antigravity-cli/antigravity-oauth-token");
                if src_tok.is_file() {
                    let dst_cli = tmp_gemini.join("antigravity-cli");
                    ensure_dir_mode(&dst_cli, 0o700)?;
                    let dst_tok = dst_cli.join("antigravity-oauth-token");
                    fs::copy(&src_tok, &dst_tok).map_err(|e| {
                        format!("failed to copy OAuth token into isolated state: {e}")
                    })?;
                    fs::set_permissions(&dst_tok, fs::Permissions::from_mode(0o600))
                        .map_err(|e| format!("failed to chmod isolated OAuth token: {e}"))?;
                }
            }
            guard = Some(g);
            (tmp_gemini, tmp_cfg)
        } else {
            (profile_gemini, profile_cfg_agy)
        };

        seed_gemini_defaults(&gemini_dir, cfg)?;

        Ok(Self {
            gemini_dir,
            config_antigravity_dir,
            adc_gcloud_dir,
            api_broker_conf,
            workspace_env,
            ephemeral_root: guard.map(TempDirGuard::disarm),
        })
    }

    /// True if the OAuth token file is currently present in the active profile.
    pub fn has_oauth_token(&self) -> bool {
        self.gemini_dir
            .join("antigravity-cli/antigravity-oauth-token")
            .is_file()
    }
}

impl Drop for AuthSession {
    fn drop(&mut self) {
        if let Some(root) = &self.ephemeral_root {
            let _ = fs::remove_dir_all(root);
        }
    }
}

fn ensure_dir_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|e| format!("failed to create directory '{}': {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("failed to chmod '{}': {e}", path.display()))?;
    Ok(())
}

/// Seed minimal, no-clobber Antigravity defaults inside the isolated container state dir.
/// Never overwrites an existing `settings.json` or `onboarding.json`.
fn seed_gemini_defaults(gemini_dir: &Path, cfg: &Config) -> Result<(), String> {
    let cli_dir = gemini_dir.join("antigravity-cli");
    let cache_dir = cli_dir.join("cache");
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("failed to create '{}': {e}", cache_dir.display()))?;

    let onboarding = cache_dir.join("onboarding.json");
    if !onboarding.exists() {
        let enterprise = cfg.auth_mode == AuthMode::Gcp;
        let body = format!(
            "{{\n  \"consumerOnboardingComplete\": {},\n  \"enterpriseOnboardingComplete\": {},\n  \"onboardingComplete\": true\n}}\n",
            !enterprise, enterprise
        );
        fs::write(&onboarding, body)
            .map_err(|e| format!("failed to write '{}': {e}", onboarding.display()))?;
    }

    let settings = cli_dir.join("settings.json");
    if !settings.exists() {
        let body = render_default_settings(cfg);
        fs::write(&settings, body)
            .map_err(|e| format!("failed to write '{}': {e}", settings.display()))?;
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to chmod '{}': {e}", settings.display()))?;
    }

    Ok(())
}

/// Render container-appropriate default `settings.json`.
/// Deliberately omits deprecated `unsandboxed(*)` and `enableTerminalSandbox`
/// (the outer rootless Podman container + internal network is the boundary).
pub fn render_default_settings(cfg: &Config) -> String {
    let mut lines = Vec::new();
    lines.push("{".to_string());
    if !cfg.strict_permissions {
        lines.push("  \"agentMode\": \"accept-edits\",".to_string());
        lines.push("  \"artifactReviewPolicy\": \"always-proceed\",".to_string());
        lines.push("  \"toolPermission\": \"always-proceed\",".to_string());
        lines.push("  \"allowNonWorkspaceAccess\": \"allow\",".to_string());
        lines.push("  \"permissions\": {".to_string());
        lines.push("    \"allow\": [".to_string());
        lines.push("      \"command(*)\",".to_string());
        lines.push("      \"execute_url(*)\",".to_string());
        lines.push("      \"mcp(*)\",".to_string());
        lines.push("      \"read_file(*)\",".to_string());
        lines.push("      \"read_url(*)\",".to_string());
        lines.push("      \"write_file(*)\"".to_string());
        lines.push("    ]".to_string());
        lines.push("  },".to_string());
    }
    if cfg.auth_mode == AuthMode::Gcp {
        if let Some(proj) = &cfg.gcp_project {
            lines.push("  \"gcp\": {".to_string());
            lines.push(format!("    \"project\": \"{}\",", json_escape(proj)));
            lines.push(format!(
                "    \"location\": \"{}\"",
                json_escape(&cfg.gcp_location)
            ));
            lines.push("  },".to_string());
        }
    }
    lines.push("  \"trustedWorkspaces\": [\"/workspace\"]".to_string());
    lines.push("}".to_string());
    lines.join("\n") + "\n"
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn read_api_key(cfg: &Config, home: &Path) -> Result<String, String> {
    let raw = if let Some(path) = &cfg.api_key_file {
        let expanded = expand_tilde(path, home);
        fs::read_to_string(&expanded).map_err(|e| {
            format!(
                "failed to read --api-key-file '{}': {e}",
                expanded.display()
            )
        })?
    } else {
        std::env::var("GEMINI_API_KEY").map_err(|_| {
            "--auth api-key requires GEMINI_API_KEY in the host environment or --api-key-file <PATH>"
                .to_string()
        })?
    };

    let key = raw.trim().to_string();
    validate_api_key(&key)?;
    Ok(key)
}

/// Strictly validate an API key before inserting it into Squid's `request_header_add`
/// directive so directive injection, header splitting, or Squid macro expansion (`%`)
/// are impossible.
pub fn validate_api_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("GEMINI_API_KEY is empty".to_string());
    }
    if key.len() > 512 {
        return Err("GEMINI_API_KEY is unexpectedly long (>512 chars)".to_string());
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '/' | '='))
    {
        return Err(
            "GEMINI_API_KEY contains disallowed characters (only ASCII alphanumerics and -_.+/= are accepted by the Squid broker)"
                .to_string(),
        );
    }
    Ok(())
}

/// Generate the per-run Squid reverse-proxy fragment for zero-MITM `GEMINI_API_KEY`
/// brokerage. Only mounted inside the proxy sidecar; never visible to the workspace.
pub fn render_api_broker_conf(real_key: &str) -> Result<String, String> {
    validate_api_key(real_key)?;
    Ok(format!(
        "\
# Zero-MITM GEMINI_API_KEY broker for agy-container.
# Workspace sends sentinel key to http://proxy:{port}; Squid replaces
# X-Goog-Api-Key and forwards exclusively to https://generativelanguage.googleapis.com.
http_port {port} accel defaultsite=generativelanguage.googleapis.com no-vhost
acl gemini_broker_port myportname {port}
acl gemini_broker_paths urlpath_regex ^/v1(beta)?/
acl gemini_broker_dotdot urlpath_regex -i (^|/|%2f)(\\.|%2e){{1,2}}(/|%2f|$|\\?)
http_access deny gemini_broker_port CONNECT
http_access deny gemini_broker_port gemini_broker_dotdot
http_access deny gemini_broker_port !gemini_broker_paths
http_access deny gemini_broker_port private_dst
http_access allow gemini_broker_port
cache_peer generativelanguage.googleapis.com parent 443 0 no-query originserver tls tls-cafile=/etc/ssl/certs/ca-certificates.crt forceddomain=generativelanguage.googleapis.com name=gemini_api
cache_peer_access gemini_api allow gemini_broker_port
cache_peer_access gemini_api deny all
never_direct allow gemini_broker_port
request_header_access X-Goog-Api-Key deny gemini_broker_port
request_header_add X-Goog-Api-Key \"{real_key}\" gemini_broker_port
",
        port = API_BROKER_PORT
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_validation_rejects_squid_injection() {
        assert!(validate_api_key("AIzaSyD-12345_testKey.value").is_ok());
        assert!(validate_api_key("").is_err());
        assert!(validate_api_key("key\" http_access allow all").is_err());
        assert!(validate_api_key("key\nhttp_access allow all").is_err());
        assert!(validate_api_key("key%macro").is_err());
    }

    #[test]
    fn broker_conf_binds_port_and_restricts_paths() {
        let conf = render_api_broker_conf("AIzaTestKey123").unwrap();
        assert!(conf.contains(&format!("http_port {API_BROKER_PORT} accel")));
        assert!(conf.contains("http_access deny gemini_broker_port CONNECT"));
        assert!(conf.contains("http_access deny gemini_broker_port !gemini_broker_paths"));
        assert!(conf.contains("request_header_access X-Goog-Api-Key deny gemini_broker_port"));
        assert!(conf
            .contains("request_header_add X-Goog-Api-Key \"AIzaTestKey123\" gemini_broker_port"));
    }

    #[test]
    fn default_settings_omits_deprecated_unsandboxed() {
        let cfg = Config::default();
        let s = render_default_settings(&cfg);
        assert!(!s.contains("unsandboxed"));
        assert!(s.contains("\"trustedWorkspaces\": [\"/workspace\"]"));
        assert!(s.contains("\"command(*)\""));
    }
}
