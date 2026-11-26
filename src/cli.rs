use std::path::PathBuf;

/// Named authentication strategy for Antigravity inside the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    /// Personal Google OAuth stored in an isolated container-only profile.
    Oauth,
    /// Zero-MITM GEMINI_API_KEY credential broker on Squid port 3129.
    ApiKey,
    /// Gemini Enterprise / Google Cloud OAuth with project & location metadata.
    Gcp,
    /// Application Default Credentials (~/.config/gcloud mounted read-only).
    Adc,
}

impl AuthMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "oauth" => Ok(Self::Oauth),
            "api-key" | "apikey" | "gemini-api-key" => Ok(Self::ApiKey),
            "gcp" | "enterprise" => Ok(Self::Gcp),
            "adc" => Ok(Self::Adc),
            other => Err(format!(
                "invalid --auth value '{other}': expected one of oauth, api-key, gcp, adc"
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::ApiKey => "api-key",
            Self::Gcp => "gcp",
            Self::Adc => "adc",
        }
    }
}

/// Wrapper-level action selected by CLI arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Run,
    Login,
    Doctor,
    UpdateImage,
    Precondition,
    Help,
    Version,
}

/// GitHub SSH gateway access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitHubMode {
    ReadOnly,
    Push,
}

/// Parsed command-line configuration for `agy-container`.
#[derive(Debug, Clone)]
pub struct Config {
    pub action: Action,
    pub workspace: Option<PathBuf>,
    pub ro_workspace: bool,
    pub ro_mounts: Vec<PathBuf>,
    pub rw_mounts: Vec<PathBuf>,

    // Network & egress
    pub allow_groups: Vec<String>,
    pub allow_hosts: Vec<String>,
    pub unrestricted_network: bool,
    pub no_gateway: bool,

    // Auth & state
    pub auth_mode: AuthMode,
    pub api_key_file: Option<PathBuf>,
    pub gcp_project: Option<String>,
    pub gcp_location: String,
    pub profile: String,
    pub isolated: bool,

    // Permissions & execution
    pub strict_permissions: bool,
    pub shell: bool,

    // Git & GitHub gateway
    pub git: bool,
    pub github: Option<GitHubMode>,
    pub git_key: Option<PathBuf>,
    pub git_repos: Vec<String>,

    // Resources
    pub memory: String,
    pub cpus: Option<String>,
    pub pids_limit: u32,

    // Image lifecycle
    pub build: bool,
    pub update: bool,

    // Diagnostics & probing
    pub probe: bool,
    pub self_test: bool,
    pub probe_timeout: u64,

    // Forwarded to `agy`
    pub agy_subcommand: Option<String>,
    pub agy_args: Vec<String>,
    pub passthrough: Vec<String>,

    // Derived runtime properties
    pub headless: bool,
    pub stream_stdin: bool,
    pub user_set_mode: bool,
    pub user_set_skip_perms: bool,
    pub user_set_sandbox: bool,
    pub user_set_remote_agent: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            action: Action::Run,
            workspace: None,
            ro_workspace: false,
            ro_mounts: Vec::new(),
            rw_mounts: Vec::new(),
            allow_groups: Vec::new(),
            allow_hosts: Vec::new(),
            unrestricted_network: false,
            no_gateway: false,
            auth_mode: AuthMode::Oauth,
            api_key_file: None,
            gcp_project: None,
            gcp_location: "global".to_string(),
            profile: "default".to_string(),
            isolated: false,
            strict_permissions: false,
            shell: false,
            git: false,
            github: None,
            git_key: None,
            git_repos: Vec::new(),
            memory: std::env::var("AGY_CONTAINER_MEM").unwrap_or_else(|_| "8g".to_string()),
            cpus: std::env::var("AGY_CONTAINER_CPUS").ok(),
            pids_limit: std::env::var("AGY_CONTAINER_PIDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4096),
            build: false,
            update: false,
            probe: false,
            self_test: false,
            probe_timeout: 60,
            agy_subcommand: None,
            agy_args: Vec::new(),
            passthrough: Vec::new(),
            headless: false,
            stream_stdin: false,
            user_set_mode: false,
            user_set_skip_perms: false,
            user_set_sandbox: false,
            user_set_remote_agent: false,
        }
    }
}

/// Native `agy` subcommands recognized directly when passed as the first positional.
const AGY_SUBCOMMANDS: &[&str] = &[
    "acp",
    "agent",
    "agents",
    "changelog",
    "mcp",
    "models",
    "plugin",
    "plugins",
    "remote-control",
];

/// Native `agy` flags that consume one value argument.
const AGY_VALUE_FLAGS: &[&str] = &[
    "-p",
    "--print",
    "--prompt",
    "-i",
    "--prompt-interactive",
    "--model",
    "--effort",
    "--mode",
    "-r",
    "--resume",
    "--conversation",
    "--output-format",
    "--input-format",
    "--json-schema",
    "--print-timeout",
    "--agent",
    "--project",
    "--settings",
    "--log-file",
    "--add-dir",
];

/// Native `agy` boolean flags.
const AGY_BOOL_FLAGS: &[&str] = &[
    "-c",
    "--continue",
    "--dangerously-skip-permissions",
    "--disable-slash-commands",
    "--new-project",
    "--remote-agent",
    "--remote-control",
    "--sandbox",
];

pub fn parse_args<I, S>(iter: I) -> Result<Config, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let raw: Vec<String> = iter.into_iter().map(Into::into).collect();
    let mut cfg = Config::default();
    let mut idx = 0usize;
    let mut auth_explicitly_set = false;

    while idx < raw.len() {
        let arg = &raw[idx];

        // Once a native `agy` subcommand has been captured (e.g., `agy-container mcp add ... -- npx foo`),
        // forward all remaining arguments (including `--`) untouched to `agy`.
        if cfg.agy_subcommand.is_some() {
            cfg.agy_args.push(arg.clone());
            idx += 1;
            continue;
        }

        // Explicit passthrough separator: everything after `--` goes straight to `agy`.
        if arg == "--" {
            cfg.passthrough.extend(raw[idx + 1..].iter().cloned());
            break;
        }

        // Split `--flag=value` forms for uniform handling.
        let (flag, eq_val) = if arg.starts_with("--") {
            match arg.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (arg.as_str(), None),
            }
        } else {
            (arg.as_str(), None)
        };

        // Helper closure for reading the next required value.
        let take_value =
            |idx: &mut usize, eq: Option<&str>, name: &str| -> Result<String, String> {
                if let Some(v) = eq {
                    return Ok(v.to_string());
                }
                *idx += 1;
                raw.get(*idx)
                    .cloned()
                    .ok_or_else(|| format!("missing value for {name}"))
            };

        match flag {
            "-h" | "--help" => {
                cfg.action = Action::Help;
                return Ok(cfg);
            }
            "-V" | "--version" => {
                cfg.action = Action::Version;
                return Ok(cfg);
            }
            "-w" | "--workspace" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.workspace = Some(PathBuf::from(v));
            }
            "--ro-workspace" => {
                reject_eq(flag, eq_val)?;
                cfg.ro_workspace = true;
            }
            "--ro" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.ro_mounts.push(PathBuf::from(v));
            }
            "--rw" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.rw_mounts.push(PathBuf::from(v));
            }
            "--allow" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                for part in v.split(',') {
                    let trimmed = part.trim();
                    if !trimmed.is_empty() {
                        cfg.allow_groups.push(trimmed.to_string());
                    }
                }
            }
            "--allow-host" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.allow_hosts.push(v);
            }
            "-n" | "--unrestricted-network" => {
                reject_eq(flag, eq_val)?;
                cfg.unrestricted_network = true;
            }
            "--no-gateway" => {
                reject_eq(flag, eq_val)?;
                cfg.no_gateway = true;
            }
            "--auth" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.auth_mode = AuthMode::parse(&v)?;
                auth_explicitly_set = true;
            }
            "--api-key-file" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.api_key_file = Some(PathBuf::from(v));
                if !auth_explicitly_set {
                    cfg.auth_mode = AuthMode::ApiKey;
                }
            }
            "--gcp-project" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.gcp_project = Some(v);
            }
            "--gcp-location" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.gcp_location = v;
            }
            "--profile" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                validate_profile_name(&v)?;
                cfg.profile = v;
            }
            "--isolated" => {
                reject_eq(flag, eq_val)?;
                cfg.isolated = true;
            }
            "--strict-permissions" => {
                reject_eq(flag, eq_val)?;
                cfg.strict_permissions = true;
            }
            "--shell" => {
                reject_eq(flag, eq_val)?;
                cfg.shell = true;
            }
            "--git" => {
                reject_eq(flag, eq_val)?;
                cfg.git = true;
            }
            "--github" => {
                let mode = match eq_val {
                    None => GitHubMode::ReadOnly,
                    Some("push") => GitHubMode::Push,
                    Some("read") | Some("ro") => GitHubMode::ReadOnly,
                    Some(other) => {
                        return Err(format!(
                            "invalid --github value '{other}': expected --github or --github=push"
                        ))
                    }
                };
                cfg.github = Some(mode);
            }
            "--git-key" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.git_key = Some(PathBuf::from(v));
            }
            "--git-repo" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.git_repos.push(v);
            }
            "--memory" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.memory = v;
            }
            "--cpus" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.cpus = Some(v);
            }
            "--pids-limit" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.pids_limit = v.parse::<u32>().map_err(|_| {
                    format!("invalid --pids-limit '{v}': expected positive integer")
                })?;
                if cfg.pids_limit == 0 {
                    return Err("--pids-limit must be greater than 0".to_string());
                }
            }
            "-b" | "--build" => {
                reject_eq(flag, eq_val)?;
                cfg.build = true;
            }
            "--update" => {
                reject_eq(flag, eq_val)?;
                cfg.update = true;
                cfg.build = true;
            }
            "--precondition" => {
                reject_eq(flag, eq_val)?;
                cfg.action = Action::Precondition;
            }
            "--probe" => {
                reject_eq(flag, eq_val)?;
                cfg.probe = true;
            }
            "--self-test" => {
                reject_eq(flag, eq_val)?;
                cfg.self_test = true;
            }
            "--probe-timeout" => {
                let v = take_value(&mut idx, eq_val, flag)?;
                cfg.probe_timeout = v
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --probe-timeout '{v}': expected seconds"))?;
            }
            // Native `agy` flags forwarded directly
            _ if AGY_VALUE_FLAGS.contains(&flag) => {
                let v = take_value(&mut idx, eq_val, flag)?;
                match flag {
                    "-p" | "--print" | "--prompt" => cfg.headless = true,
                    "--output-format" => {
                        if v == "json" || v == "stream-json" {
                            cfg.headless = true;
                        }
                    }
                    "--input-format" => {
                        if v == "stream-json" {
                            cfg.headless = true;
                            cfg.stream_stdin = true;
                        }
                    }
                    "--mode" => cfg.user_set_mode = true,
                    _ => {}
                }
                cfg.agy_args.push(flag.to_string());
                cfg.agy_args.push(v);
            }
            _ if AGY_BOOL_FLAGS.contains(&flag) => {
                reject_eq(flag, eq_val)?;
                match flag {
                    "--dangerously-skip-permissions" => cfg.user_set_skip_perms = true,
                    "--sandbox" => cfg.user_set_sandbox = true,
                    "--remote-agent" => cfg.user_set_remote_agent = true,
                    _ => {}
                }
                cfg.agy_args.push(flag.to_string());
            }
            // Wrapper subcommands or native `agy` subcommands
            _ if !arg.starts_with('-') => {
                if cfg.action == Action::Run && cfg.agy_args.is_empty() {
                    match arg.as_str() {
                        "login" => {
                            cfg.action = Action::Login;
                            idx += 1;
                            continue;
                        }
                        "doctor" => {
                            cfg.action = Action::Doctor;
                            idx += 1;
                            continue;
                        }
                        "update-image" => {
                            cfg.action = Action::UpdateImage;
                            cfg.update = true;
                            cfg.build = true;
                            idx += 1;
                            continue;
                        }
                        sub if AGY_SUBCOMMANDS.contains(&sub) => {
                            cfg.agy_subcommand = Some(sub.to_string());
                            match sub {
                                "acp" => {
                                    cfg.headless = true;
                                    cfg.stream_stdin = true;
                                }
                                "models" | "agent" | "agents" | "changelog" => {
                                    cfg.headless = true;
                                }
                                _ => {}
                            }
                            idx += 1;
                            continue;
                        }
                        _ => {}
                    }
                }
                return Err(format!(
                    "unexpected positional argument '{arg}'. Use --workspace <dir> to set the workspace, -p \"<prompt>\" for headless prompts, or '-- {arg}' to forward to agy"
                ));
            }
            other => {
                return Err(format!(
                    "unrecognized option '{other}'. Run 'agy-container --help' or pass '-- {other}' to forward directly to agy"
                ));
            }
        }

        idx += 1;
    }

    validate_config(&mut cfg)?;
    Ok(cfg)
}

fn reject_eq(flag: &str, eq_val: Option<&str>) -> Result<(), String> {
    if let Some(v) = eq_val {
        return Err(format!("flag {flag} does not accept a value (got '{v}')"));
    }
    Ok(())
}

pub fn validate_profile_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "invalid --profile '{name}': use only ASCII letters, digits, '.', '_', or '-'"
        ));
    }
    Ok(())
}

fn validate_config(cfg: &mut Config) -> Result<(), String> {
    if cfg.self_test && !cfg.probe {
        return Err("--self-test requires --probe".to_string());
    }
    if cfg.probe && cfg.no_gateway {
        return Err("--probe cannot be combined with --no-gateway".to_string());
    }
    if cfg.probe && (!cfg.allow_groups.is_empty() || !cfg.allow_hosts.is_empty()) {
        return Err("--probe cannot be combined with --allow or --allow-host".to_string());
    }
    if cfg.github.is_some() && cfg.no_gateway {
        return Err("--github cannot be combined with --no-gateway".to_string());
    }
    if cfg.git_key.is_some() && cfg.github.is_none() {
        return Err("--git-key requires --github".to_string());
    }
    if !cfg.git_repos.is_empty() && cfg.github.is_none() {
        return Err("--git-repo requires --github".to_string());
    }
    if cfg.auth_mode == AuthMode::ApiKey && cfg.no_gateway {
        return Err(
            "--auth api-key requires the Squid broker gateway and cannot be combined with --no-gateway"
                .to_string(),
        );
    }
    if cfg.auth_mode == AuthMode::Gcp && cfg.gcp_project.is_none() {
        return Err("--auth gcp requires --gcp-project <PROJECT_ID>".to_string());
    }
    if cfg.probe {
        cfg.headless = true;
    }
    if cfg.action == Action::Login {
        cfg.headless = false;
    }
    Ok(())
}

impl Config {
    /// Assemble the argument vector passed to `/usr/local/bin/agy` inside the container.
    ///
    /// Order:
    /// 1. Native subcommand (if any, e.g. `models`, `mcp`, `acp`)
    /// 2. Container-managed permission & auth flags (unless `--strict-permissions` or subcommand)
    /// 3. `--add-dir /mnt/<name>` for extra host mounts (for top-level sessions and `acp`)
    /// 4. User-provided native `agy` flags
    /// 5. Explicit `--` passthrough arguments
    pub fn build_agy_command(&self, extra_mount_targets: &[String]) -> Vec<String> {
        let mut out = Vec::new();

        if let Some(sub) = &self.agy_subcommand {
            out.push(sub.clone());
            if sub == "acp" {
                if !self.strict_permissions && !self.user_set_skip_perms {
                    out.push("--dangerously-skip-permissions".to_string());
                }
                if self.auth_mode == AuthMode::ApiKey {
                    out.push("--settings".to_string());
                    out.push(r#"{"modelProvider":"gemini"}"#.to_string());
                }
                for dir in extra_mount_targets {
                    out.push("--add-dir".to_string());
                    out.push(dir.clone());
                }
            }
            out.extend(self.agy_args.iter().cloned());
            out.extend(self.passthrough.iter().cloned());
            return out;
        }

        // Top-level interactive or headless `agy` invocation:
        // The rootless Podman container + internal network + Squid gateway form the
        // outer security boundary; unless --strict-permissions was requested, enable
        // non-blocking execution suitable for autonomous runs and /swarm workers.
        if !self.strict_permissions {
            if !self.user_set_skip_perms {
                out.push("--dangerously-skip-permissions".to_string());
            }
            if !self.user_set_mode {
                out.push("--mode".to_string());
                out.push("accept-edits".to_string());
            }
        }

        // Ephemeral session-only settings for brokered GEMINI_API_KEY mode so the
        // persistent profile settings.json is not mutated.
        if self.auth_mode == AuthMode::ApiKey {
            out.push("--settings".to_string());
            out.push(r#"{"modelProvider":"gemini"}"#.to_string());
        }

        for dir in extra_mount_targets {
            out.push("--add-dir".to_string());
            out.push(dir.clone());
        }

        out.extend(self.agy_args.iter().cloned());
        out.extend(self.passthrough.iter().cloned());
        out
    }
}

pub fn help_text() -> &'static str {
    concat!(
        "agy-container ",
        env!("CARGO_PKG_VERSION"),
        " — rootless Podman containment for Google Antigravity CLI (agy)\n\n",
        "USAGE:\n",
        "  agy-container [CONTAINER OPTIONS] [AGY OPTIONS] [-- <AGY ARGS...>]\n",
        "  agy-container <login | doctor | update-image>\n",
        "  agy-container <models | agents | mcp | plugin | acp | changelog> [ARGS...]\n\n",
        "EXAMPLES:\n",
        "  agy-container                                    Interactive session in current directory\n",
        "  agy-container --model gemini-4-neon-xhigh        Select Gemini 4 Neon (Extra High)\n",
        "  agy-container --model \"Orchestrator (Neon)\"      Use Neon planner + Hydrogen executor\n",
        "  agy-container -p \"Implement feature X\"           Headless single-turn execution\n",
        "  agy-container -c                                 Continue last conversation\n",
        "  agy-container --auth api-key -p \"Audit tests\"    Zero-MITM brokered GEMINI_API_KEY\n",
        "  agy-container --ro ../docs --allow crates        Mount reference dir + allow crates.io\n",
        "  agy-container login                              Complete headless OAuth sign-in\n",
        "  agy-container doctor                             Verify Podman isolation & host setup\n\n",
        "CONTAINER OPTIONS:\n",
        "  -w, --workspace <DIR>       Workspace directory (default: current directory)\n",
        "      --ro-workspace          Mount workspace read-only\n",
        "      --ro <DIR>              Mount extra reference directory read-only at /mnt/<name>\n",
        "      --rw <DIR>              Mount extra directory read-write at /mnt/<name>\n",
        "      --allow <GROUP>         Allow egress host group (repeatable or comma-separated):\n",
        "                              google-auth, gcp-enterprise, github, npm, pypi, crates,\n",
        "                              go, telemetry, updater, remote-control\n",
        "      --allow-host <DOMAIN>   Allow an additional HTTPS domain for this run\n",
        "  -n, --unrestricted-network  Allow public internet via Squid (logged, blocks private IPs)\n",
        "      --no-gateway            Bypass internal network & Squid entirely (unobserved)\n",
        "      --auth <MODE>           Auth mode: oauth (default), api-key, gcp, adc\n",
        "      --api-key-file <PATH>   Read GEMINI_API_KEY from file (implies --auth api-key)\n",
        "      --gcp-project <ID>      GCP project ID (required for --auth gcp)\n",
        "      --gcp-location <LOC>    GCP location (default: global)\n",
        "      --profile <NAME>        Isolated container state profile (default: default)\n",
        "      --isolated              Ephemeral per-run state dir (zero cross-session sharing)\n",
        "      --strict-permissions    Do not auto-pass --dangerously-skip-permissions\n",
        "      --git                   Mount host ~/.gitconfig read-only (warns on credentials)\n",
        "      --github[=push]         Start SSH git-gateway sidecar (read-only by default)\n",
        "      --git-key <PATH>        Host SSH key for git-gateway (default: ~/.ssh/id_ed25519)\n",
        "      --git-repo <OWNER/REPO> Restrict git-gateway to named repo (repeatable)\n",
        "      --memory <SIZE>         Memory limit (default: 8g, 'none' to disable)\n",
        "      --cpus <N>              CPU quota (optional, e.g. 4)\n",
        "      --pids-limit <N>        Process limit (default: 4096; ulimit fallback if undelegated)\n",
        "  -b, --build                 Build/rebuild container images before running\n",
        "      --update                Rebuild images with --no-cache to update agy\n",
        "      --precondition          Verify rootless Podman --internal network isolation\n",
        "      --probe                 Observe egress with permissive Squid & print summary\n",
        "      --self-test             Run built-in boundary test under --probe\n",
        "      --probe-timeout <SECS>  Timeout for --probe (default: 60)\n",
        "      --shell                 Start /bin/bash in the hardened container instead of agy\n",
        "  -h, --help                  Show this help (-- --help reaches agy --help)\n",
        "  -V, --version               Show version\n\n",
        "FORWARDED AGY OPTIONS:\n",
        "  --model, --effort, --mode, -p/--print/--prompt, -i/--prompt-interactive,\n",
        "  -c/--continue, -r/--resume/--conversation, --output-format, --input-format,\n",
        "  --json-schema, --print-timeout, --disable-slash-commands, --agent, --project,\n",
        "  --new-project, --settings, --log-file, --remote-agent, --remote-control,\n",
        "  --sandbox, --dangerously-skip-permissions, --add-dir\n"
    )
}
