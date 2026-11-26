use agy_container::allow;
use agy_container::auth;
use agy_container::cli::{parse_args, Action, AuthMode, GitHubMode};
use agy_container::gitgateway;

#[test]
fn defaults_to_interactive_run_in_cwd() {
    let cfg = parse_args(Vec::<String>::new()).unwrap();
    assert_eq!(cfg.action, Action::Run);
    assert_eq!(cfg.workspace, None);
    assert!(!cfg.headless);
    assert_eq!(cfg.auth_mode, AuthMode::Oauth);
    assert_eq!(cfg.profile, "default");
    assert_eq!(cfg.pids_limit, 4096);

    let cmd = cfg.build_agy_command(&[]);
    assert_eq!(
        cmd,
        vec!["--dangerously-skip-permissions", "--mode", "accept-edits"]
    );
}

#[test]
fn forwards_neon_model_and_effort_naturally() {
    let cfg = parse_args(["--model", "gemini-4-neon-xhigh", "--effort", "xhigh"]).unwrap();
    let cmd = cfg.build_agy_command(&[]);
    assert!(cmd.contains(&"--model".to_string()));
    assert!(cmd.contains(&"gemini-4-neon-xhigh".to_string()));
    assert!(cmd.contains(&"--effort".to_string()));
    assert!(cmd.contains(&"xhigh".to_string()));
    assert!(!cfg.headless);
}

#[test]
fn forwards_orchestrator_and_headless_print() {
    let cfg = parse_args([
        "--model",
        "Orchestrator (Neon)",
        "-p",
        "Implement this feature",
        "--output-format",
        "json",
    ])
    .unwrap();
    assert!(cfg.headless);
    assert!(!cfg.stream_stdin);
    let cmd = cfg.build_agy_command(&[]);
    assert!(cmd.contains(&"-p".to_string()));
    assert!(cmd.contains(&"Implement this feature".to_string()));
    assert!(cmd.contains(&"--output-format".to_string()));
    assert!(cmd.contains(&"json".to_string()));
}

#[test]
fn streaming_ndjson_keeps_stdin_open_without_tty() {
    let cfg = parse_args([
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
    ])
    .unwrap();
    assert!(cfg.headless);
    assert!(cfg.stream_stdin);
}

#[test]
fn strict_permissions_omits_yolo_flags() {
    let cfg = parse_args(["--strict-permissions", "--model", "gemini-4-neon"]).unwrap();
    let cmd = cfg.build_agy_command(&[]);
    assert!(!cmd.contains(&"--dangerously-skip-permissions".to_string()));
    assert!(!cmd.contains(&"--mode".to_string()));
    assert_eq!(cmd, vec!["--model", "gemini-4-neon"]);
}

#[test]
fn api_key_mode_injects_ephemeral_settings_and_conflicts_with_no_gateway() {
    let cfg = parse_args(["--auth", "api-key", "-p", "hi"]).unwrap();
    assert_eq!(cfg.auth_mode, AuthMode::ApiKey);
    let cmd = cfg.build_agy_command(&[]);
    assert!(cmd.contains(&"--settings".to_string()));
    assert!(cmd.contains(&r#"{"modelProvider":"gemini"}"#.to_string()));

    let err = parse_args(["--auth", "api-key", "--no-gateway"]).unwrap_err();
    assert!(err.contains("Squid broker"));
}

#[test]
fn gcp_auth_requires_project() {
    let err = parse_args(["--auth", "gcp"]).unwrap_err();
    assert!(err.contains("--gcp-project"));

    let ok = parse_args([
        "--auth",
        "gcp",
        "--gcp-project",
        "my-proj",
        "--gcp-location",
        "us",
    ])
    .unwrap();
    assert_eq!(ok.auth_mode, AuthMode::Gcp);
    assert_eq!(ok.gcp_project.as_deref(), Some("my-proj"));
    assert_eq!(ok.gcp_location, "us");
}

#[test]
fn native_agy_subcommands_forward_trailing_args_verbatim() {
    let cfg = parse_args([
        "mcp", "add", "--type", "stdio", "my-tool", "--", "npx", "foo",
    ])
    .unwrap();
    assert_eq!(cfg.agy_subcommand.as_deref(), Some("mcp"));
    let cmd = cfg.build_agy_command(&[]);
    assert_eq!(
        cmd,
        vec!["mcp", "add", "--type", "stdio", "my-tool", "--", "npx", "foo"]
    );

    let cfg2 = parse_args(["models"]).unwrap();
    assert_eq!(cfg2.agy_subcommand.as_deref(), Some("models"));
    assert!(cfg2.headless);
    assert_eq!(cfg2.build_agy_command(&[]), vec!["models"]);

    let cfg3 = parse_args(["acp"]).unwrap();
    assert_eq!(cfg3.agy_subcommand.as_deref(), Some("acp"));
    assert!(cfg3.headless && cfg3.stream_stdin);
    let acp_cmd = cfg3.build_agy_command(&["/mnt/docs".to_string()]);
    assert_eq!(
        acp_cmd,
        vec![
            "acp",
            "--dangerously-skip-permissions",
            "--add-dir",
            "/mnt/docs"
        ]
    );
}

#[test]
fn double_dash_passthrough_bypasses_runner_parsing() {
    let cfg = parse_args(["--", "--ro", "/etc", "--future-agy-flag"]).unwrap();
    assert!(cfg.ro_mounts.is_empty());
    assert_eq!(cfg.passthrough, vec!["--ro", "/etc", "--future-agy-flag"]);
}

#[test]
fn rejects_conflicting_flags_and_unknown_options() {
    assert!(parse_args(["--self-test"]).is_err());
    assert!(parse_args(["--probe", "--no-gateway"]).is_err());
    assert!(parse_args(["--probe", "--allow", "npm"]).is_err());
    assert!(parse_args(["--github", "--no-gateway"]).is_err());
    assert!(parse_args(["--git-key", "/tmp/k"]).is_err());
    assert!(parse_args(["--git-repo", "a/b"]).is_err());
    assert!(parse_args(["--totally-unknown-flag"]).is_err());
    assert!(parse_args(["--profile", "../escape"]).is_err());
}

#[test]
fn github_push_and_read_only_parsing() {
    let ro = parse_args(["--github"]).unwrap();
    assert_eq!(ro.github, Some(GitHubMode::ReadOnly));

    let push = parse_args(["--github=push", "--git-repo", "lmmx/agy-container"]).unwrap();
    assert_eq!(push.github, Some(GitHubMode::Push));
    assert_eq!(push.git_repos, vec!["lmmx/agy-container"]);
}

#[test]
fn every_help_advertised_allow_group_exists() {
    let help = agy_container::cli::help_text();
    for g in allow::known_group_names() {
        assert!(
            help.contains(g),
            "allow group '{g}' must be documented in help_text()"
        );
    }
}

#[test]
fn api_broker_config_matches_sentinel_and_port() {
    let conf = auth::render_api_broker_conf("AIzaTest123").unwrap();
    assert!(conf.contains(&format!("http_port {} accel", auth::API_BROKER_PORT)));
    assert!(conf.contains("acl gemini_broker_dotdot urlpath_regex"));
    assert!(conf.contains("http_access deny gemini_broker_port gemini_broker_dotdot"));
    assert!(!conf.contains(auth::API_KEY_SENTINEL));
}

#[test]
fn allow_validation_rejects_hex_ips_and_commented_squid_includes() {
    assert!(allow::validate_host("0x01.0x01.0x01.0x01").is_err());
    assert!(allow::validate_host("0x7f.0.0.1").is_err());
    assert!(allow::validate_host("docs.rs").is_ok());

    let commented = "# include /etc/squid/conf.d/allow.conf\ninclude /etc/squid/conf.d/api-broker.conf\nhttp_access deny all\n";
    assert!(allow::check_squid_conf_includes(commented).is_err());

    let misordered = "include /etc/squid/conf.d/api-broker.conf\nhttp_access deny all\ninclude /etc/squid/conf.d/allow.conf\n";
    assert!(allow::check_squid_conf_includes(misordered).is_err());
}

#[test]
fn git_gateway_prepares_throwaway_keys_and_cleans_up_on_drop() {
    let base = std::env::temp_dir().join(format!("agy-gw-unit-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let fake_host_key = base.join("host_id_ed25519");
    std::fs::write(
        &fake_host_key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();

    let temp_dir_path;
    {
        let sess = gitgateway::GitGatewaySession::prepare(
            "agy-test1234",
            GitHubMode::ReadOnly,
            Some(&fake_host_key),
            &["lmmx/agy-container".to_string()],
            &base,
        )
        .unwrap()
        .expect("session created");

        temp_dir_path = sess.temp_dir.clone();
        assert!(sess.client_key.is_file());
        assert!(sess.sidecar_host_key.is_file());
        let kh = std::fs::read_to_string(&sess.client_known_hosts).unwrap();
        assert!(kh.starts_with(&format!("[git-gateway]:{} ", gitgateway::GIT_GATEWAY_PORT)));
        let ak = std::fs::read_to_string(&sess.authorized_keys).unwrap();
        assert!(ak.starts_with("restrict,command=\"/usr/local/bin/git-policy\" "));
    }
    assert!(
        !temp_dir_path.exists(),
        "GitGatewaySession must delete throwaway keys on Drop"
    );
    let _ = std::fs::remove_dir_all(&base);
}
