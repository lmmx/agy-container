use std::collections::BTreeMap;

/// Tally of hosts observed in a Squid access log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TrafficTally {
    pub allowed: BTreeMap<String, usize>,
    pub denied: BTreeMap<String, usize>,
    pub total_requests: usize,
}

/// High-level diagnostic verdict for `--probe` runs.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    GatewayDown,
    NoTraffic,
    Denied { denied_hosts: Vec<String> },
    AllAllowed { allowed_hosts: Vec<String> },
}

/// Parse standard Squid native access log lines:
/// `<ts> <elapsed> <client> <result>/<status> <bytes> <method> <url> ...`
pub fn tally_squid_logs(logs: &str) -> TrafficTally {
    let mut tally = TrafficTally::default();

    for line in logs.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }
        // Standard Squid timestamp is numeric `<secs>.<ms>`.
        if !fields[0].chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let result_code = fields[3];
        let Some((action, status_str)) = result_code.split_once('/') else {
            continue;
        };
        let status: u16 = match status_str.parse() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let raw_target = fields[6];
        let Some(host) = extract_target_host(raw_target) else {
            continue;
        };

        tally.total_requests += 1;
        if action.contains("DENIED") || status == 403 {
            *tally.denied.entry(host).or_insert(0) += 1;
        } else {
            *tally.allowed.entry(host).or_insert(0) += 1;
        }
    }

    tally
}

pub fn extract_target_host(target: &str) -> Option<String> {
    if target.is_empty() || target == "-" || target.starts_with("error:") {
        return None;
    }
    // Strip scheme if absolute URL (e.g. http://example.com:80/path).
    let without_scheme = target
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(target);
    let authority = without_scheme.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    // Handle IPv6 `[::1]:443` or `host:443`.
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

pub fn classify_probe(proxy_running: bool, tally: &TrafficTally) -> Verdict {
    if !proxy_running && tally.total_requests == 0 {
        return Verdict::GatewayDown;
    }
    if tally.total_requests == 0 {
        return Verdict::NoTraffic;
    }
    if !tally.denied.is_empty() {
        return Verdict::Denied {
            denied_hosts: tally.denied.keys().cloned().collect(),
        };
    }
    Verdict::AllAllowed {
        allowed_hosts: tally.allowed.keys().cloned().collect(),
    }
}

pub fn render_probe_report(
    proxy_running: bool,
    tally: &TrafficTally,
    elapsed_secs: u64,
    timed_out: bool,
    self_test: bool,
) -> String {
    let verdict = classify_probe(proxy_running, tally);
    let mut out = String::new();
    out.push_str("\n=== agy-container probe report ===\n");
    out.push_str(&format!(
        "mode: {} | elapsed: {}s{}\n",
        if self_test { "self-test" } else { "probe" },
        elapsed_secs,
        if timed_out { " (timed out)" } else { "" }
    ));

    match verdict {
        Verdict::GatewayDown => {
            out.push_str("verdict: GATEWAY DID NOT START\n");
            out.push_str("hint: inspect proxy logs above or run with --build\n");
        }
        Verdict::NoTraffic => {
            out.push_str("verdict: NO PROXY TRAFFIC OBSERVED\n");
            out.push_str(
                "hint: process exited before making outbound HTTP(S) requests, or ignored HTTPS_PROXY\n",
            );
        }
        Verdict::Denied { denied_hosts } => {
            out.push_str(&format!(
                "verdict: DENIED ({} blocked host(s), {} total request(s))\n",
                denied_hosts.len(),
                tally.total_requests
            ));
        }
        Verdict::AllAllowed { allowed_hosts } => {
            out.push_str(&format!(
                "verdict: OBSERVED ({} allowed host(s), {} total request(s))\n",
                allowed_hosts.len(),
                tally.total_requests
            ));
        }
    }

    if !tally.allowed.is_empty() {
        out.push_str("allowed hosts:\n");
        for (h, count) in &tally.allowed {
            out.push_str(&format!("  + {h} ({count})\n"));
        }
    }
    if !tally.denied.is_empty() {
        out.push_str("denied hosts:\n");
        for (h, count) in &tally.denied {
            out.push_str(&format!("  - {h} ({count})\n"));
        }
    }
    out
}

/// Built-in `--probe --self-test` shell script executed inside the workspace container.
pub const SELF_TEST_CMD: &str = "\
set -u; \
echo '[self-test] checking allowed API host via proxy...'; \
curl -sS -o /dev/null -w 'generativelanguage.googleapis.com -> HTTP %{http_code}\n' --max-time 8 https://generativelanguage.googleapis.com/ || true; \
echo '[self-test] checking public host via permissive proxy...'; \
curl -sS -o /dev/null -w 'example.com -> HTTP %{http_code}\n' --max-time 8 https://example.com/ || true; \
echo '[self-test] checking private metadata SSRF denial via proxy...'; \
curl -sS -o /dev/null -w '169.254.169.254 -> HTTP %{http_code}\n' --max-time 8 http://169.254.169.254/latest/meta-data/ || true; \
echo '[self-test] checking direct route isolation...'; \
if timeout 2 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then \
  echo 'FAIL: direct route to 1.1.1.1:443 succeeded'; exit 1; \
else \
  echo 'ok: direct route to 1.1.1.1:443 blocked'; \
fi\
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_squid_logs_and_verdicts() {
        let sample = "\
1795618800.123 45 10.89.0.3 TCP_TUNNEL/200 1024 CONNECT daily-cloudcode-pa.googleapis.com:443 - HIER_DIRECT/142.250.1.1 -
1795618801.456 2 10.89.0.3 TCP_DENIED/403 3901 CONNECT example.com:443 - HIER_NONE/- text/html
1795618802.000 1 10.89.0.3 TCP_DENIED/403 3901 GET http://169.254.169.254/latest/meta-data/ - HIER_NONE/- text/html
1795618803.000 0 10.89.0.3 NONE_NONE/400 0 NONE error:invalid-request - HIER_NONE/- -
";
        let tally = tally_squid_logs(sample);
        assert_eq!(tally.total_requests, 3);
        assert_eq!(
            tally.allowed.get("daily-cloudcode-pa.googleapis.com"),
            Some(&1)
        );
        assert_eq!(tally.denied.get("example.com"), Some(&1));
        assert_eq!(tally.denied.get("169.254.169.254"), Some(&1));
        assert!(matches!(
            classify_probe(true, &tally),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn classifies_gateway_down_and_no_traffic() {
        let empty = TrafficTally::default();
        assert_eq!(classify_probe(false, &empty), Verdict::GatewayDown);
        assert_eq!(classify_probe(true, &empty), Verdict::NoTraffic);
    }
}
