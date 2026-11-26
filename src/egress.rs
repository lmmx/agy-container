use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Format current UTC wall-clock time as ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`)
/// using Howard Hinnant's civil-from-days algorithm (zero external crates).
pub fn utc_timestamp_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

pub fn format_utc(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Render a single-line structured header for the append-only egress audit log.
pub fn session_header(
    timestamp: &str,
    run_id: &str,
    network_mode: &str,
    auth_mode: &str,
    workspace: &Path,
) -> String {
    format!(
        "=== {timestamp} run={run_id} net={network_mode} auth={auth_mode} dir={} ===",
        workspace.display()
    )
}

/// Append a completed session's Squid + optional git-gateway logs to `egress.log`.
pub fn append_session_log(
    log_path: &Path,
    header: &str,
    proxy_logs: &str,
    gitgw_logs: Option<&str>,
) -> Result<(), String> {
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create log dir '{}': {e}", parent.display()))?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| format!("failed to open egress log '{}': {e}", log_path.display()))?;

    writeln!(f, "{header}").map_err(|e| format!("failed writing egress header: {e}"))?;
    if !proxy_logs.trim().is_empty() {
        writeln!(f, "{}", proxy_logs.trim_end())
            .map_err(|e| format!("failed writing proxy logs: {e}"))?;
    }
    if let Some(gw) = gitgw_logs {
        if !gw.trim().is_empty() {
            writeln!(f, "--- git-gateway ---")
                .map_err(|e| format!("failed writing git-gateway separator: {e}"))?;
            writeln!(f, "{}", gw.trim_end())
                .map_err(|e| format!("failed writing git-gateway logs: {e}"))?;
        }
    }
    writeln!(f).map_err(|e| format!("failed writing trailing newline: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_utc_timestamps() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_795_705_200), "2026-11-26T15:00:00Z");
    }

    #[test]
    fn header_has_stable_fields() {
        let h = session_header(
            "2026-11-26T15:00:00Z",
            "agy-deadbeef",
            "restricted",
            "api-key",
            Path::new("/tmp/repo"),
        );
        assert_eq!(
            h,
            "=== 2026-11-26T15:00:00Z run=agy-deadbeef net=restricted auth=api-key dir=/tmp/repo ==="
        );
    }
}
