use chrono::{DateTime, Utc};
use std::collections::HashMap;

use super::cli_probe::{
    CLAUDE_PROBE_CACHE_FILE, CLAUDE_PROBE_CACHE_TTL, ClaudeProbeCache, ClaudeProbeLock,
    claude_passive_probe_env, claude_probe_launch_args, claude_project_dir_name,
    claude_usage_settings_args, cleanup_probe_session_jsonl, cleanup_probe_transcripts_in,
    javascript_hash_base36, load_cached_probe_output, load_or_create_probe_session_id,
    login_fingerprint_at, run_locked_probe, store_cached_probe_output,
};
use super::*;

const LOGIN_A: &str = "login-a";

fn login_a() -> Option<String> {
    Some(LOGIN_A.to_string())
}

#[test]
fn probe_cache_roundtrip_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    assert!(load_cached_probe_output(dir.path(), LOGIN_A).is_none());
    store_cached_probe_output(dir.path(), LOGIN_A, "Current session 12% used");
    assert_eq!(
        load_cached_probe_output(dir.path(), LOGIN_A).as_deref(),
        Some("Current session 12% used")
    );
    let stale = ClaudeProbeCache {
        captured_at_unix: unix_now_secs() - CLAUDE_PROBE_CACHE_TTL.as_secs() - 5,
        login: LOGIN_A.to_string(),
        output: "Current session 12% used".to_string(),
    };
    std::fs::write(
        dir.path().join(CLAUDE_PROBE_CACHE_FILE),
        serde_json::to_string(&stale).unwrap(),
    )
    .unwrap();
    assert!(load_cached_probe_output(dir.path(), LOGIN_A).is_none());
}

#[test]
fn probe_cache_is_never_shared_with_another_login() {
    let dir = tempfile::tempdir().unwrap();
    store_cached_probe_output(dir.path(), LOGIN_A, "Current session 12% used");
    assert!(load_cached_probe_output(dir.path(), "login-b").is_none());

    // Written before screens were scoped to a login.
    let unscoped = format!(
        r#"{{"captured_at_unix":{},"output":"Current session 12% used"}}"#,
        unix_now_secs()
    );
    std::fs::write(dir.path().join(CLAUDE_PROBE_CACHE_FILE), unscoped).unwrap();
    assert!(load_cached_probe_output(dir.path(), LOGIN_A).is_none());
    assert!(load_cached_probe_output(dir.path(), "").is_none());
}

#[test]
fn login_fingerprint_follows_credential_rewrites_without_reading_them() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = dir.path().join(".credentials.json");
    assert_eq!(login_fingerprint_at(&credentials), None);

    std::fs::write(&credentials, "{}").unwrap();
    let first = login_fingerprint_at(&credentials).expect("fingerprint");
    assert_eq!(login_fingerprint_at(&credentials).as_ref(), Some(&first));
    assert!(!first.contains(".credentials"), "only a digest is stored");

    std::fs::write(&credentials, r#"{"another":"login"}"#).unwrap();
    assert_ne!(login_fingerprint_at(&credentials), Some(first));
}

const SHAREABLE_USAGE_SCREEN: &str = "Current session\n\
        ████████▌ 17% used\n\
        Resets 12pm (America/Bogota)\n";

#[test]
fn locked_probe_reuses_a_screen_stored_while_it_waited() {
    let dir = tempfile::tempdir().unwrap();
    store_cached_probe_output(dir.path(), LOGIN_A, SHAREABLE_USAGE_SCREEN);

    let output = run_locked_probe(dir.path(), Some(&login_a), || {
        panic!("a fresh shared screen must not launch another probe")
    })
    .unwrap();
    assert_eq!(output, SHAREABLE_USAGE_SCREEN);
}

#[test]
fn locked_probe_shares_only_parseable_usage_screens() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_locked_probe(dir.path(), Some(&login_a), || {
        Ok("Not logged in".to_string())
    });
    assert_eq!(output.unwrap(), "Not logged in");
    assert!(load_cached_probe_output(dir.path(), LOGIN_A).is_none());

    let output = run_locked_probe(dir.path(), Some(&login_a), || {
        Ok(SHAREABLE_USAGE_SCREEN.into())
    });
    assert_eq!(output.unwrap(), SHAREABLE_USAGE_SCREEN);
    assert_eq!(
        load_cached_probe_output(dir.path(), LOGIN_A).as_deref(),
        Some(SHAREABLE_USAGE_SCREEN)
    );
    assert!(
        !dir.path()
            .read_dir()
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().contains(".tmp-")),
        "the atomic write left no staging file behind"
    );
}

#[test]
fn locked_probe_keeps_a_screen_private_when_the_login_changed_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let calls = std::cell::Cell::new(0);
    let switching_login = || {
        calls.set(calls.get() + 1);
        Some(format!("login-{}", calls.get()))
    };
    let output = run_locked_probe(dir.path(), Some(&switching_login), || {
        Ok(SHAREABLE_USAGE_SCREEN.into())
    });
    assert_eq!(output.unwrap(), SHAREABLE_USAGE_SCREEN);
    assert_eq!(calls.get(), 2, "the login is read before and after");
    assert!(load_cached_probe_output(dir.path(), "login-1").is_none());
    assert!(load_cached_probe_output(dir.path(), "login-2").is_none());

    let no_login = || None;
    run_locked_probe(dir.path(), Some(&no_login), || {
        Ok(SHAREABLE_USAGE_SCREEN.into())
    })
    .unwrap();
    assert!(!dir.path().join(CLAUDE_PROBE_CACHE_FILE).exists());
}

#[test]
fn unshared_probe_neither_reuses_nor_stores_screens() {
    let dir = tempfile::tempdir().unwrap();
    store_cached_probe_output(dir.path(), LOGIN_A, SHAREABLE_USAGE_SCREEN);
    let output = run_locked_probe(dir.path(), None, || Ok("trust preflight".into()));
    assert_eq!(output.unwrap(), "trust preflight");

    let other = tempfile::tempdir().unwrap();
    run_locked_probe(other.path(), None, || Ok(SHAREABLE_USAGE_SCREEN.into())).unwrap();
    assert!(!other.path().join(CLAUDE_PROBE_CACHE_FILE).exists());
}

#[test]
fn logged_probe_screen_masks_account_email_and_secrets() {
    let screen = "Login: someone@example.com (Claude Max)\n\
                      access_token=abcdef0123456789 sk-ant-abcdefgh12345678\n\
                      Current session 12% used";
    let logged = redacted_probe_screen(screen);
    assert!(!logged.contains("someone@example.com"), "{logged}");
    assert!(!logged.contains("abcdef0123456789"), "{logged}");
    assert!(!logged.contains("sk-ant-abcdefgh12345678"), "{logged}");
    assert!(logged.contains("Current session 12% used"));
}

#[test]
fn probe_lock_wait_expiry_fails_instead_of_probing_alongside() {
    let dir = tempfile::tempdir().unwrap();
    let held = ClaudeProbeLock::acquire_within(dir.path(), Duration::ZERO)
        .expect("first lock")
        .expect("file locking is supported");

    let error = match ClaudeProbeLock::acquire_within(dir.path(), Duration::from_millis(300)) {
        Ok(lock) => panic!("second lock acquired while held: {}", lock.is_some()),
        Err(error) => error,
    };
    assert!(error.to_string().contains("Timed out waiting"), "{error}");
    assert_eq!(
        last_good_failure_policy_for_error(&error.to_string()),
        LastGoodFailurePolicy::Preserve
    );

    drop(held);
    assert!(
        ClaudeProbeLock::acquire_within(dir.path(), Duration::ZERO)
            .expect("lock after release")
            .is_some()
    );
}

#[test]
fn passive_probe_env_disables_autoupdater_color_and_chrome() {
    let env = claude_passive_probe_env(HashMap::new());
    for (key, value) in [
        ("DISABLE_AUTOUPDATER", "1"),
        ("NO_COLOR", "1"),
        ("CLAUDE_CODE_ENABLE_CFC", "0"),
    ] {
        assert_eq!(env.get(key).map(String::as_str), Some(value), "{key}");
    }
}

#[test]
fn probe_session_id_is_reused_from_probe_directory() {
    let dir = tempfile::tempdir().unwrap();
    let first = load_or_create_probe_session_id(dir.path());
    let second = load_or_create_probe_session_id(dir.path());
    assert_eq!(first, second);
    assert!(uuid::Uuid::parse_str(&first).is_ok());
    let args = claude_probe_launch_args(&first);
    // Positional structure only: the settings pair is pinned once by
    // `claude_usage_settings_args` being the sole composer.
    assert_eq!(
        args[..5],
        [
            "--setting-sources",
            "user",
            "--allowed-tools",
            "",
            "--strict-mcp-config"
        ]
    );
    assert_eq!(args[5], claude_usage_settings_args()[0]);
    assert_eq!(args[6], claude_usage_settings_args()[1]);
    assert_eq!(args[7], "--session-id");
    assert_eq!(args[8], first);
}

#[test]
fn usage_probe_settings_disable_remote_control_startup_and_user_hooks() {
    assert_eq!(
        claude_usage_settings_args(),
        [
            "--settings".to_string(),
            r#"{"remoteControlAtStartup":false,"disableAllHooks":true,"tui":"default"}"#
                .to_string(),
        ]
    );
    let settings: serde_json::Value =
        serde_json::from_str(&claude_usage_settings_args()[1]).unwrap();
    assert_eq!(settings["tui"], "default");
    assert_eq!(settings["remoteControlAtStartup"], false);
    assert_eq!(settings["disableAllHooks"], true);
}

#[test]
fn probe_session_jsonl_cleanup_removes_transcript_files() {
    let dir = tempfile::tempdir().unwrap();
    let jsonl = dir.path().join("session.jsonl");
    std::fs::write(&jsonl, "{}").unwrap();
    std::fs::write(dir.path().join("keep.txt"), "x").unwrap();
    cleanup_probe_session_jsonl(dir.path());
    assert!(!jsonl.exists());
    assert!(dir.path().join("keep.txt").exists());
}

#[test]
fn probe_project_dir_name_matches_claude_code() {
    use std::path::Path;
    assert_eq!(
        claude_project_dir_name(Path::new(
            r"C:\Users\user\AppData\Local\CodexBar\claude-usage-probe"
        )),
        "C--Users-user-AppData-Local-CodexBar-claude-usage-probe"
    );
    assert_eq!(
        claude_project_dir_name(Path::new("/Users/me/Library/Application Support/x")),
        "-Users-me-Library-Application-Support-x"
    );
    // One dash per UTF-16 code unit, so two for a character outside the BMP.
    assert_eq!(
        claude_project_dir_name(Path::new("C:\\Users\\J\u{f6}rg\u{1F600}\\probe")),
        "C--Users-J-rg---probe"
    );
    // Reference values from Claude Code's JavaScript implementation.
    let long = format!(
        r"C:\Users\user\AppData\Local\{}claude-usage-probe",
        r"deep\".repeat(40)
    );
    assert_eq!(
        claude_project_dir_name(Path::new(&long)),
        format!(
            "C--Users-user-AppData-Local-{}de-ttzy4x",
            "deep-".repeat(34)
        )
    );
    assert_eq!(javascript_hash_base36("hello"), "1n1e4y");
    assert_eq!(javascript_hash_base36(""), "0");
}

#[test]
fn probe_transcript_cleanup_stays_inside_the_probe_project() {
    use std::path::Path;
    let projects = tempfile::tempdir().unwrap();
    let other = projects.path().join("C--work-repo");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("session.jsonl"), "{}").unwrap();

    let busy_probe = Path::new(r"C:\Users\user\AppData\Local\CodexBar\busy-probe");
    let busy = projects.path().join(claude_project_dir_name(busy_probe));
    std::fs::create_dir_all(busy.join("folder.jsonl")).unwrap();
    std::fs::write(busy.join("session.jsonl"), "{}").unwrap();
    std::fs::write(busy.join("notes.txt"), "x").unwrap();
    cleanup_probe_transcripts_in(projects.path(), busy_probe);
    assert!(!busy.join("session.jsonl").exists());
    assert!(busy.join("notes.txt").exists());
    assert!(busy.join("folder.jsonl").is_dir(), "only files are removed");

    let probe = Path::new(r"C:\Users\user\AppData\Local\CodexBar\claude-usage-probe");
    let project = projects.path().join(claude_project_dir_name(probe));
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("a.jsonl"), "{}").unwrap();
    std::fs::write(project.join("b.jsonl"), "{}").unwrap();
    cleanup_probe_transcripts_in(projects.path(), probe);
    assert!(!project.exists(), "an emptied probe project dir is removed");

    assert!(other.join("session.jsonl").exists(), "other projects stay");
}

fn parse_ok(output: &str) -> ProviderFetchResult {
    ClaudeProvider::new()
        .parse_cli_output(output)
        .expect("should parse")
}

fn parse_err(output: &str) -> ProviderError {
    ClaudeProvider::new()
        .parse_cli_output(output)
        .expect_err("should reject")
}

/// Plans without a 5-hour limit print no "Current session" row. The first
/// percentage on the panel is then the weekly one and must not become the
/// session (VibeTV-shop/vibetv#614, upstream steipete/CodexBar#4914).
#[test]
fn weekly_only_cli_screen_keeps_session_empty() {
    let usage = parse_ok(
        r#"
Status   Config   Usage

  Current week (all models)
  ████                                               8% used
  Resets Nov 9 at 9am (America/New_York)

  Current week (Fable only)
  ▌                                                  0% used
  Resets Nov 9 at 9am (America/New_York)
"#,
    )
    .usage;
    assert!(usage.primary.is_informational);
    assert_eq!(usage.primary.used_percent, 0.0);
    assert_eq!(usage.secondary.map(|w| w.used_percent), Some(8.0));
}

#[test]
fn parses_current_cli_usage_screen() {
    let output = r#"
Status   Config   Usage

  Current session
  ██████████████████████████████████████████████████ 100% used
  Resets 12pm (America/Bogota)

  Current week (all models)
  ████████████████████████▌                          49% used
  Resets Apr 3, 2pm (America/Bogota)

  Extra usage
  ██▍                                                4% used
  $3.31 / $70.00 spent · Resets Apr 1 (America/Bogota)
"#;

    let result = parse_ok(output);

    assert_eq!(result.source_label, "cli");
    assert_eq!(result.usage.primary.used_percent, 100.0);
    assert_eq!(
        result.usage.primary.reset_description.as_deref(),
        Some("Resets 12pm (America/Bogota)")
    );

    let weekly = result
        .usage
        .secondary
        .expect("weekly usage should be present");
    assert_eq!(weekly.used_percent, 49.0);
    assert_eq!(
        weekly.reset_description.as_deref(),
        Some("Resets Apr 3, 2pm (America/Bogota)")
    );
}

#[test]
fn parses_short_forms_as_full_session_usage() {
    let rows = [
        (
            "You're out of extra usage · resets 12pm (America/Bogota)",
            "resets 12pm (America/Bogota)",
        ),
        (
            "You've hit your limit \u{00b7} resets 3:20pm (Asia/Shanghai)",
            "resets 3:20pm (Asia/Shanghai)",
        ),
    ];
    for (output, reset) in rows {
        let result = parse_ok(output);
        assert_eq!(result.usage.primary.used_percent, 100.0, "{output}");
        assert_eq!(
            result.usage.primary.reset_description.as_deref(),
            Some(reset)
        );
    }
}

#[test]
fn parses_remaining_available_and_decimal_percentages() {
    let output = r#"
Status   Config   Usage

  Current session
  12.5% remaining
  Resets 8pm

  Current week (all models)
  4% available
  Resets Apr 4, 2pm

  Current week (Sonnet only)
  1% consumed
"#;

    let result = parse_ok(output);

    assert_eq!(result.usage.primary.used_percent, 87.5);
    assert_eq!(
        result.usage.primary.reset_description.as_deref(),
        Some("Resets 8pm")
    );

    let weekly = result
        .usage
        .secondary
        .expect("weekly usage should be present");
    assert_eq!(weekly.used_percent, 96.0);
    assert_eq!(
        weekly.reset_description.as_deref(),
        Some("Resets Apr 4, 2pm")
    );

    let sonnet = result
        .usage
        .extra_rate_windows
        .iter()
        .find(|window| window.id == "claude-weekly-scoped-sonnet")
        .expect("sonnet usage should be present");
    assert_eq!(sonnet.window.used_percent, 1.0);
}

#[test]
fn parses_all_cli_model_scoped_weekly_limits() {
    let output = r#"
Current session
10% used
Resets 12pm (America/Bogota)

Current week (all models)
20% used
Resets Apr 3, 2pm (America/Bogota)

Current week (Sonnet only)
30% used
Resets Apr 4, 2pm (America/Bogota)

Current week (Opus only)
40% used
Resets Apr 5, 2pm (America/Bogota)
"#;

    let result = parse_ok(output);

    assert_eq!(result.usage.extra_rate_windows.len(), 2);
    assert_eq!(
        result.usage.extra_rate_windows[0].id,
        "claude-weekly-scoped-sonnet"
    );
    assert_eq!(result.usage.extra_rate_windows[0].title, "Sonnet only");
    assert_eq!(result.usage.extra_rate_windows[0].window.used_percent, 30.0);
    assert_eq!(
        result.usage.extra_rate_windows[1].id,
        "claude-weekly-scoped-opus"
    );
    assert!(result.usage.model_specific.is_none());
}

#[test]
fn scoped_weekly_parser_handles_non_ascii_labels_and_reset_prefixes() {
    let now = "2026-04-02T18:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let limits = extract_cli_scoped_weekly_limits(
        "Current week (A€€)\n10% used\nİResets Apr 3 at 2pm (America/Bogota)",
        now,
    );

    assert_eq!(limits.len(), 1);
    assert_eq!(limits[0].title, "A€€");
    assert_eq!(
        limits[0].window.resets_at,
        Some("2026-04-03T19:00:00Z".parse().unwrap())
    );
}

#[test]
fn resolves_cli_reset_occurrences_in_the_reported_timezone() {
    let now = "2026-04-02T18:00:00Z".parse::<DateTime<Utc>>().unwrap();

    assert_eq!(
        parse_claude_reset_date("Resets Apr 3, 2027, 2pm (America/Bogota)", now, None),
        Some("2027-04-03T19:00:00Z".parse().unwrap())
    );
    assert_eq!(
        parse_claude_reset_date("Resets Apr 3, 2pm (America/Bogota)", now, None),
        Some("2026-04-03T19:00:00Z".parse().unwrap())
    );
    assert_eq!(
        parse_claude_reset_date("Resets 12pm (America/Bogota)", now, None),
        Some("2026-04-03T17:00:00Z".parse().unwrap())
    );
    assert_eq!(
        parse_claude_reset_date("ResetsApr3at2pm(America/Bogota)", now, None),
        Some("2026-04-03T19:00:00Z".parse().unwrap())
    );
}

#[test]
fn timezone_less_resets_use_the_supplied_system_zone() {
    let now = "2026-03-07T18:00:00Z".parse::<DateTime<Utc>>().unwrap();

    assert_eq!(
        parse_claude_reset_date_in_system_zone(
            "Resets Mar 8 at 3:30am",
            now,
            None,
            "America/New_York".parse().unwrap(),
        ),
        Some("2026-03-08T07:30:00Z".parse().unwrap())
    );
    assert_eq!(
        parse_claude_reset_date_in_system_zone(
            "Resets Mar 8 at 3:30am (America/Los_Angeles)",
            now,
            None,
            "America/New_York".parse().unwrap(),
        ),
        Some("2026-03-08T10:30:00Z".parse().unwrap())
    );
}

#[test]
fn reset_dates_resolve_every_month_and_form() {
    let now = "2026-09-24T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let at = |text: &str, window: Option<u32>| {
        parse_claude_reset_date(text, now, window).map(|date| date.to_rfc3339())
    };
    let months = [
        "Jan", "FEB", "mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "dEc",
    ];
    for (index, month) in months.iter().enumerate() {
        assert_eq!(
            at(&format!("Resets {month} 5, 2027 at 3pm (UTC)"), None),
            Some(format!("2027-{:02}-05T15:00:00+00:00", index + 1)),
            "{month}"
        );
    }
    let rows = [
        ("Resets Foo 5, 2027 at 3pm (UTC)", None, None),
        ("Resets Feb 30, 2027 at 3pm (UTC)", None, None),
        (
            "Resets Sep 23 at 3pm (UTC)",
            None,
            Some("2027-09-23T15:00:00+00:00"),
        ),
        (
            "Resets Sep 23 at 3pm (UTC)",
            Some(10_080),
            Some("2026-09-23T15:00:00+00:00"),
        ),
        (
            "Resets Feb 29 at 3pm (UTC)",
            None,
            Some("2028-02-29T15:00:00+00:00"),
        ),
        ("Resets 3pm (UTC)", None, Some("2026-09-24T15:00:00+00:00")),
        ("Resets 11am (UTC)", None, Some("2026-09-25T11:00:00+00:00")),
        (
            "Resets 11am (UTC)",
            Some(300),
            Some("2026-09-24T11:00:00+00:00"),
        ),
        (
            "Resets Nov 1, 2026 at 1:30am (America/New_York)",
            None,
            Some("2026-11-01T05:30:00+00:00"),
        ),
        (
            "Resets Mar 8, 2026 at 2:30am (America/New_York)",
            None,
            None,
        ),
    ];
    for (text, window, expected) in rows {
        assert_eq!(at(text, window).as_deref(), expected, "{text} {window:?}");
    }
}

#[test]
fn parses_compact_usage_screen() {
    let output = r#"
Settings:StatusConfigUsage(tabtocycle)
Loadingusagedata...
Currentsession
6%used
Resets4:29am(Asia/Calcutta)
Currentweek(allmodels)
4%used
ResetsFeb12at1:29pm(Asia/Calcutta)
Currentweek(Sonnetonly)
1%used
ResetsFeb12at1:29pm(Asia/Calcutta)
"#;

    let result = parse_ok(output);

    assert_eq!(result.usage.primary.used_percent, 6.0);
    assert_eq!(
        result.usage.primary.reset_description.as_deref(),
        Some("Resets4:29am(Asia/Calcutta)")
    );
    assert_eq!(
        result
            .usage
            .secondary
            .expect("weekly usage should be present")
            .used_percent,
        4.0
    );
    let sonnet = result
        .usage
        .extra_rate_windows
        .iter()
        .find(|window| window.id == "claude-weekly-scoped-sonnet")
        .expect("sonnet usage should be present");
    assert_eq!(result.usage.extra_rate_windows.len(), 1);
    assert_eq!(sonnet.title, "Sonnet only");
    assert_eq!(sonnet.window.used_percent, 1.0);
}

#[test]
fn does_not_promote_weekly_reset_to_session() {
    let output = r#"
Current session
17% used
Current week (all models)
4% used
Resets Dec 24 at 3:59pm (Europe/Paris)
"#;

    let result = parse_ok(output);

    assert_eq!(result.usage.primary.used_percent, 17.0);
    assert_eq!(result.usage.primary.reset_description, None);
    assert_eq!(
        result
            .usage
            .secondary
            .expect("weekly usage should be present")
            .reset_description
            .as_deref(),
        Some("Resets Dec 24 at 3:59pm (Europe/Paris)")
    );
}

#[test]
fn cli_error_markers_map_to_fixed_errors() {
    let git_bash = "Other(\"Claude CLI requires Git Bash on Windows. Install Git for Windows or set CLAUDE_CODE_GIT_BASH_PATH to your bash.exe path.\")";
    let cases = [
        ("Error: Not Logged In", "AuthRequired"),
        ("login required to continue", "AuthRequired"),
        (
            "TOKEN EXPIRED",
            "OAuthExpired(\"Token expired. Run `claude login` to refresh.\")",
        ),
        (
            "{\"type\":\"token_expired\"}",
            "OAuthExpired(\"Token expired. Run `claude login` to refresh.\")",
        ),
        (
            "authentication_error",
            "OAuth(\"Authentication error. Run `claude login`.\")",
        ),
        ("Claude Code on Windows requires git-bash.", git_bash),
        (
            "Running scripts is disabled on this system",
            "Other(\"Claude CLI could not start because PowerShell script execution is disabled. Use claude.cmd or adjust the execution policy.\")",
        ),
        (
            "Cannot run a document in the middle of a pipeline",
            "Other(\"Claude CLI resolved to a Unix shell script on Windows. Reinstall Claude Code or ensure claude.cmd is first on PATH.\")",
        ),
        // Auth markers win over environment markers.
        ("requires git-bash; not logged in", "AuthRequired"),
        (
            "requires git-bash; token expired",
            "OAuthExpired(\"Token expired. Run `claude login` to refresh.\")",
        ),
        // Login wins over the other auth markers.
        ("token expired; not logged in", "AuthRequired"),
        (
            "authentication_error; token_expired",
            "OAuthExpired(\"Token expired. Run `claude login` to refresh.\")",
        ),
        ("running scripts is disabled; requires git-bash", git_bash),
    ];
    for (output, expected) in cases {
        let error = claude_cli_error_from_output(output).expect(output);
        assert_eq!(format!("{error:?}"), expected, "{output}");
    }
    assert!(claude_cli_error_from_output("Current session 5% used").is_none());
}

#[test]
fn all_percents_fold_case_and_clamp() {
    let text = "50% USED\n20 % Left\n101% used\n150% left\n5.5% remaining\n1000% used\n7%Spent 8% available";
    assert_eq!(
        percent_matches(text).collect::<Vec<_>>(),
        vec![50.0, 80.0, 100.0, 0.0, 94.5, 0.0, 7.0, 92.0]
    );
    assert!(percent_matches("no numbers here").next().is_none());
}

#[test]
fn label_sections_stop_at_their_window_and_the_next_section() {
    let filler = |count: usize| vec!["filler"; count].join("\n");
    // Percent on the label line itself, and on the last line of the
    // twelve-line window (label + 11).
    assert_eq!(
        extract_percent_near_label("Current session 30% used", "current session"),
        Some(30.0)
    );
    let at_last = format!("Current session\n{}\n40% used", filler(10));
    assert_eq!(
        extract_percent_near_label(&at_last, "current session"),
        Some(40.0)
    );
    let past_window = format!("Current session\n{}\n40% used", filler(11));
    assert_eq!(
        extract_percent_near_label(&past_window, "current session"),
        None
    );
    // The next "Current ..." heading ends the section, but the same
    // heading does not.
    let next_section = "Current session\nCurrent week\n40% used";
    assert_eq!(
        extract_percent_near_label(next_section, "current session"),
        None
    );
    let same_label = "Current session\nCURRENT SESSION again\n40% used";
    assert_eq!(
        extract_percent_near_label(same_label, "current session"),
        Some(40.0)
    );
    // A section without a value falls through to a later label line.
    let later = "Current session\nCurrent week\n10% used\nCurrent session\n60% left";
    assert_eq!(
        extract_percent_near_label(later, "current session"),
        Some(40.0)
    );
    assert_eq!(
        extract_percent_near_label("Current week (all models)\n10% used", "current week"),
        Some(10.0)
    );

    // Reset text uses a fourteen-line window (label + 13).
    let reset_last = format!("Current week\n{}\nResets Mon 9am", filler(12));
    assert_eq!(
        extract_reset_description(&reset_last, "current week").as_deref(),
        Some("Resets Mon 9am")
    );
    let reset_past = format!("Current week\n{}\nResets Mon 9am", filler(13));
    assert_eq!(extract_reset_description(&reset_past, "current week"), None);
    assert_eq!(
        extract_reset_description("Current week  5% used · resets Fri 1pm  ", "current week")
            .as_deref(),
        Some("resets Fri 1pm")
    );
    assert_eq!(
        extract_reset_description(
            "Current session\nCurrent week\nResets Mon",
            "current session"
        ),
        None
    );
    let later_reset = "Current session\nCurrent week\nCurrent session\nResets 5pm";
    assert_eq!(
        extract_reset_description(later_reset, "current session").as_deref(),
        Some("Resets 5pm")
    );
}

#[test]
fn scoped_weekly_sections_use_a_fourteen_line_window() {
    let now = Utc::now();
    let filler = |count: usize| vec!["filler"; count].join("\n");
    let inside = format!("Current week (Opus)\n{}\n25% used", filler(12));
    let limits = extract_cli_scoped_weekly_limits(&inside, now);
    assert_eq!(limits.len(), 1);
    assert_eq!(limits[0].window.used_percent, 25.0);
    let outside = format!("Current week (Opus)\n{}\n25% used", filler(13));
    assert!(extract_cli_scoped_weekly_limits(&outside, now).is_empty());
    let next = "Current week (Opus)\nCurrent session\n25% used";
    assert!(extract_cli_scoped_weekly_limits(next, now).is_empty());
}

/// Insights footer as Claude Code 2.1.294 prints it below the quota rows.
const USAGE_INSIGHTS: &str = "What's contributing to your limits usage?\n\
        Approximate, based on local sessions on this machine.\n\
        Last 24h · 100 requests · 2 sessions\n\
        30% of your usage was at >150k context\n\
        Top MCP servers: Claude Browser 10%, claude-in-chrome 5%\n\
        Last 7d · 1000 requests · 20 sessions\n\
        Top skills: Claude Max 20%";

#[test]
fn usage_insights_footer_cannot_set_identity_or_quota() {
    let text = format!(
        "Current session\n13% used\nResets 2:20pm (Asia/Singapore)\n\
             Current week (all models)\n2% used\nResets Oct 3 at 8am (Asia/Singapore)\n{USAGE_INSIGHTS}"
    );
    let usage = ClaudeProvider::new().parse_cli_output(&text).unwrap().usage;
    assert_eq!(usage.primary.used_percent, 13.0);
    assert_eq!(
        usage.primary.reset_description.as_deref(),
        Some("Resets 2:20pm (Asia/Singapore)")
    );
    assert_eq!(usage.secondary.map(|w| w.used_percent), Some(2.0));
    assert_eq!(usage.login_method.as_deref(), Some("Claude (CLI)"));
}

#[test]
fn usage_insights_without_quota_are_not_read_as_limits() {
    let text = format!(
        "You are currently using your subscription to power your Claude Code usage\n{USAGE_INSIGHTS}"
    );
    let error = ClaudeProvider::new().parse_cli_output(&text).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("returned usage insights without quota data"),
        "{error}"
    );
}

#[test]
fn cli_parse_usage_error_can_fallback_to_oauth() {
    let err = ProviderError::Parse("Claude CLI did not return usage data".to_string());

    assert!(should_fallback_from_claude_cli_error(&err));
}

#[test]
fn cli_auth_error_does_not_fallback_to_oauth() {
    assert!(!should_fallback_from_claude_cli_error(
        &ProviderError::AuthRequired
    ));
}

#[test]
fn claude_code_answers_before_the_browser_unless_a_cookie_was_asked_for() {
    let ctx = |api_key: Option<&str>, cookie: Option<&str>| FetchContext {
        api_key: api_key.map(str::to_string),
        manual_cookie_header: cookie.map(str::to_string),
        ..FetchContext::default()
    };
    assert!(claude_code_answers_first(&ctx(None, None), true));
    assert!(claude_code_answers_first(&ctx(Some("token"), None), false));
    assert!(!claude_code_answers_first(&ctx(Some(" "), None), false));
    assert!(!claude_code_answers_first(&ctx(None, None), false));
    // A token account's cookie is its own account, whatever Claude Code holds.
    assert!(!claude_code_answers_first(&ctx(None, Some("sessionKey=x")), true));
}

#[test]
fn auto_fetch_error_keeps_all_source_failures() {
    let err = claude_auto_fetch_error(vec![
        ("OAuth", ProviderError::OAuth("token expired".to_string())),
        ("Web", ProviderError::NoCookies),
        (
            "CLI",
            ProviderError::Parse("Empty output from Claude CLI".to_string()),
        ),
    ]);

    assert_eq!(
        err.to_string(),
        "Claude usage failed from all configured sources. OAuth: OAuth error: token expired; Web: No cookies available for web API; CLI: Parse error: Empty output from Claude CLI"
    );
}

fn oauth_rate_limited() -> ProviderError {
    ClaudeOAuthFetcher::rate_limited_error(Duration::from_secs(30))
}

#[test]
fn auto_fetch_error_asks_for_a_browser_sign_in_when_only_the_browser_can_help() {
    // (CLI failure, retention policy of the plain summary)
    let cases = [
        (
            ProviderError::Parse("Claude CLI did not return usage data".to_string()),
            LastGoodFailurePolicy::Preserve,
        ),
        (
            ProviderError::Other("Claude CLI failed: exit status 1".to_string()),
            LastGoodFailurePolicy::Replace,
        ),
    ];
    for (cli_failure, policy) in cases {
        let err = claude_auto_fetch_error(vec![
            ("Web", ProviderError::NoCookies),
            ("OAuth", oauth_rate_limited()),
            ("CLI", cli_failure),
        ]);
        let ProviderError::BrowserSignInRequired {
            message,
            sign_in_url,
        } = &err
        else {
            panic!("expected a browser sign-in signal, got {err:?}");
        };
        assert_eq!(sign_in_url, CLAUDE_BROWSER_SIGN_IN_URL);
        assert_eq!(err.to_string(), *message);
        assert!(
            message.starts_with(
                "Claude usage failed from all configured sources. Web: No cookies available for web API; OAuth: Transient OAuth error: Claude OAuth usage endpoint is rate limited."
            ),
            "{message}"
        );
        assert!(
            message.ends_with("Sign in at https://claude.ai/login in your browser, then refresh."),
            "{message}"
        );
        // ClaudeProvider::error_state_kind defers to this for every
        // variant except a missing CLI.
        assert_eq!(
            err.state_kind(),
            crate::core::ProviderStateKind::NeedsAuthentication
        );
        // The hint leaves the desktop retention policy unchanged.
        let plain = message
            .strip_suffix(browser_sign_in_hint().as_str())
            .map(str::trim_end)
            .expect("hint is appended");
        assert_eq!(last_good_failure_policy_for_error(plain), policy);
        assert_eq!(last_good_failure_policy_for_error(message), policy);
    }
}

#[test]
fn auto_fetch_error_keeps_other_failure_mixes_untyped() {
    let cli_failure = || ProviderError::Parse("Claude CLI did not return usage data".to_string());
    let mixes = [
        // A browser session was there; the Web source failed differently.
        vec![
            ("Web", ProviderError::AuthRequired),
            ("OAuth", oauth_rate_limited()),
            ("CLI", cli_failure()),
        ],
        // Signed out of Claude Code, not rate limited.
        vec![
            ("Web", ProviderError::NoCookies),
            (
                "OAuth",
                ProviderError::OAuth(
                    "Claude OAuth credentials not found. Run `claude` to authenticate."
                        .to_string(),
                ),
            ),
            ("CLI", cli_failure()),
        ],
        // Another transient OAuth failure.
        vec![
            ("Web", ProviderError::NoCookies),
            (
                "OAuth",
                ProviderError::OAuthTransient(
                    "Claude OAuth token expired and token refresh is cooling down after a failed attempt."
                        .to_string(),
                ),
            ),
            ("CLI", cli_failure()),
        ],
        // The CLI was not tried.
        vec![
            ("Web", ProviderError::NoCookies),
            ("OAuth", oauth_rate_limited()),
        ],
    ];
    for failures in mixes {
        let err = claude_auto_fetch_error(failures);
        assert!(matches!(err, ProviderError::Other(_)), "{err:?}");
        assert!(
            !err.to_string().contains(CLAUDE_BROWSER_SIGN_IN_URL),
            "{err}"
        );
    }
}

#[test]
fn transient_transport_failure_stops_auto_fallback_and_preserves_last_good() {
    let provider = ClaudeProvider::new();
    assert!(provider.retains_last_good_on_transport_failure());
    assert_eq!(
        provider.last_good_failure_policy_for_error(&ProviderError::Timeout),
        LastGoodFailurePolicy::Preserve
    );

    let mut failures = Vec::new();
    let result = record_auto_source(&mut failures, "Web", Err(ProviderError::Timeout));
    assert!(matches!(result, Err(ProviderError::Timeout)));
    assert!(failures.is_empty());
}

#[test]
fn rejects_cli_output_that_is_not_a_usage_screen() {
    let git_bash = "Claude Code on Windows requires git-bash.";
    let claude_2_1 = r#"
I see you've entered `/usage` and `/exit`.

**Usage**: Token usage and statistics are typically displayed by the CLI interface itself. I don't have direct access to those metrics through my available tools.

**Exit**: I'll end the session here. Goodbye!
"#;
    let legacy = r#"
I see you've entered two slash commands:

1. `/usage` - This appears to be a request to check usage information
2. `/exit` - This appears to be a request to exit

However, looking at the available custom slash commands, I don't see these commands defined.
"#;
    let activity = r#"
❯ /usage

Status   Config   Usage   Stats

Overview  Models

Favorite model: glm-4.6        Total tokens: 263.3k
Sessions: 6                    Longest session: 18s
Active days: 2/10              Longest streak: 1 day
"#;
    let ansi_activity = "\x1b[2CTotal\x1b[1Ccost:\x1b[12C$0.0000\n\
                      \x1b[2CTotal\x1b[1Cduration\x1b[1C(API):\x1b[2C0s\n\
                      \x1b[2CUsage:\x1b[17C0\x1b[1Cinput,\x1b[1C0\x1b[1Coutput,\x1b[1C0\x1b[1Ccache\x1b[1Cread";
    let rows: [(&str, &str, Option<&str>); 5] = [
        (
            git_bash,
            "parse",
            Some("Parse error: Claude CLI did not return usage data"),
        ),
        (
            claude_2_1,
            "other",
            Some(
                "Claude CLI treated /usage as a normal prompt instead of opening the interactive usage screen. Use Auto, OAuth, or Web mode for Claude usage.",
            ),
        ),
        (legacy, "other", None),
        (
            activity,
            "other",
            Some(
                "Claude CLI /usage opened, but this Claude version returned local activity stats instead of plan limit percentages. Use Auto, OAuth, or Web mode for Claude limits.",
            ),
        ),
        (ansi_activity, "other", None),
    ];
    for (output, kind, message) in rows {
        let err = parse_err(output);
        let got = match &err {
            ProviderError::Parse(_) => "parse",
            ProviderError::Other(_) => "other",
            _ => "unexpected",
        };
        assert_eq!(got, kind, "{output}");
        if let Some(message) = message {
            assert_eq!(err.to_string(), message);
        }
    }
}

#[test]
fn accepts_plan_limits_followed_by_activity_stats() {
    // Claude Code 2.1.27x on Windows prints the exit summary (cost,
    // duration, cache tokens) after the /usage view when the probe ends.
    let output = r#"
❯ /usage

Status   Config   Usage   Stats

Current session
███████░░░░░░░░░░░░░░░░░░░░░░ 19% used
Resets 3pm (Europe/Berlin)

Current week (all models)
█████████░░░░░░░░░░░░░░░░░░░░ 31% used
Resets Sep 19, 4pm (Europe/Berlin)

Total cost:            $0.0000
Total duration (API):  0s
Usage:                 0 input, 0 output, 0 cache read
"#;

    let result = parse_ok(output);

    assert_eq!(result.usage.primary.used_percent, 19.0);
    assert_eq!(
        result
            .usage
            .secondary
            .as_ref()
            .map(|window| window.used_percent),
        Some(31.0)
    );
}

// ── Upstream 0.50.1 #2516: revoked vs missing OAuth ────────────────────────

#[test]
fn oauth_revoked_error_is_detected() {
    assert!(is_oauth_revoked_error(&ProviderError::OAuthRevoked(
        "revoked".to_string()
    )));
    assert!(!is_oauth_revoked_error(&ProviderError::OAuth(
        "expired".to_string()
    )));
    assert!(!is_oauth_revoked_error(&ProviderError::AuthRequired));
}

#[test]
fn rate_limited_and_revoked_oauth_reuse_the_cli_cache() {
    let rate_limited = ProviderError::OAuthTransient(
        "Claude OAuth usage endpoint is rate limited. Retrying in about 5m; credentials were preserved."
            .to_string(),
    );
    assert!(oauth::is_rate_limited_error(&rate_limited));
    assert!(oauth_failure_uses_cli_cache(&rate_limited));
    assert!(oauth_failure_uses_cli_cache(&ProviderError::OAuthRevoked(
        "revoked".to_string()
    )));
    // Other transient failures and plain expiry still probe the CLI.
    assert!(!oauth_failure_uses_cli_cache(
        &ProviderError::OAuthTransient("connection reset".to_string())
    ));
    assert!(!oauth_failure_uses_cli_cache(&ProviderError::OAuth(
        "expired".to_string()
    )));
    assert!(!oauth_failure_uses_cli_cache(&ProviderError::AuthRequired));
}

/// Serializes the tests that use the global CLI result cache.
static CLI_CACHE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[test]
fn cli_result_cache_round_trips() {
    let _guard = CLI_CACHE_TEST_LOCK.blocking_lock();
    let mut result = ProviderFetchResult::new(UsageSnapshot::new(RateWindow::new(42.0)), "cli");
    result.has_successful_claude_cli_quota = true;
    cache_cli_result(result.clone());
    let cached = cached_cli_result().expect("cached result within TTL");
    assert!((cached.usage.primary.used_percent - 42.0).abs() < 0.01);
    assert_eq!(cached.source_label, "cli");
    assert!(!cached.has_successful_claude_cli_quota);

    // A live non-CLI success clears the cache.
    clear_cli_result_cache();
    assert!(cached_cli_result().is_none());
}

// ── Upstream #4155: CLI timeout resilience ───────────────────────────────

/// Run `probe_cli_with_retry` over scripted outcomes. Returns the result
/// and the timeout each probe call received, in order.
async fn run_scripted_cli_probe(
    started: Instant,
    outcomes: Vec<Result<String, ProviderError>>,
) -> (Result<String, ProviderError>, Vec<Duration>) {
    let calls = std::cell::RefCell::new(Vec::new());
    let outcomes = std::cell::RefCell::new(std::collections::VecDeque::from(outcomes));
    let result = probe_cli_with_retry(started, |timeout| {
        calls.borrow_mut().push(timeout);
        let outcome = outcomes
            .borrow_mut()
            .pop_front()
            .expect("probe called more times than scripted");
        async move { outcome }
    })
    .await;
    (result, calls.into_inner())
}

#[tokio::test]
async fn cli_probe_timeout_retries_once_with_longer_timeout() {
    let (result, calls) = run_scripted_cli_probe(
        Instant::now(),
        vec![
            Err(ProviderError::Timeout),
            Ok("Current session 12% used".to_string()),
        ],
    )
    .await;

    assert_eq!(
        result.expect("longer retry succeeds"),
        "Current session 12% used"
    );
    assert_eq!(
        calls,
        vec![CLAUDE_CLI_PROBE_TIMEOUT, CLAUDE_CLI_RETRY_PROBE_TIMEOUT]
    );
}

#[tokio::test]
async fn cli_probe_retries_at_most_once() {
    let (result, calls) = run_scripted_cli_probe(
        Instant::now(),
        vec![Err(ProviderError::Timeout), Err(ProviderError::Timeout)],
    )
    .await;

    assert!(matches!(result, Err(ProviderError::Timeout)));
    assert_eq!(calls.len(), 2);
}

#[tokio::test]
async fn cli_probe_does_not_retry_non_retryable_failures() {
    let cases: [fn() -> ProviderError; 3] = [
        || ProviderError::AuthRequired,
        || ProviderError::OAuthExpired("Token expired. Run `claude login` to refresh.".into()),
        || ProviderError::Parse("Claude CLI did not return usage data".to_string()),
    ];
    for make_error in cases {
        let expected = make_error().to_string();
        let (result, calls) = run_scripted_cli_probe(Instant::now(), vec![Err(make_error())]).await;

        assert_eq!(result.unwrap_err().to_string(), expected);
        assert_eq!(calls, vec![CLAUDE_CLI_PROBE_TIMEOUT], "{expected}");
    }
}

#[test]
fn cli_probe_retryable_errors_match_upstream_set() {
    assert!(is_retryable_cli_probe_error(&ProviderError::Timeout));
    assert!(is_retryable_cli_probe_error(&ProviderError::Other(
        "Claude CLI failed: Command timed out".to_string()
    )));
    assert!(is_retryable_cli_probe_error(&ProviderError::Parse(
        "Claude CLI /usage still loading usage".to_string()
    )));
    assert!(!is_retryable_cli_probe_error(&ProviderError::AuthRequired));
    assert!(!is_retryable_cli_probe_error(&ProviderError::OAuth(
        "Authentication error. Run `claude login`.".to_string()
    )));
    assert!(!is_retryable_cli_probe_error(&ProviderError::Parse(
        "Claude CLI did not return usage data".to_string()
    )));
}

#[test]
fn cli_usage_still_loading_checks_only_the_latest_panel() {
    let loading = "Claude Code v2.1.29\n22:47 | Opus 4.5 | 0%\n\nSettings:  Status   Config   Usage  (tab to cycle)\nLoading usage data…\nEsc to cancel\n";
    assert!(claude_cli_usage_still_loading(loading));

    let retained = "Settings:  Status   Config   Usage  (tab to cycle)\nCurrent session\n15% used\n\nSettings:  Status   Config   Usage  (tab to cycle)\nLoading usage data…\nEsc to cancel\n";
    assert!(claude_cli_usage_still_loading(retained));

    let rendered =
        "Settings:StatusConfigUsage(tabtocycle)\nLoadingusagedata...\nCurrentsession\n6%used\n";
    assert!(!claude_cli_usage_still_loading(rendered));
    assert!(!claude_cli_usage_still_loading("Current session 12% used"));
}

#[tokio::test]
async fn cli_probe_loading_stall_retries_with_longer_timeout() {
    let (result, calls) = run_scripted_cli_probe(
        Instant::now(),
        vec![
            Err(ProviderError::Parse(
                "Claude CLI /usage is still loading usage data.".to_string(),
            )),
            Ok("Current session 12% used".to_string()),
        ],
    )
    .await;

    assert_eq!(result.expect("retry succeeds"), "Current session 12% used");
    assert_eq!(
        calls,
        vec![CLAUDE_CLI_PROBE_TIMEOUT, CLAUDE_CLI_RETRY_PROBE_TIMEOUT]
    );
}

#[test]
fn cli_retry_timeout_is_capped_by_the_fetch_budget() {
    // Fresh fetch: the full longer timeout.
    assert_eq!(
        cli_retry_timeout(Duration::ZERO),
        Some(CLAUDE_CLI_RETRY_PROBE_TIMEOUT)
    );
    // 75 s budget - 26 s spent - 5 s margin = 44 s left for the retry.
    assert_eq!(
        cli_retry_timeout(Duration::from_secs(26)),
        Some(Duration::from_secs(44))
    );
    // Exactly the minimum useful retry is still allowed.
    assert_eq!(
        cli_retry_timeout(Duration::from_secs(55)),
        Some(CLAUDE_CLI_MIN_RETRY_TIMEOUT)
    );
    // Below the minimum, or past the budget, no retry at all.
    assert_eq!(cli_retry_timeout(Duration::from_secs(56)), None);
    assert_eq!(cli_retry_timeout(Duration::from_secs(80)), None);
    // The worst single-retry case still ends inside the shell budget.
    let elapsed = Duration::from_secs(26);
    let retry = cli_retry_timeout(elapsed).expect("retry fits");
    assert!(elapsed + retry + CLAUDE_FETCH_BUDGET_MARGIN <= CLAUDE_FETCH_BUDGET);
}

#[tokio::test]
async fn cli_probe_failure_keeps_cached_cli_result_as_stale_fallback() {
    let _guard = CLI_CACHE_TEST_LOCK.lock().await;
    cache_cli_result(ProviderFetchResult::new(
        UsageSnapshot::new(RateWindow::new(42.0)),
        "cli",
    ));

    // Every attempt times out: the probe reports the failure, and the
    // retained CLI result stays available for the stale fallback.
    let (result, _) = run_scripted_cli_probe(
        Instant::now(),
        vec![Err(ProviderError::Timeout), Err(ProviderError::Timeout)],
    )
    .await;
    assert!(matches!(result, Err(ProviderError::Timeout)));

    let stale = cached_cli_result().expect("retained CLI result survives failed probes");
    assert!((stale.usage.primary.used_percent - 42.0).abs() < 0.01);
    assert!(!stale.has_successful_claude_cli_quota);
    clear_cli_result_cache();
}

#[tokio::test]
async fn cli_probe_timeout_returns_stale_cached_cli_result() {
    let _guard = CLI_CACHE_TEST_LOCK.lock().await;
    let mut live = ProviderFetchResult::new(UsageSnapshot::new(RateWindow::new(42.0)), "cli");
    live.has_successful_claude_cli_quota = true;
    cache_cli_result(live);

    let (probe, _) = run_scripted_cli_probe(
        Instant::now(),
        vec![Err(ProviderError::Timeout), Err(ProviderError::Timeout)],
    )
    .await;
    let cli_result: Result<ProviderFetchResult, ProviderError> =
        probe.map(|_| unreachable!("every scripted probe times out"));

    let stale = stale_cli_result_on_probe_timeout(&cli_result)
        .expect("timeout with a retained CLI result falls back to it");
    assert!((stale.usage.primary.used_percent - 42.0).abs() < 0.01);
    assert_eq!(stale.source_label, "cli");
    assert!(!stale.has_successful_claude_cli_quota);
    clear_cli_result_cache();
}

#[test]
fn live_oauth_or_web_success_drops_retained_cli_result() {
    let _guard = CLI_CACHE_TEST_LOCK.blocking_lock();
    let timeout: Result<ProviderFetchResult, ProviderError> = Err(ProviderError::Timeout);

    for source in ["OAuth", "Web"] {
        cache_cli_result(ProviderFetchResult::new(
            UsageSnapshot::new(RateWindow::new(42.0)),
            "cli",
        ));
        let live = ProviderFetchResult::new(UsageSnapshot::new(RateWindow::new(10.0)), "oauth");
        let mut failures = Vec::new();
        let recorded = record_auto_source(&mut failures, source, Ok(live))
            .expect("live success is not a failure")
            .expect("live success yields a result");
        let returned = live_auto_success(recorded);

        assert!((returned.usage.primary.used_percent - 10.0).abs() < 0.01);
        assert!(cached_cli_result().is_none(), "{source}");
        assert!(
            stale_cli_result_on_probe_timeout(&timeout).is_none(),
            "{source}"
        );
    }
}

#[test]
fn revoked_oauth_failure_keeps_retained_cli_result() {
    let _guard = CLI_CACHE_TEST_LOCK.blocking_lock();
    cache_cli_result(ProviderFetchResult::new(
        UsageSnapshot::new(RateWindow::new(42.0)),
        "cli",
    ));

    let revoked = ProviderError::OAuthRevoked("token revoked".to_string());
    assert!(oauth_failure_uses_cli_cache(&revoked));
    let mut failures = Vec::new();
    let outcome = record_auto_source(&mut failures, "OAuth", Err(revoked));
    assert!(matches!(outcome, Ok(None)));
    assert!(cached_cli_result().is_some());
    clear_cli_result_cache();
}

#[tokio::test]
async fn cli_probe_timeout_without_cache_still_propagates() {
    let _guard = CLI_CACHE_TEST_LOCK.lock().await;
    clear_cli_result_cache();

    let (probe, _) = run_scripted_cli_probe(
        Instant::now(),
        vec![Err(ProviderError::Timeout), Err(ProviderError::Timeout)],
    )
    .await;
    let cli_result: Result<ProviderFetchResult, ProviderError> =
        probe.map(|_| unreachable!("every scripted probe times out"));

    assert!(stale_cli_result_on_probe_timeout(&cli_result).is_none());
    let mut failures = Vec::new();
    let outcome = record_auto_source(&mut failures, "CLI", cli_result);
    assert!(matches!(outcome, Err(ProviderError::Timeout)));
    assert!(failures.is_empty());
}

#[tokio::test]
async fn cli_auth_failure_skips_timeout_fallback_and_is_recorded() {
    let _guard = CLI_CACHE_TEST_LOCK.lock().await;
    cache_cli_result(ProviderFetchResult::new(
        UsageSnapshot::new(RateWindow::new(42.0)),
        "cli",
    ));

    let (probe, _) =
        run_scripted_cli_probe(Instant::now(), vec![Err(ProviderError::AuthRequired)]).await;
    let cli_result: Result<ProviderFetchResult, ProviderError> =
        probe.map(|_| unreachable!("the scripted probe fails"));

    assert!(stale_cli_result_on_probe_timeout(&cli_result).is_none());
    let mut failures = Vec::new();
    let outcome = record_auto_source(&mut failures, "CLI", cli_result);
    assert!(matches!(outcome, Ok(None)));
    assert_eq!(failures.len(), 1);
    assert!(matches!(failures[0], ("CLI", ProviderError::AuthRequired)));
    clear_cli_result_cache();
}

#[test]
fn cli_quota_without_credential_identity_cannot_prove_account_action() {
    let result = mark_live_claude_cli_result(parse_ok(
        "Current session\n25% used\nCurrent week (all models)\n40% used",
    ));

    assert!(result.usage.account_email.is_none());
    assert!(result.has_successful_claude_cli_quota);
}

#[test]
fn non_cli_fetch_result_does_not_prove_account_action() {
    let result = ProviderFetchResult::new(UsageSnapshot::new(RateWindow::new(42.0)), "oauth");

    assert!(!result.has_successful_claude_cli_quota);
}
#[test]
fn error_states_and_last_good_policies() {
    use crate::core::ProviderStateKind;
    let provider = ClaudeProvider::new();
    // `true` checks the free function on the rendered text; `false` the
    // provider method. Each row keeps the path its original test used.
    type Row = (
        ProviderError,
        ProviderStateKind,
        Option<(LastGoodFailurePolicy, bool)>,
    );
    let rows: [Row; 6] = [
        (
            ProviderError::NotInstalled(
                "Claude CLI not found. Install from https://docs.claude.ai/claude-code".to_string(),
            ),
            ProviderStateKind::LocalRuntimeOffline,
            None,
        ),
        (
            ProviderError::AuthRequired,
            ProviderStateKind::NeedsAuthentication,
            None,
        ),
        (ProviderError::OAuthTransient(
        "OAuth error: Claude OAuth usage endpoint is rate limited. Retrying in about 1s; credentials were preserved."
            .to_string(),
    ), ProviderStateKind::Unknown, Some((LastGoodFailurePolicy::Preserve, false))),
        (ProviderError::OAuthTransient(
        "Claude OAuth token expired and token refresh is cooling down after a failed attempt. Please retry shortly, or run `claude login`."
            .to_string(),
    ), ProviderStateKind::Unknown, Some((LastGoodFailurePolicy::Preserve, false))),
        (ProviderError::OAuth(
        "Claude OAuth credentials not found. Run `claude` to authenticate.".to_string(),
    ), ProviderStateKind::NeedsAuthentication, Some((LastGoodFailurePolicy::Replace, true))),
        (ProviderError::OAuth("OAuth API returned rate limited".to_string()), ProviderStateKind::NeedsAuthentication, Some((LastGoodFailurePolicy::Replace, false))),
    ];
    for (error, state, policy) in rows {
        assert_eq!(provider.error_state_kind(&error), state, "{error}");
        match policy {
            Some((expected, true)) => assert_eq!(
                last_good_failure_policy_for_error(&error.to_string()),
                expected
            ),
            Some((expected, false)) => assert_eq!(
                provider.last_good_failure_policy_for_error(&error),
                expected,
                "{error}"
            ),
            None => {}
        }
    }
}

/// Upstream #4503: default and API accounts open Platform usage; recognized
/// Pro, Max, Team and Ultra subscriptions keep the claude.ai usage page.
#[test]
fn dashboard_url_opens_platform_usage_unless_account_is_subscription() {
    const PLATFORM: &str = "https://platform.claude.com/usage";
    const SUBSCRIPTION: &str = "https://claude.ai/settings/usage";
    let provider = ClaudeProvider::new();

    for login in [
        None,
        Some("Claude (OAuth)"),
        Some("Claude (CLI)"),
        Some("Admin API"),
        Some("Claude Enterprise"),
    ] {
        assert_eq!(
            provider.dashboard_url_for_login_method(login),
            Some(PLATFORM),
            "{login:?}"
        );
    }

    for login in [
        "Claude Pro",
        "Claude Max 5x",
        "Claude Max 20x",
        "Claude Team",
        "Claude Ultra",
        "Claude Max Account",
    ] {
        assert_eq!(
            provider.dashboard_url_for_login_method(Some(login)),
            Some(SUBSCRIPTION),
            "{login}"
        );
    }
}

/// Mirrors upstream `ClaudePlan.fromCompatibilityLoginMethod` ordering: the
/// words are checked in a fixed priority order (Max, Pro, Team, Enterprise,
/// Ultra) and the first match decides, so Max wins over Enterprise and
/// "Claude Enterprise Max" counts as a subscription. Enterprise alone does not.
#[test]
fn subscription_login_method_follows_upstream_word_ordering() {
    assert!(!is_subscription_login_method(None));
    assert!(!is_subscription_login_method(Some("")));
    assert!(!is_subscription_login_method(Some("Claude (OAuth)")));
    assert!(!is_subscription_login_method(Some("Claude Enterprise")));
    assert!(is_subscription_login_method(Some("Claude Enterprise Max")));
    assert!(is_subscription_login_method(Some("claude-max")));
    assert!(is_subscription_login_method(Some("CLAUDE PRO")));
    assert!(!is_subscription_login_method(Some("Maximum API")));
}
