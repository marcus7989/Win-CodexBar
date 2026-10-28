//! Windsurf provider implementation.
//!
//! Reads Windsurf's cached plan information from its VS Code-style SQLite
//! state database. Devin Desktop (the renamed Windsurf) writes to
//! `%APPDATA%\Devin\User\globalStorage\state.vscdb`; the old
//! `%APPDATA%\Windsurf\...` database is read only when no Devin one exists.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags, types::Value as SqlValue};
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::core::{
    FetchContext, Provider, ProviderError, ProviderFetchResult, ProviderId, ProviderMetadata,
    RateWindow, SourceMode, UsageSnapshot,
};

const STATE_KEY: &str = "windsurf.settings.cachedPlanInfo";
/// Devin Desktop keeps one flat plan cache per account under this prefix.
const DEVIN_STATE_KEY_PREFIX: &str = "windsurf.reactSettings.cachedPlanInfoData:";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedPlanInfo {
    plan_name: Option<String>,
    end_timestamp: Option<i64>,
    usage: Option<WindsurfUsage>,
    quota_usage: Option<QuotaUsage>,
    // Devin Desktop's flat format.
    remaining_messages: Option<i64>,
    total_messages: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WindsurfUsage {
    messages: Option<i64>,
    used_messages: Option<i64>,
    remaining_messages: Option<i64>,
    flow_actions: Option<i64>,
    used_flow_actions: Option<i64>,
    remaining_flow_actions: Option<i64>,
    flex_credits: Option<i64>,
    used_flex_credits: Option<i64>,
    remaining_flex_credits: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuotaUsage {
    daily_remaining_percent: Option<f64>,
    weekly_remaining_percent: Option<f64>,
    daily_reset_at_unix: Option<i64>,
    weekly_reset_at_unix: Option<i64>,
}

pub struct WindsurfProvider {
    metadata: ProviderMetadata,
}

impl WindsurfProvider {
    pub fn new() -> Self {
        Self {
            metadata: ProviderMetadata {
                id: ProviderId::Windsurf,
                display_name: "Windsurf",
                session_label: "Daily",
                weekly_label: "Weekly",
                supports_opus: false,
                supports_credits: false,
                default_enabled: false,
                is_primary: false,
                dashboard_url: Some("https://windsurf.com/subscription"),
                status_page_url: Some("https://status.windsurf.com"),
            },
        }
    }

    fn default_db_path() -> Option<PathBuf> {
        if let Ok(path) = std::env::var("WINDSURF_STATE_DB")
            && !path.trim().is_empty()
        {
            return Some(PathBuf::from(path));
        }
        dirs::data_dir().map(|base| Self::db_path_in(&base))
    }

    fn db_path_in(base: &Path) -> PathBuf {
        let state_db = |folder: &str| {
            base.join(folder)
                .join("User")
                .join("globalStorage")
                .join("state.vscdb")
        };
        let devin = state_db("Devin");
        if devin.exists() {
            devin
        } else {
            state_db("Windsurf")
        }
    }

    fn read_cached_plan(db_path: PathBuf) -> Result<CachedPlanInfo, ProviderError> {
        if !db_path.exists() {
            return Err(ProviderError::NotInstalled(format!(
                "Windsurf database not found at {}. Open Devin Desktop (or Windsurf) and sign in first.",
                db_path.display()
            )));
        }

        let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| ProviderError::Other(format!("Failed to open Windsurf database: {e}")))?;
        conn.busy_timeout(std::time::Duration::from_millis(250))
            .map_err(|e| {
                ProviderError::Other(format!("Failed to configure SQLite timeout: {e}"))
            })?;

        let values = conn
            .prepare("SELECT value FROM ItemTable WHERE key = ?1 OR key LIKE ?2")
            .and_then(|mut stmt| {
                stmt.query_map([STATE_KEY, &format!("{DEVIN_STATE_KEY_PREFIX}%")], |row| {
                    row.get::<_, SqlValue>(0)
                })?
                .collect::<Result<Vec<_>, _>>()
            })
            .map_err(|e| {
                ProviderError::Other(format!("Failed to read Windsurf plan cache: {e}"))
            })?;
        // Which cached account is signed in is not recorded next to the cache,
        // so several of them stay unavailable instead of being guessed.
        let [value] = <[SqlValue; 1]>::try_from(values).map_err(|values| {
            if values.is_empty() {
                ProviderError::AuthRequired
            } else {
                ProviderError::Other(
                    "Windsurf plan cache holds several accounts; cannot tell which is active"
                        .to_string(),
                )
            }
        })?;

        let json_text = decode_json_value(value).ok_or_else(|| {
            ProviderError::Parse("Windsurf plan cache is not valid UTF-8/UTF-16 JSON".to_string())
        })?;

        serde_json::from_str::<CachedPlanInfo>(&json_text)
            .map_err(|e| ProviderError::Parse(format!("Failed to parse Windsurf plan cache: {e}")))
    }

    fn snapshot_from_plan(plan: CachedPlanInfo) -> Result<UsageSnapshot, ProviderError> {
        let mut primary = None;
        let mut secondary = None;

        if let Some(quota) = plan.quota_usage {
            if let Some(daily) = quota.daily_remaining_percent {
                primary = Some(window_from_remaining_percent(
                    daily,
                    quota.daily_reset_at_unix,
                ));
            }
            if let Some(weekly) = quota.weekly_remaining_percent {
                secondary = Some(window_from_remaining_percent(
                    weekly,
                    quota.weekly_reset_at_unix,
                ));
            }
        }

        if let Some(usage) = plan.usage {
            if primary.is_none() {
                primary = usage_window(
                    usage.used_messages,
                    usage.remaining_messages,
                    usage.messages,
                    "messages",
                );
            }
            if secondary.is_none() {
                secondary = usage_window(
                    usage.used_flow_actions,
                    usage.remaining_flow_actions,
                    usage.flow_actions,
                    "flow actions",
                );
            }
            if let Some(flex) = usage_window(
                usage.used_flex_credits,
                usage.remaining_flex_credits,
                usage.flex_credits,
                "flex credits",
            ) {
                let had_primary = primary.is_some();
                let mut snapshot = UsageSnapshot::new(primary.unwrap_or_else(|| flex.clone()));
                if let Some(secondary) = secondary {
                    snapshot = snapshot.with_secondary(secondary);
                }
                if had_primary {
                    snapshot = snapshot.with_extra_rate_window("flex", "Flex Credits", flex);
                }
                return Ok(with_identity(snapshot, plan.plan_name, plan.end_timestamp));
            }
        }

        if primary.is_none() {
            primary = usage_window(
                None,
                plan.remaining_messages,
                plan.total_messages,
                "messages",
            );
        }

        if primary.is_none() && secondary.is_none() {
            return Err(ProviderError::Parse(
                "Windsurf plan cache has no quota details".to_string(),
            ));
        }
        let mut snapshot = UsageSnapshot::new(primary.unwrap_or_else(|| {
            RateWindow::informational("No cached Windsurf daily quota details")
        }));
        if let Some(secondary) = secondary {
            snapshot = snapshot.with_secondary(secondary);
        }
        Ok(with_identity(snapshot, plan.plan_name, plan.end_timestamp))
    }
}

impl Default for WindsurfProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Provider for WindsurfProvider {
    fn id(&self) -> ProviderId {
        ProviderId::Windsurf
    }

    fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }

    async fn fetch_usage(&self, ctx: &FetchContext) -> Result<ProviderFetchResult, ProviderError> {
        match ctx.source_mode {
            SourceMode::Auto | SourceMode::Cli => {
                let path = Self::default_db_path().ok_or_else(|| {
                    ProviderError::NotInstalled(
                        "Could not resolve Windsurf application data path.".to_string(),
                    )
                })?;
                let plan = Self::read_cached_plan(path)?;
                Ok(ProviderFetchResult::new(
                    Self::snapshot_from_plan(plan)?,
                    "local cache",
                ))
            }
            SourceMode::OAuth | SourceMode::Web => {
                Err(ProviderError::UnsupportedSource(ctx.source_mode))
            }
        }
    }

    fn available_sources(&self) -> Vec<SourceMode> {
        vec![SourceMode::Auto, SourceMode::Cli]
    }

    fn supports_cli(&self) -> bool {
        true
    }
}

fn decode_json_value(value: SqlValue) -> Option<String> {
    match value {
        SqlValue::Text(text) => valid_json_text(&text),
        SqlValue::Blob(bytes) => decode_json_blob(&bytes),
        _ => None,
    }
}

fn decode_json_blob(value: &[u8]) -> Option<String> {
    if let Ok(text) = std::str::from_utf8(value)
        && let Some(json) = valid_json_text(text)
    {
        return Some(json);
    }

    if value.len().is_multiple_of(2) {
        let utf16: Vec<u16> = value
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        if let Ok(text) = String::from_utf16(&utf16)
            && let Some(json) = valid_json_text(&text)
        {
            return Some(json);
        }
    }

    None
}

fn valid_json_text(text: &str) -> Option<String> {
    let trimmed = text.trim_matches(char::from(0)).trim();
    if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
        return Some(trimmed.to_string());
    }
    None
}

fn window_from_remaining_percent(remaining: f64, reset_unix: Option<i64>) -> RateWindow {
    let resets_at = reset_unix.and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0));
    // Reset countdowns are localized at render time; keep cached snapshots language-neutral.
    RateWindow::with_details((100.0 - remaining).clamp(0.0, 100.0), None, resets_at, None)
}

fn usage_window(
    raw_used: Option<i64>,
    raw_remaining: Option<i64>,
    raw_total: Option<i64>,
    unit: &str,
) -> Option<RateWindow> {
    let total = raw_total?;
    if total <= 0 {
        return None;
    }
    let used = raw_used.or_else(|| raw_remaining.map(|remaining| total - remaining))?;
    let clamped_used = used.clamp(0, total);
    let percent = clamped_used as f64 / total as f64 * 100.0;
    let mut window = RateWindow::new(percent);
    window.reset_description = Some(format!("{clamped_used} / {total} {unit}"));
    Some(window)
}

fn with_identity(
    mut snapshot: UsageSnapshot,
    plan_name: Option<String>,
    end_timestamp: Option<i64>,
) -> UsageSnapshot {
    if let Some(plan) = plan_name.filter(|v| !v.trim().is_empty()) {
        snapshot = snapshot.with_login_method(plan);
    }
    if let Some(end) = end_timestamp.and_then(DateTime::<Utc>::from_timestamp_millis) {
        snapshot = snapshot.with_organization(format!("Expires {}", end.format("%Y-%m-%d")));
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_snapshot_from_quota_usage() {
        let snapshot = WindsurfProvider::snapshot_from_plan(CachedPlanInfo {
            plan_name: Some("Pro".into()),
            end_timestamp: Some(1_800_000_000_000),
            usage: None,
            quota_usage: Some(QuotaUsage {
                daily_remaining_percent: Some(80.0),
                weekly_remaining_percent: Some(25.0),
                daily_reset_at_unix: None,
                weekly_reset_at_unix: None,
            }),
            remaining_messages: None,
            total_messages: None,
        })
        .expect("snapshot");

        assert_eq!(snapshot.primary.used_percent, 20.0);
        assert_eq!(
            snapshot.secondary.as_ref().map(|w| w.used_percent),
            Some(75.0)
        );
        assert_eq!(snapshot.login_method.as_deref(), Some("Pro"));
    }

    #[test]
    fn decodes_utf16_state_value() {
        let json = r#"{"planName":"Free"}"#;
        let bytes: Vec<u8> = json.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        assert_eq!(decode_json_blob(&bytes).as_deref(), Some(json));
    }

    #[test]
    fn decodes_sql_text_state_value() {
        let json = r#"{"planName":"Teams"}"#;

        assert_eq!(
            decode_json_value(SqlValue::Text(json.to_string())).as_deref(),
            Some(json)
        );
    }

    #[test]
    fn quota_window_with_resets_at_has_no_pre_localized_description() {
        let future = Utc::now() + chrono::Duration::hours(4);
        let window = window_from_remaining_percent(80.0, Some(future.timestamp()));

        assert!(window.resets_at.is_some());
        assert!(
            window.reset_description.is_none(),
            "reset_description should be None when resets_at is present, got {:?}",
            window.reset_description
        );
    }

    #[test]
    fn usage_window_keeps_raw_unit_description() {
        let window = usage_window(Some(5), Some(5), Some(10), "messages").unwrap();

        assert_eq!(window.reset_description.as_deref(), Some("5 / 10 messages"));
    }
}

#[cfg(test)]
mod missing_usage_tests {
    use super::*;

    fn plan(usage: Option<WindsurfUsage>, quota_usage: Option<QuotaUsage>) -> CachedPlanInfo {
        CachedPlanInfo {
            plan_name: Some("Pro".into()),
            end_timestamp: None,
            usage,
            quota_usage,
            remaining_messages: None,
            total_messages: None,
        }
    }

    #[test]
    fn plan_without_a_quota_is_an_error_not_zero_percent() {
        assert!(WindsurfProvider::snapshot_from_plan(plan(None, None)).is_err());
    }

    #[test]
    fn weekly_only_plan_keeps_daily_unavailable() {
        let snapshot = WindsurfProvider::snapshot_from_plan(plan(
            None,
            Some(QuotaUsage {
                daily_remaining_percent: None,
                weekly_remaining_percent: Some(25.0),
                daily_reset_at_unix: None,
                weekly_reset_at_unix: None,
            }),
        ))
        .expect("snapshot");
        assert!(snapshot.primary.is_informational);
        assert_eq!(snapshot.secondary.map(|w| w.used_percent), Some(75.0));
    }

    #[test]
    fn real_zero_usage_stays_a_quota() {
        let snapshot = WindsurfProvider::snapshot_from_plan(plan(
            None,
            Some(QuotaUsage {
                daily_remaining_percent: Some(100.0),
                weekly_remaining_percent: None,
                daily_reset_at_unix: None,
                weekly_reset_at_unix: None,
            }),
        ))
        .expect("snapshot");
        assert!(!snapshot.primary.is_informational);
        assert_eq!(snapshot.primary.used_percent, 0.0);
    }
}

/// Provisional: the flat Devin Desktop format is taken from the Devin Desktop
/// 3.11.228 package (key and field names), not from a signed-in Windows
/// database. Value types and the meaning of the totals are unconfirmed.
#[cfg(test)]
mod devin_cache_tests {
    use super::*;
    use std::path::Path;

    const DEVIN_KEY_PREFIX: &str = "windsurf.reactSettings.cachedPlanInfoData:";

    fn state_db(base: &Path, folder: &str, rows: &[(&str, &str)]) -> PathBuf {
        let dir = base.join(folder).join("User").join("globalStorage");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.vscdb");
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)",
            [],
        )
        .unwrap();
        for (key, value) in rows {
            conn.execute(
                "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
                [key, value],
            )
            .unwrap();
        }
        path
    }

    fn read(path: PathBuf) -> Result<UsageSnapshot, ProviderError> {
        WindsurfProvider::read_cached_plan(path).and_then(WindsurfProvider::snapshot_from_plan)
    }

    #[test]
    fn flat_message_counters_become_the_primary_quota() {
        let base = tempfile::tempdir().unwrap();
        let path = state_db(
            base.path(),
            "Devin",
            &[(
                &format!("{DEVIN_KEY_PREFIX}user-1"),
                r#"{"planName":"Pro","endTimestamp":1800000000000,"remainingMessages":40,"totalMessages":100}"#,
            )],
        );

        let snapshot = read(path).expect("snapshot");

        assert!(!snapshot.primary.is_informational);
        assert_eq!(snapshot.primary.used_percent, 60.0);
        assert_eq!(
            snapshot.primary.reset_description.as_deref(),
            Some("60 / 100 messages")
        );
        assert!(snapshot.primary.resets_at.is_none());
        assert!(snapshot.secondary.is_none());
        assert_eq!(snapshot.login_method.as_deref(), Some("Pro"));
    }

    #[test]
    fn flat_cache_without_a_message_total_is_an_error() {
        for json in [
            r#"{"planName":"Pro"}"#,
            r#"{"planName":"Pro","remainingMessages":40}"#,
            r#"{"planName":"Pro","totalMessages":100}"#,
            r#"{"planName":"Pro","totalMessages":0,"remainingMessages":0}"#,
            r#"{"planName":"Pro","acuConsumed":3.5,"acuLimit":10,"dollarsConsumed":1,"dollarsLimit":20}"#,
        ] {
            let base = tempfile::tempdir().unwrap();
            let path = state_db(
                base.path(),
                "Devin",
                &[(&format!("{DEVIN_KEY_PREFIX}user-1"), json)],
            );
            assert!(read(path).is_err(), "must not invent a quota for {json}");
        }
    }

    #[test]
    fn several_account_caches_are_not_guessed() {
        let base = tempfile::tempdir().unwrap();
        let flat = r#"{"planName":"Pro","remainingMessages":40,"totalMessages":100}"#;
        let path = state_db(
            base.path(),
            "Devin",
            &[
                (&format!("{DEVIN_KEY_PREFIX}user-1"), flat),
                (&format!("{DEVIN_KEY_PREFIX}user-2"), flat),
            ],
        );

        assert!(WindsurfProvider::read_cached_plan(path).is_err());
    }

    #[test]
    fn devin_database_without_a_plan_cache_needs_sign_in() {
        let base = tempfile::tempdir().unwrap();
        let path = state_db(base.path(), "Devin", &[("something.else", "{}")]);

        assert!(matches!(
            WindsurfProvider::read_cached_plan(path),
            Err(ProviderError::AuthRequired)
        ));
    }

    #[test]
    fn the_legacy_windsurf_cache_still_reads() {
        let base = tempfile::tempdir().unwrap();
        let path = state_db(
            base.path(),
            "Windsurf",
            &[(
                STATE_KEY,
                r#"{"planName":"Pro","usage":{"messages":100,"usedMessages":10}}"#,
            )],
        );

        let snapshot = read(path).expect("snapshot");

        assert_eq!(snapshot.primary.used_percent, 10.0);
    }

    #[test]
    fn the_devin_folder_wins_over_the_legacy_windsurf_folder() {
        let base = tempfile::tempdir().unwrap();
        let legacy = state_db(base.path(), "Windsurf", &[]);
        assert_eq!(WindsurfProvider::db_path_in(base.path()), legacy);

        let devin = state_db(base.path(), "Devin", &[]);
        assert_eq!(WindsurfProvider::db_path_in(base.path()), devin);
    }
}
