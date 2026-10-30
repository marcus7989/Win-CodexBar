//! `/usage` and `/cost` data route handlers.
//!
//! Moved verbatim from the pre-0.48.0 serve module; the only 0.48.0 change is
//! the additive `daily` field on `/cost` — the web dashboard's daily spend bar
//! charts ride this array (upstream #2722 fetches `/cost` for the same data).

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::cli::usage::ProviderSelection;
use crate::core::{
    CostScanOptions, FetchContext, ProviderFetchResult, ProviderId, SourceMode,
    instantiate_provider, provider_pace_json,
};
use crate::cost_scanner::{self, CostScanner};

use super::json_response;

pub async fn usage_response(provider: Option<&str>, source: Option<&str>) -> String {
    let selection = match ProviderSelection::from_arg(provider) {
        Ok(selection) => selection,
        Err(error) => {
            return json_response(400, json!({ "error": error.to_string() }));
        }
    };
    // Optional `source=auto|oauth|web|cli` lets a client (or a test bench) pin
    // one fetch path instead of the auto cascade.
    let source_mode = match source {
        None => SourceMode::Auto,
        Some(raw) => match SourceMode::parse(raw) {
            Some(mode) => mode,
            None => {
                return json_response(400, json!({ "error": format!("unknown source: {raw}") }));
            }
        },
    };
    let ctx = FetchContext {
        source_mode,
        include_credits: true,
        web_timeout: 60,
        verbose: false,
        manual_cookie_header: None,
        api_key: None,
        workspace_id: None,
        api_region: None,
        gateway_url: None,
        auto_prefer_web: false,
        // Serve `/usage` is a background poll read: keep the short optional-
        // join grace (upstream #2583), unlike `codexbar usage` which blocks
        // for the full completeness window.
        requires_optional_usage_completeness: false,
    };

    let mut results = Vec::new();
    for provider_id in selection.as_list() {
        let provider = instantiate_provider(provider_id);
        match provider.fetch_usage(&ctx).await {
            Ok(result) => results.push(usage_item(provider_id, &result, None)),
            Err(error) => results.push(json!({
                "provider": provider_id.cli_name(),
                "error": error.to_string(),
            })),
        }
    }
    json_response(200, serde_json::Value::Array(results))
}

/// One provider's `/usage` entry. `pace` is present only where a window has
/// one, in the shape of CodexBar's own `serve`; VibeTV reads it from here.
fn usage_item(
    provider_id: ProviderId,
    result: &ProviderFetchResult,
    now: Option<DateTime<Utc>>,
) -> serde_json::Value {
    let mut item = json!({
        "provider": provider_id.cli_name(),
        "source": result.source_label,
        "usage": result.usage,
        "cost": result.cost,
    });
    if let Some(pace) = provider_pace_json(provider_id, &result.usage, now) {
        item["pace"] = pace;
    }
    item
}

pub async fn cost_response(provider: Option<&str>) -> String {
    let selection = match ProviderSelection::from_arg(provider) {
        Ok(selection) => selection,
        Err(error) => {
            return json_response(400, json!({ "error": error.to_string() }));
        }
    };
    let scanner = CostScanner::new(30).with_options(CostScanOptions::app_driven());
    let mut results = Vec::new();
    for provider_id in selection.as_list() {
        if provider_id == ProviderId::Antigravity {
            let history = crate::providers::antigravity::local_sessions::summarize(30);
            results.push(crate::spend_contract::local_token_history_json(
                "antigravity",
                history,
                30,
            ));
            continue;
        }
        let (supported, summary) = match provider_id {
            ProviderId::Codex => (true, scanner.scan_codex()),
            ProviderId::Claude => (true, scanner.scan_claude()),
            _ => (false, Default::default()),
        };
        if supported {
            // Daily spend history for the dashboard bar charts. The debounced
            // helper reuses the cache the summary scan just warmed, so no
            // second disk walk happens per request.
            let daily = daily_json(cost_scanner::get_daily_cost_history(
                provider_id.cli_name(),
                30,
            ));
            results.push(json!({
                "provider": provider_id.cli_name(),
                "supported": true,
                "days_scanned": 30,
                "cost": {
                    "total_usd": summary.total_cost_usd,
                    "currency": "USD"
                },
                "daily": daily,
                "tokens": {
                    "input": summary.input_tokens,
                    "output": summary.output_tokens,
                    "cached": summary.cached_tokens
                },
                "sessions_count": summary.sessions_count,
                "by_model": summary.by_model,
            }));
        } else {
            results.push(json!({
                "provider": provider_id.cli_name(),
                "supported": false,
                "error": "Local cost scanning not available for this provider"
            }));
        }
    }
    json_response(200, serde_json::Value::Array(results))
}

/// Dashboard-charts shape for one provider's daily spend: [{date, totalCost}].
fn daily_json(daily: Vec<(String, Option<f64>)>) -> serde_json::Value {
    serde_json::Value::Array(
        daily
            .into_iter()
            .map(|(date, cost_usd)| json!({ "date": date, "totalCost": cost_usd }))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{RateWindow, UsageSnapshot};

    /// Codex and Claude entries of the CodexBar 0.63.0 (macOS) `serve`
    /// `/usage` recording VibeTV tests against, cut down to the usage windows
    /// and the pace.
    const MAC_SERVE_USAGE: &str =
        include_str!("fixtures/codexbar-macos-0.63.0-serve-usage-pace.json");

    fn recorded_window(window: &serde_json::Value) -> Option<RateWindow> {
        if window.is_null() {
            return None;
        }
        Some(RateWindow::with_details(
            window["usedPercent"].as_f64().unwrap(),
            window["windowMinutes"]
                .as_u64()
                .map(|minutes| u32::try_from(minutes).unwrap()),
            window["resetsAt"].as_str().map(|at| at.parse().unwrap()),
            None,
        ))
    }

    /// The recording has no clock of its own. Each entry is taken half a
    /// second into the second its `updatedAt` names; the recorded ETA only
    /// fits a moment between 08:30:18.26 and 08:30:19.02.
    fn recorded_entry(provider: &str) -> (serde_json::Value, ProviderFetchResult, DateTime<Utc>) {
        let entries: serde_json::Value = serde_json::from_str(MAC_SERVE_USAGE).unwrap();
        let entry = entries
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["provider"] == provider)
            .unwrap()
            .clone();
        let usage = &entry["usage"];
        // Upstream's absent session is `primary: null`; here it is the
        // informational placeholder.
        let primary =
            recorded_window(&usage["primary"]).unwrap_or_else(RateWindow::no_active_session);
        let mut snapshot = UsageSnapshot::new(primary);
        if let Some(secondary) = recorded_window(&usage["secondary"]) {
            snapshot = snapshot.with_secondary(secondary);
        }
        let updated_at: DateTime<Utc> = usage["updatedAt"].as_str().unwrap().parse().unwrap();
        let now = updated_at + chrono::Duration::milliseconds(500);
        let result = ProviderFetchResult::new(snapshot, entry["source"].as_str().unwrap());
        (entry, result, now)
    }

    fn assert_same_pace(got: &serde_json::Value, want: &serde_json::Value, lane: &str) {
        let (got, want) = (got.as_object().unwrap(), want.as_object().unwrap());
        assert_eq!(
            got.keys().collect::<Vec<_>>(),
            want.keys().collect::<Vec<_>>(),
            "{lane}: field names"
        );
        for (field, value) in want {
            assert_eq!(&got[field], value, "{lane}.{field}");
        }
    }

    #[test]
    fn usage_item_carries_the_pace_of_both_windows_in_the_mac_shape() {
        let (recorded, result, now) = recorded_entry("claude");
        let item = usage_item(ProviderId::Claude, &result, Some(now));
        let (got, want) = (&item["pace"], &recorded["pace"]);
        assert_eq!(got.as_object().unwrap().len(), 2);
        assert_same_pace(&got["primary"], &want["primary"], "primary");
        assert_same_pace(&got["secondary"], &want["secondary"], "secondary");
        // Spelled out once, so a changed fixture cannot hide a changed shape.
        assert_eq!(
            got["primary"],
            json!({
                "deltaPercent": -25,
                "expectedUsedPercent": 33,
                "stage": "farBehind",
                "summary": "25% in reserve | Expected 33% used | Lasts until reset",
                "willLastToReset": true
            })
        );
        assert_eq!(item["provider"], "claude");
        assert!(item["usage"].is_object());
    }

    #[test]
    fn usage_item_carries_the_eta_of_a_window_that_runs_out() {
        let (recorded, result, now) = recorded_entry("codex");
        let item = usage_item(ProviderId::Codex, &result, Some(now));
        let got = item["pace"].as_object().unwrap();
        // Weekly-only plan: no session lane, as in the recording.
        assert_eq!(got.keys().collect::<Vec<_>>(), ["secondary"]);
        assert_same_pace(
            &got["secondary"],
            &recorded["pace"]["secondary"],
            "secondary",
        );
        assert_eq!(got["secondary"]["etaSeconds"], json!(230_241));
        assert_eq!(got["secondary"]["stage"], "farAhead");
    }

    #[test]
    fn usage_item_leaves_out_the_pace_of_a_window_without_reset() {
        // The recorded Claude reading, its session without a reset time.
        let (recorded, mut result, now) = recorded_entry("claude");
        result.usage.primary.resets_at = None;
        let item = usage_item(ProviderId::Claude, &result, Some(now));
        assert!(item["pace"].get("primary").is_none());
        assert_same_pace(
            &item["pace"]["secondary"],
            &recorded["pace"]["secondary"],
            "secondary",
        );

        // No window with a reset time: no `pace` key at all.
        let bare = ProviderFetchResult::new(
            UsageSnapshot::new(RateWindow::new(40.0)).with_secondary(RateWindow::new(40.0)),
            "oauth",
        );
        let item = usage_item(ProviderId::Claude, &bare, Some(now));
        assert!(item.get("pace").is_none());
        assert!(item["usage"].is_object());
        assert_eq!(item["source"], "oauth");
    }

    #[test]
    fn daily_array_shape_matches_dashboard_charts_contract() {
        let daily = daily_json(vec![
            ("2026-08-07".to_string(), Some(0.0)),
            ("2026-08-08".to_string(), Some(4.25)),
            ("2026-08-09".to_string(), None),
        ]);
        let rows = daily.as_array().unwrap();
        assert_eq!(rows[0]["date"], "2026-08-07");
        assert_eq!(rows[1]["totalCost"], 4.25);
        assert_eq!(rows[0]["totalCost"], 0.0);
        assert!(rows[2]["totalCost"].is_null());
    }

    #[test]
    fn antigravity_cost_payload_is_token_only_and_preserves_partial_unknown() {
        use crate::spend_contract::{LocalHistoryCoverage, LocalTokenHistorySummary};
        let complete = crate::spend_contract::local_token_history_json(
            "antigravity",
            LocalTokenHistorySummary {
                total_tokens: 42,
                session_count: 1,
                coverage: LocalHistoryCoverage::Complete,
            },
            30,
        );
        assert!(complete["cost"]["total_usd"].is_null());
        assert_eq!(complete["tokens"]["total"], 42);
        assert_eq!(complete["historyCoverage"], "complete");

        let partial = crate::spend_contract::local_token_history_json(
            "antigravity",
            LocalTokenHistorySummary {
                total_tokens: 42,
                session_count: 1,
                coverage: LocalHistoryCoverage::Partial,
            },
            30,
        );
        assert!(partial["tokens"]["total"].is_null());
        assert_eq!(partial["historyCoverage"], "partial");
    }
    #[test]
    fn daily_rows_use_upstream_total_cost_key_only() {
        let daily = daily_json(vec![
            ("2026-08-07".to_string(), Some(0.0)),
            ("2026-08-08".to_string(), Some(4.25)),
            ("2026-08-09".to_string(), None),
        ]);
        let serialized = daily.to_string();
        assert!(
            serialized.contains("\"totalCost\""),
            "wire key is totalCost"
        );
        assert!(
            !serialized.contains("cost_usd") && !serialized.contains("costUSD"),
            "no stale daily cost keys may leak to the wire"
        );
    }

    #[test]
    fn daily_empty_array_has_no_rows() {
        let daily = daily_json(vec![]);
        assert_eq!(daily.as_array().unwrap().len(), 0);
    }

    #[test]
    fn daily_zero_values_are_preserved_not_filtered() {
        let daily = daily_json(vec![("2026-08-07".to_string(), Some(0.0))]);
        let rows = daily.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["totalCost"], 0.0);
    }
}
