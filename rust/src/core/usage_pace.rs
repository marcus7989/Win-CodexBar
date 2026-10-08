//! Usage Pace Prediction
//!
//! Calculates whether the user is On Track, Ahead, or Behind their usage quota
//! based on elapsed time and consumption rate.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::{ProviderId, RateWindow, SESSION_WINDOW_MINUTES, UsageSnapshot, WEEKLY_WINDOW_MINUTES};

/// CodexBar's CLI leaves the pace out until this much of the window has
/// elapsed (upstream `CLIRenderer.paceMinimumExpectedPercent`).
const WIRE_MINIMUM_EXPECTED_PERCENT: f64 = 3.0;

/// Which wording a pace lane uses (upstream `ProviderPaceKind`): a session
/// window "is projected empty", a weekly window "runs out".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaceKind {
    Session,
    Weekly,
}

/// Usage pace stage indicating consumption rate relative to time
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaceStage {
    /// Within 2% of expected usage
    OnTrack,
    /// 2-6% ahead of expected
    SlightlyAhead,
    /// 6-12% ahead of expected
    Ahead,
    /// More than 12% ahead of expected
    FarAhead,
    /// 2-6% behind expected
    SlightlyBehind,
    /// 6-12% behind expected
    Behind,
    /// More than 12% behind expected
    FarBehind,
}

impl PaceStage {
    /// Get a short label for the stage
    pub fn label(&self) -> &'static str {
        match self {
            PaceStage::OnTrack => "On Track",
            PaceStage::SlightlyAhead => "Slightly Ahead",
            PaceStage::Ahead => "Ahead",
            PaceStage::FarAhead => "Far Ahead",
            PaceStage::SlightlyBehind => "Slightly Behind",
            PaceStage::Behind => "Behind",
            PaceStage::FarBehind => "Far Behind",
        }
    }

    /// Stage token on the wire, identical to upstream `UsagePace.Stage`
    /// (camelCase): what CodexBar's `usage --json` and `serve` print.
    pub fn wire_name(&self) -> &'static str {
        match self {
            PaceStage::OnTrack => "onTrack",
            PaceStage::SlightlyAhead => "slightlyAhead",
            PaceStage::Ahead => "ahead",
            PaceStage::FarAhead => "farAhead",
            PaceStage::SlightlyBehind => "slightlyBehind",
            PaceStage::Behind => "behind",
            PaceStage::FarBehind => "farBehind",
        }
    }

    /// Get an emoji indicator for the stage
    pub fn emoji(&self) -> &'static str {
        match self {
            PaceStage::OnTrack => "✓",
            PaceStage::SlightlyAhead | PaceStage::Ahead | PaceStage::FarAhead => "⚡",
            PaceStage::SlightlyBehind | PaceStage::Behind | PaceStage::FarBehind => "🐢",
        }
    }

    /// Whether the user is consuming faster than expected
    pub fn is_ahead(&self) -> bool {
        matches!(
            self,
            PaceStage::SlightlyAhead | PaceStage::Ahead | PaceStage::FarAhead
        )
    }

    /// Whether the user is consuming slower than expected
    pub fn is_behind(&self) -> bool {
        matches!(
            self,
            PaceStage::SlightlyBehind | PaceStage::Behind | PaceStage::FarBehind
        )
    }
}

/// Usage pace prediction result
#[derive(Debug, Clone)]
pub struct UsagePace {
    /// The pace stage
    pub stage: PaceStage,
    /// Delta between actual and expected usage (positive = ahead)
    pub delta_percent: f64,
    /// Expected usage percent based on elapsed time
    pub expected_used_percent: f64,
    /// Actual usage percent
    pub actual_used_percent: f64,
    /// Estimated time until quota is exhausted (if ahead of pace)
    pub eta_seconds: Option<f64>,
    /// Whether current pace will last until reset
    pub will_last_to_reset: bool,
}

impl UsagePace {
    /// Calculate weekly usage pace
    ///
    /// # Arguments
    /// * `window` - The rate window to analyze
    /// * `now` - Current time (defaults to Utc::now())
    /// * `default_window_minutes` - Default window duration if not specified (10080 = 7 days)
    pub fn weekly(
        window: &RateWindow,
        now: Option<DateTime<Utc>>,
        default_window_minutes: u32,
    ) -> Option<Self> {
        let now = now.unwrap_or_else(Utc::now);
        let resets_at = window.resets_at?;
        let minutes = window.window_minutes.unwrap_or(default_window_minutes);

        if minutes == 0 {
            return None;
        }

        let duration_secs = f64::from(minutes) * 60.0;
        // Sub-second precision, as upstream's `timeIntervalSince`: whole
        // seconds shift a rounded ETA by one.
        #[allow(
            clippy::cast_precision_loss,
            reason = "milliseconds until a reset are far below f64's exact range"
        )]
        let time_until_reset = (resets_at - now).num_milliseconds() as f64 / 1000.0;

        // Must be before reset and within the window duration
        if time_until_reset <= 0.0 || time_until_reset > duration_secs {
            return None;
        }

        let elapsed = Self::clamp(duration_secs - time_until_reset, 0.0, duration_secs);
        let expected = Self::clamp((elapsed / duration_secs) * 100.0, 0.0, 100.0);
        let actual = Self::clamp(window.used_percent, 0.0, 100.0);

        // If no time has elapsed but there's usage, something's wrong
        if elapsed == 0.0 && actual > 0.0 {
            return None;
        }

        let delta = actual - expected;
        let stage = Self::stage_for_delta(delta);

        let mut eta_seconds = None;
        let mut will_last_to_reset = false;

        if elapsed > 0.0 && actual > 0.0 {
            let rate = actual / elapsed; // percent per second
            if rate > 0.0 {
                let remaining = (100.0 - actual).max(0.0);
                let candidate = remaining / rate;
                if candidate >= time_until_reset {
                    will_last_to_reset = true;
                } else {
                    eta_seconds = Some(candidate);
                }
            }
        } else if elapsed > 0.0 && actual == 0.0 {
            // No usage yet, will definitely last
            will_last_to_reset = true;
        }

        Some(UsagePace {
            stage,
            delta_percent: delta,
            expected_used_percent: expected,
            actual_used_percent: actual,
            eta_seconds,
            will_last_to_reset,
        })
    }

    /// Calculate the stage for a given delta percentage
    fn stage_for_delta(delta: f64) -> PaceStage {
        let abs_delta = delta.abs();

        if abs_delta <= 2.0 {
            PaceStage::OnTrack
        } else if abs_delta <= 6.0 {
            if delta >= 0.0 {
                PaceStage::SlightlyAhead
            } else {
                PaceStage::SlightlyBehind
            }
        } else if abs_delta <= 12.0 {
            if delta >= 0.0 {
                PaceStage::Ahead
            } else {
                PaceStage::Behind
            }
        } else if delta >= 0.0 {
            PaceStage::FarAhead
        } else {
            PaceStage::FarBehind
        }
    }

    fn clamp(value: f64, lower: f64, upper: f64) -> f64 {
        value.clamp(lower, upper)
    }

    /// Format the ETA as a human-readable string
    pub fn format_eta(&self) -> Option<String> {
        let secs = self.eta_seconds?;
        // Display-only ETA breakdown; whole hours/minutes by design.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "display-only ETA; whole hours/minutes by design"
        )]
        let hours = (secs / 3600.0) as i64;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "display-only ETA; whole hours/minutes by design"
        )]
        let minutes = ((secs % 3600.0) / 60.0) as i64;

        if hours > 24 {
            let days = hours / 24;
            Some(format!("{}d {}h", days, hours % 24))
        } else if hours > 0 {
            Some(format!("{}h {}m", hours, minutes))
        } else {
            Some(format!("{}m", minutes))
        }
    }

    /// Format the pace as a status line
    pub fn format_status(&self) -> String {
        let stage_text = self.stage.label();

        if self.will_last_to_reset {
            format!("{} - will last to reset", stage_text)
        } else if let Some(eta) = self.format_eta() {
            format!("{} - exhausted in {}", stage_text, eta)
        } else {
            stage_text.to_string()
        }
    }

    /// Pace of one usage lane as CodexBar's CLI reports it, or `None` where
    /// CodexBar reports none: no reset time, a row that is no quota, nothing
    /// left in the window, or
    /// less than 3% of the window elapsed (upstream `CLIRenderer.computePace`).
    pub fn for_wire(
        window: &RateWindow,
        kind: PaceKind,
        now: Option<DateTime<Utc>>,
    ) -> Option<Self> {
        if window.is_informational || window.used_percent >= 100.0 {
            return None;
        }
        let default_minutes = match kind {
            PaceKind::Session => SESSION_WINDOW_MINUTES,
            PaceKind::Weekly => WEEKLY_WINDOW_MINUTES,
        };
        let pace = Self::weekly(window, now, default_minutes)?;
        (pace.expected_used_percent >= WIRE_MINIMUM_EXPECTED_PERCENT).then_some(pace)
    }

    /// How many times faster the window could be used and still last to its
    /// reset (upstream `speedMultiplierToReset`). Time left over time elapsed
    /// equals `(100 - expected) / expected`, so the stored fields suffice.
    fn speed_multiplier_to_reset(&self) -> Option<f64> {
        if self.expected_used_percent <= 0.0 {
            return None;
        }
        let projected_remaining_usage = self.actual_used_percent
            * (100.0 - self.expected_used_percent)
            / self.expected_used_percent;
        let remaining_capacity = 100.0 - self.actual_used_percent;
        if remaining_capacity <= 0.0 || projected_remaining_usage <= 0.0 {
            return None;
        }
        let multiplier = remaining_capacity / projected_remaining_usage;
        multiplier.is_finite().then_some(multiplier)
    }

    /// The one-line summary of CodexBar's CLI:
    /// `25% in reserve | Expected 33% used | Lasts until reset`.
    pub fn wire_summary(&self, kind: PaceKind, shows_headroom_hint: bool) -> String {
        let delta = round_to_i64(self.delta_percent.abs());
        let left = if self.stage.is_ahead() {
            format!("{delta}% in deficit")
        } else if self.stage.is_behind() {
            format!("{delta}% in reserve")
        } else {
            "On pace".to_string()
        };
        let mut parts = vec![
            left,
            format!(
                "Expected {}% used",
                round_to_i64(self.expected_used_percent)
            ),
        ];
        if self.will_last_to_reset {
            parts.push("Lasts until reset".to_string());
            if shows_headroom_hint
                && self.delta_percent < -15.0
                && self.speed_multiplier_to_reset().is_some_and(|m| m >= 1.5)
            {
                parts.push("1.5× headroom".to_string());
            }
        } else if let Some(eta) = self.eta_seconds {
            let text = wire_countdown(eta);
            parts.push(match (kind, text) {
                (PaceKind::Session, None) => "Projected empty now".to_string(),
                (PaceKind::Session, Some(text)) => format!("Projected empty in {text}"),
                (PaceKind::Weekly, None) => "Runs out now".to_string(),
                (PaceKind::Weekly, Some(text)) => format!("Runs out in {text}"),
            });
        }
        parts.join(" | ")
    }

    /// One lane's pace in the JSON shape of CodexBar's CLI (`PacePayload`):
    /// whole-number percents, `etaSeconds` only where the quota runs out
    /// before the reset.
    pub fn wire_json(&self, kind: PaceKind, shows_headroom_hint: bool) -> Value {
        let mut out = Map::new();
        out.insert("stage".into(), json!(self.stage.wire_name()));
        out.insert(
            "deltaPercent".into(),
            json!(round_to_i64(self.delta_percent)),
        );
        out.insert(
            "expectedUsedPercent".into(),
            json!(round_to_i64(self.expected_used_percent)),
        );
        out.insert("willLastToReset".into(), json!(self.will_last_to_reset));
        if let Some(eta) = self.eta_seconds {
            out.insert("etaSeconds".into(), json!(round_to_i64(eta)));
        }
        out.insert(
            "summary".into(),
            json!(self.wire_summary(kind, shows_headroom_hint)),
        );
        Value::Object(out)
    }
}

/// A provider's `pace` object as CodexBar's `usage --json` and `serve`
/// `/usage` print it: one entry per lane that has a pace, keyed `primary`
/// (session) and `secondary` (weekly). `None` when no lane has one, so the
/// caller leaves the key out, as CodexBar does.
///
/// The session lane counts only for a window of at most five hours, the
/// weekly lane for whatever the provider reports as its second window.
pub fn provider_pace_json(
    provider: ProviderId,
    usage: &UsageSnapshot,
    now: Option<DateTime<Utc>>,
) -> Option<Value> {
    // Upstream shows the headroom hint for Codex only.
    let shows_headroom_hint = provider == ProviderId::Codex;
    let lane = |window: &RateWindow, kind: PaceKind| {
        UsagePace::for_wire(window, kind, now).map(|pace| pace.wire_json(kind, shows_headroom_hint))
    };

    let mut out = Map::new();
    let is_session = usage
        .primary
        .window_minutes
        .is_some_and(|minutes| minutes <= SESSION_WINDOW_MINUTES);
    if is_session && let Some(pace) = lane(&usage.primary, PaceKind::Session) {
        out.insert("primary".into(), pace);
    }
    if let Some(pace) = usage
        .secondary
        .as_ref()
        .and_then(|window| lane(window, PaceKind::Weekly))
    {
        out.insert("secondary".into(), pace);
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

/// Rounds half away from zero, as Swift's `rounded()`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "percents and ETA seconds of one usage window fit an i64 by far"
)]
fn round_to_i64(value: f64) -> i64 {
    value.round() as i64
}

/// Upstream `UsageFormatter.resetCountdownDescription` without its "in ":
/// minutes rounded up, two units at most. `None` stands for "now".
fn wire_countdown(seconds: f64) -> Option<String> {
    if seconds < 1.0 {
        return None;
    }
    let total_minutes = round_to_i64((seconds / 60.0).ceil()).max(1);
    let days = total_minutes / (24 * 60);
    let hours = (total_minutes / 60) % 24;
    let minutes = total_minutes % 60;
    Some(if days > 0 {
        if hours > 0 {
            format!("{days}d {hours}h")
        } else if minutes > 0 {
            format!("{days}d {minutes}m")
        } else {
            format!("{days}d")
        }
    } else if hours > 0 {
        if minutes > 0 {
            format!("{hours}h {minutes}m")
        } else {
            format!("{hours}h")
        }
    } else {
        format!("{total_minutes}m")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_stage_for_delta() {
        assert_eq!(UsagePace::stage_for_delta(0.0), PaceStage::OnTrack);
        assert_eq!(UsagePace::stage_for_delta(1.5), PaceStage::OnTrack);
        assert_eq!(UsagePace::stage_for_delta(-1.5), PaceStage::OnTrack);

        assert_eq!(UsagePace::stage_for_delta(4.0), PaceStage::SlightlyAhead);
        assert_eq!(UsagePace::stage_for_delta(-4.0), PaceStage::SlightlyBehind);

        assert_eq!(UsagePace::stage_for_delta(10.0), PaceStage::Ahead);
        assert_eq!(UsagePace::stage_for_delta(-10.0), PaceStage::Behind);

        assert_eq!(UsagePace::stage_for_delta(20.0), PaceStage::FarAhead);
        assert_eq!(UsagePace::stage_for_delta(-20.0), PaceStage::FarBehind);
    }

    #[test]
    fn test_pace_calculation() {
        let now = Utc::now();
        // Window resets in 3.5 days (halfway through a 7-day window)
        let resets_at = now + Duration::days(3) + Duration::hours(12);

        // User has used 50% - exactly on track
        let window = RateWindow::with_details(50.0, Some(10080), Some(resets_at), None);
        let pace = UsagePace::weekly(&window, Some(now), 10080).unwrap();

        assert_eq!(pace.stage, PaceStage::OnTrack);
        assert!(pace.delta_percent.abs() < 2.0);
    }

    #[test]
    fn test_pace_ahead() {
        let now = Utc::now();
        // Window resets in 3.5 days (halfway through a 7-day window)
        let resets_at = now + Duration::days(3) + Duration::hours(12);

        // User has used 80% - way ahead of schedule
        let window = RateWindow::with_details(80.0, Some(10080), Some(resets_at), None);
        let pace = UsagePace::weekly(&window, Some(now), 10080).unwrap();

        assert!(pace.stage.is_ahead());
        assert!(pace.delta_percent > 0.0);
    }

    #[test]
    fn test_pace_labels() {
        assert_eq!(PaceStage::OnTrack.label(), "On Track");
        assert_eq!(PaceStage::FarAhead.label(), "Far Ahead");
        assert_eq!(PaceStage::SlightlyBehind.emoji(), "🐢");
    }

    fn at(text: &str) -> DateTime<Utc> {
        text.parse().unwrap()
    }

    /// A weekly window `elapsed_percent` through, `used` percent spent.
    fn weekly_window(now: DateTime<Utc>, elapsed_percent: i64, used: f64) -> RateWindow {
        let resets_at = now + Duration::minutes(10080 * (100 - elapsed_percent) / 100);
        RateWindow::with_details(used, Some(10080), Some(resets_at), None)
    }

    #[test]
    fn wire_json_names_every_stage_as_upstream_does() {
        let now = at("2026-09-21T08:00:00Z");
        for (used, stage, delta, summary_start) in [
            (50.0, "onTrack", 0, "On pace"),
            (54.0, "slightlyAhead", 4, "4% in deficit"),
            (60.0, "ahead", 10, "10% in deficit"),
            (70.0, "farAhead", 20, "20% in deficit"),
            (46.0, "slightlyBehind", -4, "4% in reserve"),
            (40.0, "behind", -10, "10% in reserve"),
            (30.0, "farBehind", -20, "20% in reserve"),
        ] {
            let pace =
                UsagePace::for_wire(&weekly_window(now, 50, used), PaceKind::Weekly, Some(now))
                    .unwrap()
                    .wire_json(PaceKind::Weekly, false);
            assert_eq!(pace["stage"], stage);
            assert_eq!(pace["deltaPercent"], json!(delta));
            assert_eq!(pace["expectedUsedPercent"], json!(50));
            let summary = pace["summary"].as_str().unwrap();
            assert!(summary.starts_with(summary_start), "{stage}: {summary}");
            assert!(
                summary.contains(" | Expected 50% used"),
                "{stage}: {summary}"
            );
        }
    }

    #[test]
    fn wire_json_has_an_eta_only_where_the_quota_runs_out_first() {
        let now = at("2026-09-21T08:00:00Z");
        // 70% spent at half time: empty after 3.5 d * 30 / 70 = 1.5 d.
        let deficit =
            UsagePace::for_wire(&weekly_window(now, 50, 70.0), PaceKind::Weekly, Some(now))
                .unwrap()
                .wire_json(PaceKind::Weekly, false);
        assert_eq!(deficit["etaSeconds"], json!(129_600));
        assert_eq!(deficit["willLastToReset"], json!(false));
        assert_eq!(
            deficit["summary"],
            "20% in deficit | Expected 50% used | Runs out in 1d 12h"
        );

        let reserve =
            UsagePace::for_wire(&weekly_window(now, 50, 30.0), PaceKind::Weekly, Some(now))
                .unwrap()
                .wire_json(PaceKind::Weekly, false);
        assert!(reserve.get("etaSeconds").is_none());
        assert_eq!(reserve["willLastToReset"], json!(true));
        assert_eq!(
            reserve["summary"],
            "20% in reserve | Expected 50% used | Lasts until reset"
        );
        let keys: Vec<&str> = reserve
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "deltaPercent",
                "expectedUsedPercent",
                "stage",
                "summary",
                "willLastToReset"
            ]
        );
    }

    #[test]
    fn wire_summary_words_a_session_and_the_codex_headroom_as_upstream_does() {
        let now = at("2026-09-21T08:00:00Z");
        // A 5-hour session, half over, 80% spent: empty in 150 min * 20 / 80.
        let session =
            RateWindow::with_details(80.0, Some(300), Some(now + Duration::minutes(150)), None);
        let pace = UsagePace::for_wire(&session, PaceKind::Session, Some(now)).unwrap();
        assert_eq!(
            pace.wire_summary(PaceKind::Session, false),
            "30% in deficit | Expected 50% used | Projected empty in 38m"
        );

        // 20% spent at half time leaves room for four times the speed.
        let reserve =
            UsagePace::for_wire(&weekly_window(now, 50, 20.0), PaceKind::Weekly, Some(now))
                .unwrap();
        assert_eq!(
            reserve.wire_summary(PaceKind::Weekly, true),
            "30% in reserve | Expected 50% used | Lasts until reset | 1.5× headroom"
        );
        assert_eq!(
            reserve.wire_summary(PaceKind::Weekly, false),
            "30% in reserve | Expected 50% used | Lasts until reset"
        );
        // 40% at half time lasts, but only 1.5 times: 10% reserve is no hint.
        let tight = UsagePace::for_wire(&weekly_window(now, 50, 40.0), PaceKind::Weekly, Some(now))
            .unwrap();
        assert_eq!(
            tight.wire_summary(PaceKind::Weekly, true),
            "10% in reserve | Expected 50% used | Lasts until reset"
        );
    }

    #[test]
    fn wire_countdown_matches_upstream_reset_countdown() {
        assert_eq!(wire_countdown(0.4), None);
        assert_eq!(wire_countdown(1.0).as_deref(), Some("1m"));
        assert_eq!(wire_countdown(61.0).as_deref(), Some("2m"));
        assert_eq!(wire_countdown(3600.0).as_deref(), Some("1h"));
        assert_eq!(wire_countdown(5400.0).as_deref(), Some("1h 30m"));
        assert_eq!(wire_countdown(86_400.0).as_deref(), Some("1d"));
        assert_eq!(wire_countdown(87_000.0).as_deref(), Some("1d 10m"));
        // The two ETAs of the recorded CodexBar 0.63.0 payloads.
        assert_eq!(wire_countdown(230_241.0).as_deref(), Some("2d 15h"));
        assert_eq!(wire_countdown(205_121.0).as_deref(), Some("2d 8h"));
    }

    #[test]
    fn for_wire_reports_no_pace_where_upstream_reports_none() {
        let now = at("2026-09-21T08:00:00Z");
        let no_reset = RateWindow::with_details(40.0, Some(10080), None, None);
        assert!(UsagePace::for_wire(&no_reset, PaceKind::Weekly, Some(now)).is_none());
        let exhausted = weekly_window(now, 50, 100.0);
        assert!(UsagePace::for_wire(&exhausted, PaceKind::Weekly, Some(now)).is_none());
        let just_started = weekly_window(now, 2, 1.0);
        assert!(UsagePace::for_wire(&just_started, PaceKind::Weekly, Some(now)).is_none());
        let reset_passed =
            RateWindow::with_details(40.0, Some(10080), Some(now - Duration::minutes(1)), None);
        assert!(UsagePace::for_wire(&reset_passed, PaceKind::Weekly, Some(now)).is_none());
        let mut placeholder = weekly_window(now, 50, 0.0);
        placeholder.is_informational = true;
        assert!(UsagePace::for_wire(&placeholder, PaceKind::Weekly, Some(now)).is_none());
    }

    #[test]
    fn provider_pace_json_keys_the_session_and_the_weekly_lane() {
        let now = at("2026-09-21T08:00:00Z");
        let session =
            RateWindow::with_details(10.0, Some(300), Some(now + Duration::minutes(150)), None);
        let both = UsageSnapshot::new(session.clone()).with_secondary(weekly_window(now, 50, 70.0));
        let pace = provider_pace_json(ProviderId::Claude, &both, Some(now)).unwrap();
        assert_eq!(pace["primary"]["stage"], "farBehind");
        assert_eq!(pace["secondary"]["stage"], "farAhead");
        assert_eq!(pace.as_object().unwrap().len(), 2);

        // A weekly window without a reset time: that lane is left out.
        let weekly_without_reset = UsageSnapshot::new(session)
            .with_secondary(RateWindow::with_details(70.0, Some(10080), None, None));
        let pace =
            provider_pace_json(ProviderId::Claude, &weekly_without_reset, Some(now)).unwrap();
        assert!(pace.get("secondary").is_none());
        assert!(pace.get("primary").is_some());

        // A first window that is no session (a month) has no session pace.
        let monthly = UsageSnapshot::new(RateWindow::with_details(
            10.0,
            Some(43_200),
            Some(now + Duration::days(10)),
            None,
        ));
        assert!(provider_pace_json(ProviderId::Cursor, &monthly, Some(now)).is_none());

        // No reset anywhere: no `pace` at all.
        let bare = UsageSnapshot::new(RateWindow::new(40.0)).with_secondary(RateWindow::new(40.0));
        assert!(provider_pace_json(ProviderId::Codex, &bare, Some(now)).is_none());
    }
}
