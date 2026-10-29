use serde::Serialize;

use crate::core::RateWindow;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowPayload {
    pub kind: String,
    pub label: String,
    pub used_percent: f64,
    pub remaining_percent: f64,
    pub reset_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Preserve the engine's measurement validity for provider and account clients.
    #[serde(skip_serializing_if = "is_false")]
    pub is_informational: bool,
    /// Display-only hint. Script clients can ignore this additive schema-v1 key.
    #[serde(skip_serializing_if = "is_false")]
    pub idle: bool,
    /// Informational or unknown lane: `used_percent` / `remaining_percent` are
    /// placeholders, not a measurement. Additive schema-v1 key.
    #[serde(skip_serializing_if = "is_false")]
    pub unavailable: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn informational_window_keeps_its_authoritative_flag() {
        let payload = make_window_with_idle(
            "session",
            "Session",
            &RateWindow::no_active_session(),
            false,
        );
        let json = serde_json::to_value(payload).unwrap();
        assert_eq!(json["isInformational"], true);
        assert_eq!(json["usedPercent"], 0.0);
        assert!(json["resetAt"].is_null());
    }

    #[test]
    fn measured_zero_without_reset_is_not_informational() {
        for kind in ["session", "weekly"] {
            let payload = make_window_with_idle(kind, kind, &RateWindow::new(0.0), false);
            let json = serde_json::to_value(payload).unwrap();
            assert!(json.get("isInformational").is_none());
            assert_eq!(json["usedPercent"], 0.0);
            assert!(json["resetAt"].is_null());
        }
    }
}

pub(super) fn make_window_with_idle(
    kind: &str,
    label: &str,
    window: &RateWindow,
    idle: bool,
) -> WindowPayload {
    let used = window.used_percent.clamp(0.0, 100.0);
    WindowPayload {
        kind: kind.to_string(),
        label: label.to_string(),
        used_percent: used,
        remaining_percent: (100.0 - used).clamp(0.0, 100.0),
        reset_at: window.resets_at,
        is_informational: window.is_informational,
        idle,
        unavailable: window.is_informational,
    }
}
