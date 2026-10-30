//! Config command implementation
//!
//! Utilities for validating and inspecting configuration.

use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use std::path::Path;

use crate::core::{ProviderId, TokenAccountStore, instantiate_provider};
use crate::settings::{ApiKeys, ManualCookies, Settings};

/// Arguments for the config command
#[derive(Parser, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Validate configuration files
    Validate,
    /// Dump configuration to stdout
    Dump {
        /// Output format: json or toml
        #[arg(short, long, default_value = "json")]
        format: String,
        /// Include raw secrets (default: redact)
        #[arg(long = "show-secrets", default_value_t = false)]
        show_secrets: bool,
    },
    /// List providers and enabled state
    Providers,
    /// Enable a provider
    Enable {
        /// Provider CLI name or alias
        provider: String,
    },
    /// Disable a provider
    Disable {
        /// Provider CLI name or alias
        provider: String,
    },
    /// Sign in to a provider
    Login {
        /// Provider CLI name
        #[arg(long)]
        provider: String,
        /// Emit machine-readable device authorization details
        #[arg(long)]
        json: bool,
    },
    /// Store an API key for a provider
    SetApiKey {
        /// Provider CLI name or alias
        provider: String,
        /// API key to store
        #[arg(long = "api-key")]
        api_key: Option<String>,
        /// Read API key from stdin
        #[arg(long)]
        stdin: bool,
        /// Store the key without enabling the provider
        #[arg(long = "no-enable")]
        no_enable: bool,
    },
    /// Show configuration file paths
    Path,
}

/// Run the config command
pub async fn run(args: ConfigArgs) -> anyhow::Result<()> {
    match args.command {
        ConfigCommand::Validate => validate_config().await,
        ConfigCommand::Dump {
            format,
            show_secrets,
        } => dump_config(&format, show_secrets).await,
        ConfigCommand::Providers => list_providers().await,
        ConfigCommand::Enable { provider } => set_provider_enabled(&provider, true).await,
        ConfigCommand::Disable { provider } => set_provider_enabled(&provider, false).await,
        ConfigCommand::Login { provider, json } => login(&provider, json).await,
        ConfigCommand::SetApiKey {
            provider,
            api_key,
            stdin,
            no_enable,
        } => set_api_key(&provider, api_key.as_deref(), stdin, !no_enable).await,
        ConfigCommand::Path => show_paths().await,
    }
}

async fn login(provider: &str, json: bool) -> anyhow::Result<()> {
    if parse_provider(provider)? != ProviderId::Copilot {
        anyhow::bail!("Device login is only supported for copilot.");
    }
    let flow = crate::providers::copilot::device_flow::CopilotDeviceFlow::new();
    let device = flow.request_device_code().await?;
    write_device_code(&mut std::io::stdout().lock(), &device, json)?;
    let token = flow
        .wait_for_token(&device.device_code, device.interval, device.expires_in)
        .await?;
    let identity = crate::providers::copilot::CopilotApi::new()
        .fetch_identity_with_token(&token, None)
        .await
        .ok();
    store_copilot_token(&TokenAccountStore::new(), token, identity)?;
    Ok(())
}

fn write_device_code(
    out: &mut impl std::io::Write,
    device: &crate::providers::copilot::device_flow::DeviceCodeResponse,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        writeln!(
            out,
            "{}",
            serde_json::json!({
                "verificationURI": device.verification_uri,
                "userCode": device.user_code,
                "expiresIn": device.expires_in,
                "status": "authorization_pending"
            })
        )?;
    } else {
        writeln!(
            out,
            "Visit {} and enter code {}.",
            device.verification_uri, device.user_code
        )?;
    }
    out.flush()?;
    Ok(())
}

fn store_copilot_token(
    store: &TokenAccountStore,
    token: String,
    identity: Option<crate::providers::copilot::GitHubIdentity>,
) -> anyhow::Result<()> {
    let mut data = store.load_provider(ProviderId::Copilot)?;
    let identifier = identity
        .as_ref()
        .and_then(|i| i.id)
        .map(|id| format!("github:user:{id}"));
    let label = identity
        .map(|i| i.login)
        .unwrap_or_else(|| "GitHub Copilot".to_string());
    if let Some(index) = identifier.as_ref().and_then(|id| {
        data.accounts
            .iter()
            .position(|a| a.external_identifier.as_ref() == Some(id))
    }) {
        data.accounts[index].token = token;
        data.accounts[index].label = label;
        data.accounts[index].mark_used();
        data.set_active(index);
    } else {
        let mut account = crate::core::TokenAccount::new(label, token);
        account.external_identifier = identifier;
        account.mark_used();
        data.add_account(account);
        data.set_active(data.accounts.len() - 1);
    }
    store.save_provider(ProviderId::Copilot, &data)?;
    Ok(())
}

/// Validate configuration files
async fn validate_config() -> anyhow::Result<()> {
    let mut report = ValidationReport::default();
    validate_settings_config(&mut report);
    validate_manual_cookies_config(&mut report);
    validate_token_accounts_config(&mut report);
    report.finish()
}

#[derive(Default)]
struct ValidationReport {
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl ValidationReport {
    fn error(&mut self, message: impl Into<String>) {
        self.errors.push(message.into());
    }

    fn warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    fn finish(self) -> anyhow::Result<()> {
        print_validation_summary(&self.errors, &self.warnings)
    }
}

fn validate_settings_config(report: &mut ValidationReport) {
    print!("Checking settings.json... ");
    let Some(path) = Settings::settings_path() else {
        println!("ERROR");
        report.error("settings.json: Could not determine config path");
        return;
    };

    if validate_optional_json_file::<Settings>(&path, "settings.json", report) {
        return;
    }

    println!("NOT FOUND (using defaults)");
    report.warning("settings.json: File does not exist, using defaults");
}

fn validate_manual_cookies_config(report: &mut ValidationReport) {
    print!("Checking manual_cookies.json... ");
    let Some(path) = ManualCookies::cookies_path() else {
        println!("SKIP");
        return;
    };

    if !validate_optional_json_file::<ManualCookies>(&path, "manual_cookies.json", report) {
        println!("NOT FOUND (none configured)");
    }
}

fn validate_optional_json_file<T>(path: &Path, label: &str, report: &mut ValidationReport) -> bool
where
    T: DeserializeOwned,
{
    if !path.exists() {
        return false;
    }

    match read_json_config::<T>(path) {
        Ok(()) => println!("OK"),
        Err(ConfigFileError::Read(e)) => {
            println!("ERROR");
            report.error(format!("{label}: Could not read file: {e}"));
        }
        Err(ConfigFileError::Parse(e)) => {
            println!("INVALID");
            report.error(format!("{label}: {e}"));
        }
    }

    true
}

fn read_json_config<T>(path: &Path) -> Result<(), ConfigFileError>
where
    T: DeserializeOwned,
{
    // Match the application loaders so validation supports DPAPI-protected
    // config files without materializing plaintext on disk.
    let content = crate::secure_file::read_string(path).map_err(ConfigFileError::Read)?;
    serde_json::from_str::<T>(&content)
        .map(|_| ())
        .map_err(ConfigFileError::Parse)
}

enum ConfigFileError {
    Read(std::io::Error),
    Parse(serde_json::Error),
}

fn validate_token_accounts_config(report: &mut ValidationReport) {
    print!("Checking token-accounts.json... ");
    let path = TokenAccountStore::default_path();
    if !path.exists() {
        println!("NOT FOUND (none configured)");
        return;
    }

    match TokenAccountStore::new().load() {
        Ok(_) => println!("OK"),
        Err(e) => {
            println!("INVALID");
            report.error(format!("token-accounts.json: {e}"));
        }
    }
}

fn print_validation_summary(errors: &[String], warnings: &[String]) -> anyhow::Result<()> {
    println!();
    if errors.is_empty() && warnings.is_empty() {
        println!("Configuration is valid.");
    } else {
        if !warnings.is_empty() {
            println!("Warnings:");
            for w in warnings {
                println!("  - {}", w);
            }
        }
        if !errors.is_empty() {
            println!("Errors:");
            for e in errors {
                println!("  - {}", e);
            }
            anyhow::bail!(
                "Configuration validation failed with {} error(s).",
                errors.len()
            );
        }
    }

    Ok(())
}

/// Dump configuration to stdout
async fn dump_config(format: &str, show_secrets: bool) -> anyhow::Result<()> {
    let value = build_dump_value()?;
    let value = sanitize_settings_for_dump(value, show_secrets);

    match format.to_lowercase().as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&value)?;
            println!("{}", json);
        }
        "toml" => {
            let toml = toml::to_string_pretty(&value)
                .map_err(|e| anyhow::anyhow!("Failed to convert dump to TOML: {e}"))?;
            println!("{}", toml);
        }
        _ => {
            anyhow::bail!("Unknown format '{}'. Supported formats: json, toml", format);
        }
    }

    Ok(())
}

fn build_dump_value() -> anyhow::Result<serde_json::Value> {
    let settings = Settings::load();
    let mut root = serde_json::to_value(&settings)?;

    if let Some(obj) = root.as_object_mut() {
        obj.insert(
            "api_keys".to_string(),
            serde_json::to_value(ApiKeys::load())?,
        );
        obj.insert(
            "manual_cookies".to_string(),
            serde_json::to_value(ManualCookies::load())?,
        );

        let token_accounts = TokenAccountStore::new()
            .load()
            .unwrap_or_default()
            .into_iter()
            .map(|(id, data)| (id.cli_name().to_string(), data))
            .collect::<std::collections::BTreeMap<_, _>>();
        obj.insert(
            "token_accounts".to_string(),
            serde_json::to_value(token_accounts)?,
        );
    }

    Ok(root)
}

/// Recursively redact secret-shaped fields for `config dump`.
///
/// When `show_secrets` is true the value is returned unchanged.
fn sanitize_settings_for_dump(value: serde_json::Value, show_secrets: bool) -> serde_json::Value {
    if show_secrets {
        return value;
    }
    redact_secrets_value(value)
}

fn is_secret_field_name(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| *c != '_')
        .flat_map(|c| c.to_lowercase())
        .collect();
    matches!(
        normalized.as_str(),
        "apikey"
            | "secretkey"
            | "cookieheader"
            | "manualcookieheader"
            | "token"
            | "apitoken"
            | "managementapitoken"
            | "httpproxypassword"
            | "password"
    )
}

fn redact_secrets_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, child) in map {
                if is_secret_field_name(&key) {
                    out.insert(key, serde_json::Value::String("[REDACTED]".to_string()));
                } else {
                    out.insert(key, redact_secrets_value(child));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(redact_secrets_value).collect())
        }
        other => other,
    }
}

/// List provider enabled state.
async fn list_providers() -> anyhow::Result<()> {
    let settings = Settings::load();
    for id in ProviderId::all() {
        let state = if settings.is_provider_enabled(*id) {
            "enabled"
        } else {
            "disabled"
        };
        let default_marker = if instantiate_provider(*id).metadata().default_enabled {
            " default"
        } else {
            ""
        };
        println!(
            "{}: {}{} ({})",
            id.cli_name(),
            state,
            default_marker,
            id.display_name()
        );
    }
    Ok(())
}

/// Enable or disable a provider by CLI name.
async fn set_provider_enabled(provider: &str, enabled: bool) -> anyhow::Result<()> {
    let id = parse_provider(provider)?;
    let mut settings = Settings::load();
    if enabled {
        settings.enable_provider(id);
    } else {
        settings.disable_provider(id);
    }
    settings.save()?;
    let state = if enabled { "enabled" } else { "disabled" };
    println!("Config: {state} {}", id.display_name());
    Ok(())
}

/// Store an API key and optionally enable the provider.
async fn set_api_key(
    provider: &str,
    api_key: Option<&str>,
    read_from_stdin: bool,
    enable_provider: bool,
) -> anyhow::Result<()> {
    let id = parse_provider(provider)?;
    ensure_provider_accepts_api_key(id)?;
    let api_key = resolve_api_key_input(api_key, read_from_stdin)?;

    let mut keys = ApiKeys::load();
    keys.set(id.cli_name(), &api_key, None);
    keys.save()?;

    if enable_provider {
        let mut settings = Settings::load();
        settings.enable_provider(id);
        settings.save()?;
    }

    let suffix = if enable_provider { " and enabled" } else { "" };
    println!("Config: stored API key for {}{suffix}", id.display_name());
    Ok(())
}

fn parse_provider(raw: &str) -> anyhow::Result<ProviderId> {
    ProviderId::from_cli_name(raw).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown provider '{}'. Run `codexbar config providers` to list providers.",
            raw
        )
    })
}

fn ensure_provider_accepts_api_key(id: ProviderId) -> anyhow::Result<()> {
    if crate::settings::get_api_key_providers()
        .iter()
        .any(|provider| provider.id == id)
    {
        return Ok(());
    }
    anyhow::bail!("{} does not support stored API keys.", id.display_name())
}

fn resolve_api_key_input(api_key: Option<&str>, read_from_stdin: bool) -> anyhow::Result<String> {
    if api_key.is_some() && read_from_stdin {
        anyhow::bail!("Use either --api-key or --stdin, not both.");
    }

    let raw = if read_from_stdin {
        let mut buffer = String::new();
        use std::io::Read;
        std::io::stdin().read_to_string(&mut buffer)?;
        Some(buffer)
    } else {
        api_key.map(ToString::to_string)
    };

    let mut value = raw
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Missing API key. Pass --api-key <key> or use --stdin."))?;

    if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        value.remove(0);
        value.pop();
    }

    let value = value.trim().to_string();
    if value.is_empty() {
        anyhow::bail!("Missing API key. Pass --api-key <key> or use --stdin.");
    }
    Ok(value)
}

/// Show configuration file paths
async fn show_paths() -> anyhow::Result<()> {
    println!("Configuration paths:");

    if let Some(path) = Settings::settings_path() {
        let exists = if path.exists() { "" } else { " (not found)" };
        println!("  Settings:       {}{}", path.display(), exists);
    } else {
        println!("  Settings:       (could not determine path)");
    }

    if let Some(path) = ManualCookies::cookies_path() {
        let exists = if path.exists() { "" } else { " (not found)" };
        println!("  Manual cookies: {}{}", path.display(), exists);
    } else {
        println!("  Manual cookies: (could not determine path)");
    }

    let token_path = TokenAccountStore::default_path();
    let exists = if token_path.exists() {
        ""
    } else {
        " (not found)"
    };
    println!("  Token accounts: {}{}", token_path.display(), exists);

    // Show config directory
    if let Some(config_dir) = dirs::config_dir() {
        let codexbar_dir = config_dir.join("CodexBar");
        println!();
        println!("Config directory: {}", codexbar_dir.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ConfigFileError, read_json_config, sanitize_settings_for_dump};
    #[cfg(windows)]
    use crate::secure_file;
    use crate::settings::ManualCookies;
    use serde_json::json;

    #[test]
    fn device_json_matches_mac_contract_and_hides_device_code() {
        let device = crate::providers::copilot::device_flow::DeviceCodeResponse {
            device_code: "secret-device-code".into(),
            user_code: "ABCD-1234".into(),
            verification_uri: "https://github.com/login/device".into(),
            verification_uri_complete: None,
            expires_in: 900,
            interval: 5,
        };
        let mut output = Vec::new();
        super::write_device_code(&mut output, &device, true).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap(),
            json!({
                "verificationURI": "https://github.com/login/device", "userCode": "ABCD-1234",
                "expiresIn": 900, "status": "authorization_pending"
            })
        );
        assert!(!output.contains("secret-device-code"));
    }

    #[test]
    fn login_persists_and_activates_account_without_losing_other_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::core::TokenAccountStore::with_path(dir.path().join("accounts.json"));
        let mut other = crate::core::ProviderAccountData::new();
        other.add_account(crate::core::TokenAccount::new("Other", "other-token"));
        store
            .save_provider(crate::core::ProviderId::OpenRouter, &other)
            .unwrap();
        let identity = || {
            Some(crate::providers::copilot::GitHubIdentity {
                login: "test-user".into(),
                id: Some(42),
                name: None,
            })
        };
        super::store_copilot_token(&store, "first-token".into(), identity()).unwrap();
        super::store_copilot_token(&store, "second-token".into(), identity()).unwrap();
        let data = store
            .load_provider(crate::core::ProviderId::Copilot)
            .unwrap();
        assert_eq!(data.accounts.len(), 1);
        assert_eq!(data.active_account().unwrap().token, "second-token");
        assert_eq!(
            data.active_account()
                .unwrap()
                .external_identifier
                .as_deref(),
            Some("github:user:42")
        );
        assert_eq!(
            store
                .load_provider(crate::core::ProviderId::OpenRouter)
                .unwrap()
                .active_account()
                .unwrap()
                .token,
            "other-token"
        );
    }

    #[tokio::test]
    async fn login_rejects_other_providers_before_network_access() {
        assert!(
            super::login("claude", true)
                .await
                .unwrap_err()
                .to_string()
                .contains("only supported for copilot")
        );
        assert!(
            super::login("not-a-provider", true)
                .await
                .unwrap_err()
                .to_string()
                .contains("Unknown provider")
        );
    }

    #[cfg(windows)]
    #[test]
    fn validates_dpapi_protected_manual_cookies_without_plaintext() {
        let dir = tempfile::tempdir().expect("create temporary directory");
        let path = dir.path().join("manual_cookies.json");
        let expected = r#"{"cookies":{}}"#;

        secure_file::write_string(&path, expected).expect("write protected cookies");

        let raw = std::fs::read_to_string(&path).expect("read protected wrapper");
        assert!(raw.contains("\"format\": \"codexbar.secure-file\""));
        assert!(!raw.contains(expected));
        assert!(
            read_json_config::<ManualCookies>(&path).is_ok(),
            "valid protected cookies should validate"
        );
    }

    #[test]
    fn rejects_malformed_secure_wrapper_without_echoing_payload() {
        let dir = tempfile::tempdir().expect("create temporary directory");
        let path = dir.path().join("manual_cookies.json");
        let payload = "AA==";
        let malformed = format!(
            r#"{{"format":"codexbar.secure-file","version":1,"protection":"unsupported","payload":"{payload}"}}"#
        );
        std::fs::write(&path, malformed).expect("write malformed wrapper");

        let error = read_json_config::<ManualCookies>(&path)
            .expect_err("reject malformed protected wrapper");
        let ConfigFileError::Read(error) = error else {
            panic!("malformed protected wrapper must be a read error");
        };
        let message = error.to_string();
        assert!(message.contains("unsupported secure file protection"));
        assert!(!message.contains(payload));
    }

    #[test]
    fn sanitize_settings_for_dump_redacts_secret_fields() {
        let raw = json!({
            "http_proxy_password": "proxy-secret",
            "provider_configs": {
                "claude": {
                    "manual_cookie_header": "sessionKey=abc",
                    "api_token": "tok-123",
                    "management_api_token": "management-secret"
                }
            },
            "api_keys": {
                "keys": {
                    "zai": {
                        "api_key": "cb_test_api_key_456",
                        "label": "Work",
                        "saved_at": "2026-01-01"
                    }
                }
            },
            "manual_cookies": {
                "cookies": {
                    "claude": {
                        "cookie_header": "sessionKey=secret-cookie",
                        "saved_at": "2026-01-01"
                    }
                }
            },
            "token_accounts": {
                "factory": {
                    "accounts": [{
                        "id": "11111111-1111-1111-1111-111111111111",
                        "label": "Team",
                        "token": "raw-token-value",
                        "added_at": 1
                    }]
                }
            },
            "secret_key": "top-secret"
        });

        let redacted = sanitize_settings_for_dump(raw, false);
        let text = serde_json::to_string(&redacted).expect("serialize");

        assert!(text.contains("[REDACTED]"));
        assert!(!text.contains("proxy-secret"));
        assert!(!text.contains("sessionKey=abc"));
        assert!(!text.contains("tok-123"));
        assert!(!text.contains("management-secret"));
        assert!(!text.contains("cb_test_api_key_456"));
        assert!(!text.contains("secret-cookie"));
        assert!(!text.contains("raw-token-value"));
        assert!(!text.contains("top-secret"));
        // Non-secret identity fields stay.
        assert!(text.contains("Work"));
        assert!(text.contains("Team"));
        assert!(text.contains("11111111-1111-1111-1111-111111111111"));
    }

    #[test]
    fn sanitize_settings_for_dump_show_secrets_keeps_raw() {
        let raw = json!({
            "api_key": "keep-me",
            "nested": { "token": "also-keep", "label": "Team" }
        });

        let out = sanitize_settings_for_dump(raw.clone(), true);
        assert_eq!(out, raw);
        assert_eq!(out["api_key"], "keep-me");
        assert_eq!(out["nested"]["token"], "also-keep");
    }
}
