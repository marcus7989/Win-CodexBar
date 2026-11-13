//! Which claude.ai session the web path uses: the one the browser holds now,
//! not the saved header of an account or organization the user left
//! (VibeTV-shop/vibetv#697).

use super::ClaudeWebApiFetcher;
use crate::core::ProviderError;
use crate::providers::test_support::{mock_response, mock_response_expect};
use mockito::Server;
use std::cell::{Cell, RefCell};

const LIVE: &str = "sessionKey=sk-live; lastActiveOrg=org-team";
const SAVED: &str = "sessionKey=sk-saved; lastActiveOrg=org-personal";
const USAGE_BODY: &str = r#"{"five_hour": {"utilization": 11}}"#;

struct Outcome {
    result: Result<(), ProviderError>,
    stored: Option<String>,
    cleared: bool,
}

async fn run(
    server: &Server,
    live: Vec<String>,
    saved: Option<&str>,
    no_session: ProviderError,
) -> Outcome {
    let fetcher = ClaudeWebApiFetcher::new().with_base_url(server.url());
    let stored = RefCell::new(None);
    let cleared = Cell::new(false);
    let result = fetcher
        .fetch_live_session_first(
            &mut live.into_iter(),
            saved.map(str::to_string),
            |header| *stored.borrow_mut() = Some(header.to_string()),
            || cleared.set(true),
            |_| no_session,
        )
        .await
        .map(|_| ());
    Outcome {
        result,
        stored: stored.into_inner(),
        cleared: cleared.get(),
    }
}

#[tokio::test]
async fn live_browser_session_wins_over_the_saved_one() {
    let mut server = Server::new_async().await;
    let team = mock_response_expect(
        &mut server,
        "GET",
        "/organizations/org-team/usage",
        200,
        USAGE_BODY,
        1,
    )
    .await;
    let personal = mock_response_expect(
        &mut server,
        "GET",
        "/organizations/org-personal/usage",
        200,
        USAGE_BODY,
        0,
    )
    .await;

    let got = run(
        &server,
        vec![LIVE.into()],
        Some(SAVED),
        ProviderError::NoCookies,
    )
    .await;

    assert!(got.result.is_ok());
    assert_eq!(got.stored.as_deref(), Some(LIVE));
    team.assert_async().await;
    personal.assert_async().await;
}

#[tokio::test]
async fn saved_session_is_the_fallback_when_no_browser_session_is_readable() {
    let mut server = Server::new_async().await;
    let personal = mock_response_expect(
        &mut server,
        "GET",
        "/organizations/org-personal/usage",
        200,
        USAGE_BODY,
        1,
    )
    .await;

    let got = run(&server, vec![], Some(SAVED), ProviderError::NoCookies).await;

    assert!(got.result.is_ok());
    assert_eq!(got.stored, None);
    personal.assert_async().await;
}

#[tokio::test]
async fn rejected_saved_fallback_is_cleared() {
    let mut server = Server::new_async().await;
    mock_response(
        &mut server,
        "GET",
        "/organizations/org-personal/usage",
        401,
        "{}",
    )
    .await;

    let got = run(&server, vec![], Some(SAVED), ProviderError::NoCookies).await;

    assert!(matches!(got.result, Err(ProviderError::AuthRequired)));
    assert!(got.cleared);
}

#[tokio::test]
async fn nothing_to_read_and_nothing_saved_reports_why_no_session_exists() {
    let server = Server::new_async().await;

    let got = run(&server, vec![], None, ProviderError::NoCookies).await;

    assert!(matches!(got.result, Err(ProviderError::NoCookies)));
}

#[tokio::test]
async fn signed_out_browser_is_not_replaced_by_the_saved_session() {
    let mut server = Server::new_async().await;
    mock_response(
        &mut server,
        "GET",
        "/organizations/org-team/usage",
        401,
        "{}",
    )
    .await;
    let personal = mock_response_expect(
        &mut server,
        "GET",
        "/organizations/org-personal/usage",
        200,
        USAGE_BODY,
        0,
    )
    .await;

    let got = run(
        &server,
        vec![LIVE.into()],
        Some(SAVED),
        ProviderError::NoCookies,
    )
    .await;

    assert!(matches!(got.result, Err(ProviderError::AuthRequired)));
    personal.assert_async().await;
}
