// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interactive enforcement mode: hold-and-ask decision client.
//!
//! When a request would otherwise be denied and the endpoint is configured
//! with `enforcement: { mode: interactive, endpoint: "http://…/decide" }`,
//! [`consult_interactive_endpoint`] POSTs the request context to the external
//! decision endpoint (wire protocol schema version 1) and returns an
//! [`InteractiveDecision`].
//!
//! # Error handling
//!
//! All error paths (timeout, network failure, non-2xx response, malformed JSON,
//! unrecognized `decision` value) return the [`FallbackMode`] configured on the
//! endpoint — which defaults to [`FallbackMode::Deny`] (fail-closed).
//!
//! # Concurrency
//!
//! A process-wide semaphore (see [`MAX_CONCURRENT`]) bounds the number of
//! simultaneous in-flight HTTP calls.  If all permits are taken,
//! [`consult_interactive_endpoint`] returns the fallback immediately rather
//! than queueing — so a flood of denied connections never causes unbounded
//! back-pressure here.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use super::FallbackMode;

// ── DNS resolver ──────────────────────────────────────────────────────────────

/// DNS resolver that uses libc `getaddrinfo` via `spawn_blocking`.
/// Ensures `/etc/hosts` entries (e.g. `host.openshell.internal`) are resolved
/// correctly; reqwest's built-in resolver is `pub(crate)` and cannot be reused.
struct HostsAwareResolver;

impl Resolve for HostsAwareResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                (host.as_str(), 0u16)
                    .to_socket_addrs()
                    .map(|iter| -> Addrs { Box::new(iter) })
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
            })
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
        })
    }
}

// ── constants ─────────────────────────────────────────────────────────────────

/// Maximum response body size accepted from the decision endpoint.
/// Decision responses are small JSON objects; reject larger responses to bound
/// memory usage regardless of what the endpoint returns.
const MAX_RESPONSE_BYTES: usize = 65_536; // 64 KiB

/// Maximum simultaneous in-flight decision HTTP calls per process.
/// Excess calls receive `fallback` immediately rather than queuing.
/// Can be raised if a sandbox legitimately sees >16 concurrent denies;
/// future work could make this per-policy.
const MAX_CONCURRENT: usize = 16;

// ── global shared state ───────────────────────────────────────────────────────

/// Shared HTTP client for all decision-endpoint calls.
/// - `.no_proxy()`: bypass any HTTP_PROXY env var; the endpoint is control-plane
///   traffic that must reach the host directly.
/// - `.dns_resolver(HostsAwareResolver)`: use libc getaddrinfo so /etc/hosts
///   entries resolve correctly.
/// - `.redirect(none)`: do not follow redirects; the endpoint URL is fixed by
///   operator policy and redirects are unexpected.
/// - `connect_timeout`: bounds the TCP connect phase; the outer
///   `tokio::time::timeout` in `consult_interactive_endpoint` bounds the total
///   wall-clock wait.
static INTERACTIVE_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .no_proxy()
        .dns_resolver(Arc::new(HostsAwareResolver))
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build interactive-enforcement HTTP client")
});

/// Process-wide concurrency limiter for interactive-enforcement calls.
static INTERACTIVE_SEMAPHORE: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT));

// ── wire protocol ─────────────────────────────────────────────────────────────

/// JSON body POSTed to the decision endpoint (schema_version: 1).
#[derive(Debug, Serialize)]
struct DecisionRequest<'a> {
    schema_version: u8,
    request_id: &'a str,
    host: &'a str,
    port: u16,
    binary: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    method: &'a str,
    path: &'a str,
    protocol: &'a str,
    policy_name: &'a str,
    sandbox_name: &'a str,
}

/// JSON response body returned by the decision endpoint.
#[derive(Debug, Deserialize)]
struct DecisionResponse {
    decision: String,
    #[serde(default)]
    reason: String,
}

// ── public interface ──────────────────────────────────────────────────────────

/// Outcome of an interactive enforcement decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InteractiveDecision {
    Allow,
    Deny,
}

/// Request context passed to [`consult_interactive_endpoint`].
#[derive(Debug)]
pub(crate) struct InteractiveContext<'a> {
    /// Lowercase target hostname.
    pub host: &'a str,
    /// Target port.
    pub port: u16,
    /// Absolute path of the initiating binary.
    pub binary: &'a str,
    /// PID of the initiating binary, if available.
    /// Relay call sites pass `None` because `L7EvalContext` does not carry
    /// PID; threading it through is a future improvement.
    pub pid: Option<u32>,
    /// HTTP method (e.g. `"GET"`).
    pub method: &'a str,
    /// Request path, with credential query-params redacted.
    pub path: &'a str,
    /// L7 protocol string (e.g. `"rest"`, `"graphql"`).
    pub protocol: &'a str,
    /// Name of the matched network policy.
    pub policy_name: &'a str,
    /// Sandbox name from the process-wide OCSF context.
    pub sandbox_name: &'a str,
}

/// POST the request context to the decision endpoint and return Allow or Deny.
///
/// Returns `fallback` on any error: timeout, network failure, non-2xx response,
/// body size exceeded, malformed JSON, or unrecognized `decision` value.
///
/// Cancel-safe: dropping the future releases the semaphore permit immediately.
pub(crate) async fn consult_interactive_endpoint(
    endpoint: &str,
    timeout: Duration,
    fallback: FallbackMode,
    ctx: &InteractiveContext<'_>,
) -> InteractiveDecision {
    tracing::debug!(
        endpoint,
        host = ctx.host,
        port = ctx.port,
        "interactive-enforcement: [A] enter"
    );

    let fallback_decision = match fallback {
        FallbackMode::Allow => InteractiveDecision::Allow,
        FallbackMode::Deny => InteractiveDecision::Deny,
    };

    // Non-blocking acquire: shed the call with fallback if at capacity.
    let permit = match INTERACTIVE_SEMAPHORE.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(
                endpoint,
                max_concurrent = MAX_CONCURRENT,
                "interactive-enforcement: semaphore exhausted, applying fallback"
            );
            return fallback_decision;
        }
    };

    tracing::debug!(endpoint, "interactive-enforcement: [B] semaphore acquired");

    let request_id = uuid::Uuid::new_v4().to_string();
    let body = DecisionRequest {
        schema_version: 1,
        request_id: &request_id,
        host: ctx.host,
        port: ctx.port,
        binary: ctx.binary,
        pid: ctx.pid,
        method: ctx.method,
        path: ctx.path,
        protocol: ctx.protocol,
        policy_name: ctx.policy_name,
        sandbox_name: ctx.sandbox_name,
    };

    tracing::debug!(
        endpoint,
        timeout_ms = timeout.as_millis(),
        "interactive-enforcement: [C] calling send()"
    );

    let timed = tokio::time::timeout(timeout, async {
        let resp = INTERACTIVE_CLIENT
            .post(endpoint)
            .json(&body)
            .send()
            .await
            .map_err(anyhow::Error::from)?;

        tracing::debug!(
            endpoint,
            status = %resp.status(),
            "interactive-enforcement: [D] response headers received"
        );

        anyhow::ensure!(
            resp.status().is_success(),
            "non-2xx status: {}",
            resp.status()
        );

        // Cap body size before deserialising to bound memory usage.
        let bytes = resp.bytes().await.map_err(anyhow::Error::from)?;
        anyhow::ensure!(
            bytes.len() <= MAX_RESPONSE_BYTES,
            "response body too large: {} bytes (max {})",
            bytes.len(),
            MAX_RESPONSE_BYTES
        );
        let parsed =
            serde_json::from_slice::<DecisionResponse>(&bytes).map_err(anyhow::Error::from)?;

        tracing::debug!(endpoint, "interactive-enforcement: [E] body parsed");

        Ok::<_, anyhow::Error>(parsed)
    })
    .await;

    drop(permit);

    let parsed = match timed {
        Err(_elapsed) => {
            tracing::warn!(
                endpoint,
                timeout_ms = timeout.as_millis(),
                "interactive-enforcement: request timed out"
            );
            return fallback_decision;
        }
        Ok(Err(err)) => {
            tracing::warn!(
                endpoint,
                err = %err,
                "interactive-enforcement: request failed"
            );
            return fallback_decision;
        }
        Ok(Ok(r)) => r,
    };

    // Normalise to lowercase+trimmed before matching; the protocol spec
    // requires lowercase but be tolerant of endpoint implementation variance.
    let decision_lower = parsed.decision.trim().to_ascii_lowercase();
    match decision_lower.as_str() {
        "allow" => {
            tracing::debug!(
                endpoint,
                reason = %sanitize_reason(&parsed.reason),
                "interactive-enforcement: allowed"
            );
            InteractiveDecision::Allow
        }
        "deny" => {
            tracing::debug!(
                endpoint,
                reason = %sanitize_reason(&parsed.reason),
                "interactive-enforcement: denied"
            );
            InteractiveDecision::Deny
        }
        _ => {
            tracing::warn!(
                endpoint,
                decision = %parsed.decision,
                "interactive-enforcement: unrecognized decision value, applying fallback"
            );
            fallback_decision
        }
    }
}

/// Strip control characters and clamp length to prevent log injection.
fn sanitize_reason(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(256).collect()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::l7::FallbackMode;

    /// Build a minimal valid [`InteractiveContext`] for tests.
    fn ctx<'a>(host: &'a str, http_method: &'a str) -> InteractiveContext<'a> {
        InteractiveContext {
            host,
            port: 443,
            binary: "/usr/local/bin/claude",
            pid: Some(1234),
            method: http_method,
            path: "/api/test",
            protocol: "rest",
            policy_name: "test_policy",
            sandbox_name: "test-sandbox",
        }
    }

    // ── happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn allow_response_returns_allow() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"decision":"allow","reason":"approved"})),
            )
            .mount(&server)
            .await;

        let decision = consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Deny,
            &ctx("api.example.com", "GET"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Allow);
    }

    #[tokio::test]
    async fn deny_response_returns_deny() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"decision":"deny","reason":"blocked"})),
            )
            .mount(&server)
            .await;

        // fallback is Allow here — but explicit "deny" from endpoint wins.
        let decision = consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Allow,
            &ctx("api.example.com", "POST"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Deny);
    }

    #[tokio::test]
    async fn missing_reason_field_is_tolerated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"decision":"allow"})),
            )
            .mount(&server)
            .await;

        let decision = consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Deny,
            &ctx("api.example.com", "GET"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Allow);
    }

    // ── error paths → fallback ────────────────────────────────────────────────

    #[tokio::test]
    async fn non_2xx_applies_fallback_deny() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let decision = consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Deny,
            &ctx("api.example.com", "GET"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Deny);
    }

    #[tokio::test]
    async fn non_2xx_applies_fallback_allow() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let decision = consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Allow,
            &ctx("api.example.com", "GET"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Allow);
    }

    #[tokio::test]
    async fn non_2xx_with_allow_body_still_applies_fallback() {
        // An endpoint returning 500 + {"decision":"allow"} must NOT be
        // treated as an allow — status check happens before JSON parse.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(serde_json::json!({"decision":"allow"})),
            )
            .mount(&server)
            .await;

        let decision = consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Deny,
            &ctx("api.example.com", "GET"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Deny);
    }

    #[tokio::test]
    async fn malformed_json_applies_fallback() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
            .mount(&server)
            .await;

        let decision = consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Deny,
            &ctx("api.example.com", "GET"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Deny);
    }

    #[tokio::test]
    async fn unrecognized_decision_value_applies_fallback_deny() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"decision":"maybe","reason":"unsure"})),
            )
            .mount(&server)
            .await;

        let decision = consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Deny,
            &ctx("api.example.com", "GET"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Deny);
    }

    #[tokio::test]
    async fn unrecognized_decision_value_applies_fallback_allow() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"decision":"unknown"})),
            )
            .mount(&server)
            .await;

        let decision = consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Allow,
            &ctx("api.example.com", "GET"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Allow);
    }

    #[tokio::test]
    async fn unreachable_endpoint_applies_fallback() {
        // Port 1 is reserved/refused immediately — no timeout wait.
        let decision = consult_interactive_endpoint(
            "http://127.0.0.1:1/decide",
            Duration::from_secs(5),
            FallbackMode::Deny,
            &ctx("api.example.com", "GET"),
        )
        .await;

        assert_eq!(decision, InteractiveDecision::Deny);
    }

    // ── wire protocol ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn request_body_contains_all_expected_fields() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"decision":"deny"})),
            )
            .mount(&server)
            .await;

        consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Deny,
            &InteractiveContext {
                host: "github.com",
                port: 443,
                binary: "/usr/bin/curl",
                pid: Some(9999),
                method: "GET",
                path: "/torvalds/linux",
                protocol: "rest",
                policy_name: "my_policy",
                sandbox_name: "my-sandbox",
            },
        )
        .await;

        let reqs = server.received_requests().await.expect("wiremock requests");
        assert_eq!(reqs.len(), 1, "exactly one POST expected");
        let body: serde_json::Value =
            serde_json::from_slice(&reqs[0].body).expect("body must be JSON");

        assert_eq!(body["schema_version"], 1, "schema_version");
        assert_eq!(body["host"], "github.com", "host");
        assert_eq!(body["port"], 443, "port");
        assert_eq!(body["binary"], "/usr/bin/curl", "binary");
        assert_eq!(body["pid"], 9999, "pid");
        assert_eq!(body["method"], "GET", "method");
        assert_eq!(body["path"], "/torvalds/linux", "path");
        assert_eq!(body["protocol"], "rest", "protocol");
        assert_eq!(body["policy_name"], "my_policy", "policy_name");
        assert_eq!(body["sandbox_name"], "my-sandbox", "sandbox_name");
        assert!(
            body["request_id"].is_string(),
            "request_id must be a string"
        );
        assert!(
            !body["request_id"].as_str().unwrap_or("").is_empty(),
            "request_id must not be empty"
        );
    }

    // ── semaphore ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn semaphore_exhausted_applies_fallback() {
        // acquire_many(MAX_CONCURRENT) blocks until all permits are free.
        // If another test in this module holds a permit concurrently this
        // will deadlock.  Other tests complete quickly in practice; structural
        // injection of a per-test semaphore would remove the risk but requires
        // non-trivial refactoring.
        let permits = INTERACTIVE_SEMAPHORE
            .acquire_many(MAX_CONCURRENT as u32)
            .await
            .expect("semaphore not closed");

        // With no permits left the call must return the fallback immediately,
        // without making any network I/O (the endpoint URL is unreachable but
        // we never get that far).
        let decision = consult_interactive_endpoint(
            "http://127.0.0.1:1/decide",
            Duration::from_secs(5),
            FallbackMode::Deny,
            &ctx("api.example.com", "GET"),
        )
        .await;

        drop(permits);
        assert_eq!(decision, InteractiveDecision::Deny);
    }

    #[tokio::test]
    async fn absent_pid_is_omitted_from_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/decide"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"decision":"deny"})),
            )
            .mount(&server)
            .await;

        consult_interactive_endpoint(
            &format!("{}/decide", server.uri()),
            Duration::from_secs(5),
            FallbackMode::Deny,
            &InteractiveContext {
                host: "example.com",
                port: 80,
                binary: "-",
                pid: None,
                method: "GET",
                path: "/",
                protocol: "rest",
                policy_name: "p",
                sandbox_name: "s",
            },
        )
        .await;

        let reqs = server.received_requests().await.expect("wiremock requests");
        let body: serde_json::Value =
            serde_json::from_slice(&reqs[0].body).expect("body must be JSON");
        // skip_serializing_if = "Option::is_none" means the key is absent, not null.
        assert!(
            body.get("pid").is_none(),
            "pid key must be absent when pid is None; got: {body}"
        );
    }
}
