# Interactive-enforcement — post-implementation review changes

Recorded after a full branch diff review on 2026-05-28.
All items are pending implementation; none have been applied yet.

---

## Severity key

| Symbol | Meaning |
|--------|---------|
| 🔴 | Critical — security or correctness risk |
| 🟡 | Warning — behavioural or observability issue |
| 🔵 | Suggestion — documentation or defensive improvement |

---

## 🔴 C1 — No URL validation on `endpoint` (SSRF)

**Files:** `crates/openshell-sandbox/src/l7/mod.rs`, `crates/openshell-policy/src/lib.rs`

`parse_enforcement_value` in `mod.rs` accepts the `endpoint` string from the
policy payload verbatim and hands it directly to `reqwest::Client::post()`.
There is no scheme, host, or port validation. A policy with
`endpoint: "file:///etc/passwd"` or `endpoint: "http://169.254.169.254/"` would be
executed by the supervisor process, which has direct TCP access to the host
and internal subnets.

**Change:** Reject non-`http://`/`https://` schemes at parse time in
`parse_enforcement_value`. Fall closed to `EnforcementMode::Enforce` on
rejection (same behaviour as a missing `endpoint`).

```rust
// In parse_enforcement_value, after extracting `endpoint`:
if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
    tracing::warn!(
        endpoint,
        "interactive-enforcement: endpoint must be http or https, \
         treating as misconfiguration → Enforce"
    );
    return EnforcementMode::Enforce;
}
```

**Breaking?** No — no valid policy uses a non-http(s) scheme.

---

## 🟡 W1 — Investigation files at repo root must not go upstream

**Files:** `L7_DENY_RULES_NOT_FIRING.md`, `SUPERVISOR_DECIDE_POST_NEVER_REACHES_ENDPOINT.md`

Both files are session debugging journals. They expose fork-specific
infrastructure details (Docker socket config, agentbox hostnames, internal IP
ranges). They must not appear in a PR to NVIDIA/OpenShell.

**Change:** Move both files to `docs/interactive-enforcement/` where all other
fork-specific dev docs live.

**Note:** `SUPERVISOR_DECIDE_POST_NEVER_REACHES_ENDPOINT.md` is still open
(bug partially unresolved — see section at bottom of this file). Keep it in
`docs/interactive-enforcement/` until the bug is fully closed.

**Breaking?** No — file moves only.

---

## 🟡 W2 — WebSocket Interactive arm logs `"audit"` for fallback-allow

**File:** `crates/openshell-sandbox/src/l7/websocket.rs`

```rust
// Current (wrong):
FallbackMode::Allow => "audit",
FallbackMode::Deny  => "deny",

// Correct:
FallbackMode::Allow => "allow",  // interactive fallback-allow, not a policy-audit event
FallbackMode::Deny  => "deny",
```

`"audit"` means *policy violation logged but allowed because enforcement mode
is Audit*. Using it here makes a fallback-allow event indistinguishable from
a genuine Audit-mode event in the OCSF log. The forwarding gate
(`if decision == "deny"`) is unaffected — this is a labelling-only fix.

**Breaking?** Changes OCSF log output. Since Interactive mode is new code with
no deployed log consumers, risk is negligible.

---

## 🟡 W3 — Stale doc comment on `EnforcementMode::Interactive`

**File:** `crates/openshell-sandbox/src/l7/mod.rs`

The variant doc still reads *"Phase 1: parsed but not yet wired into the
proxy decision path (the proxy treats this as a deny)"*. The mode is fully
wired. Remove the Phase-1 sentence.

**Breaking?** No — doc-only.

---

## 🟡 W4 — Unknown `mode` in enforcement object falls back to Audit (fail-open)

**File:** `crates/openshell-sandbox/src/l7/mod.rs`

```rust
// Current (fail-open):
if mode != "interactive" {
    return EnforcementMode::Audit;
}

// Correct (fail-closed):
if mode != "interactive" {
    tracing::warn!(
        mode,
        "interactive-enforcement: unrecognized mode in enforcement object, \
         treating as misconfiguration → Enforce"
    );
    return EnforcementMode::Enforce;
}
```

The valid object form is only `{ mode: "interactive", ... }`. The bare-string
forms `"enforce"` and `"audit"` are handled in an earlier branch. A typo like
`{ mode: "Enforce" }` currently degrades silently to Audit (fail-open).
Changing to Enforce is consistent with the missing-`endpoint` case two lines
below and with the fail-closed design principle stated in DESIGN.md.

**Breaking?** Yes, for misconfigured policies with an unknown `mode` value in
an object. No valid policy is affected. Deliberately flagged.

---

## ✅ W5 — `pid: None` in relay.rs Interactive arms — RESOLVED

**File:** `crates/openshell-sandbox/src/l7/relay.rs` (three Interactive arms)

Previously `pid: None` was passed to `InteractiveContext` at all three relay
call sites because the PID, available in `proxy.rs` via `decision.binary_pid`,
was not threaded into `L7EvalContext`.

**Change applied:** `L7EvalContext` gained a `binary_pid: Option<u32>` field,
populated at the two production construction sites from `decision.binary_pid`
(the PID resolved for the L4 network decision — the same identity the
allow/deny path binds to). The three relay Interactive arms now forward it as
`InteractiveContext.pid`. The shared L4 `resolve_process_identity` /
`ConnectDecision` are untouched, so allow/deny behavior is unchanged; only the
Interactive decision request now carries the pid.

**Breaking?** No — additive struct field; allow/deny paths never read it.

---

## 🟡 W6 — `semaphore_exhausted_applies_fallback` test: parallel fragility

**File:** `crates/openshell-sandbox/src/l7/interactive.rs`

The test drains all 16 `INTERACTIVE_SEMAPHORE` permits via `acquire_many(16)`.
If another test holding a permit runs concurrently, this blocks indefinitely.
Unlikely to cause CI failures but is a latent hang risk.

**Change:** Add `#[allow(clippy::…)]` comment explaining the design constraint
and note the limitation inline so the next person understands why the test is
structured this way. Do not restructure the test (requires non-trivial
injection machinery).

**Breaking?** No — test-only.

---

## 🔵 S1 — `relay_graphql` Interactive arm: hardcoded `"graphql"` needs explanation

**File:** `crates/openshell-sandbox/src/l7/relay.rs`

The protocol string is hardcoded as `"graphql"` in the `relay_graphql`
Interactive arm. The hardcode is correct (the function only dispatches for
GraphQL), but it's inconsistent with the `relay_with_route_selection` arm
which computes `protocol_str` from `config.protocol`. Add a one-line comment.

**Breaking?** No — doc-only.

---

## 🔵 S2 — Silent fail in `enforcement_def_from_proto_string` on malformed JSON

**File:** `crates/openshell-policy/src/lib.rs`

When a stored proto enforcement string fails JSON parsing, the code silently
falls through to a bare-string `EnforcementDef`. The operator has no log
evidence that their Interactive policy was silently downgraded.

**Change:** Add `tracing::warn!` on that path.

**Breaking?** No — adds a log line; no behavioural change.

---

## 🔵 S3 — `connect_timeout` vs outer timeout: relationship needs a comment

**File:** `crates/openshell-sandbox/src/l7/interactive.rs`

`connect_timeout(10s)` covers the TCP connect phase. The outer
`tokio::time::timeout(timeout, ...)` covers the full round-trip. The
asymmetry is intentional, but there are two non-obvious subtleties that should
be documented:

1. The reqwest build (`default-features = false, features = ["json",
   "rustls-tls-native-roots"]`) uses `GaiResolver` (blocking `getaddrinfo`
   via `spawn_blocking`) for DNS. In some reqwest/hyper versions,
   `connect_timeout` wraps only the TCP connect, not the DNS phase. If
   `getaddrinfo` blocks, `connect_timeout` does not save us — only the outer
   `tokio::time::timeout` bounds the total wait.

2. `connect_timeout` uses `tokio::time::sleep` internally. If tokio worker
   threads are all blocked on synchronous work (e.g., `std::sync::Mutex::lock`
   in `evaluate_l7_request` in the relay loop), the timer is not polled and
   `connect_timeout` effectively becomes a no-op until threads become available.
   The outer `tokio::time::timeout` behaves the same way, but has a much
   longer fuse (the configured `timeout_seconds`).

   **This is the confirmed failure mode on Linux Docker** (see
   `SUPERVISOR_DECIDE_POST_NEVER_REACHES_ENDPOINT.md`). The fix for (2) is
   a separate structural change: wrap `evaluate_l7_request` in
   `spawn_blocking` across all relay call sites so worker threads are never
   blocked by OPA evaluation.

**Breaking?** No — doc-only.

---

## Open: supervisor POST bug (partially unresolved)

`c49bcc7` fixed the Docker-Desktop / macOS case (Docker proxy config injecting
`HTTP_PROXY` into the container). The bug still reproduces on bare Linux Docker
with no proxy env vars.

**Confirmed remaining mechanism:** Tokio thread starvation. `evaluate_l7_request`
holds `std::sync::Mutex<regorus::Engine>` synchronously on tokio worker threads
(no `spawn_blocking`). On systems with few vCPUs (≤4), all worker threads can
be transiently blocked simultaneously, preventing tokio's timer and I/O driver
from being polled. `connect_timeout` never fires; `send()` never makes progress;
the outer 120 s timeout eventually triggers.

**Proposed fix (separate commit):** Wrap `evaluate_l7_request` call sites in
`relay.rs` (lines 313, 733, 1024) and `proxy.rs` (line 3115) in
`spawn_blocking`, consistent with how `evaluate_opa_tcp` is already handled.
This prevents relay tasks from blocking worker threads and removes the
starvation path.

**Scope note:** This fix is deliberately NOT bundled with the review changes
above. It requires changes to `relay.rs` and `proxy.rs`, and needs a
re-test against the Linux Docker reproducer before merging.
