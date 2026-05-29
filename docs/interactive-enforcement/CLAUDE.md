# CLAUDE.md — guidance for a Claude Code session picking up interactive enforcement

You're working on `vshalpnjabi/OpenShell`, branch
`1-interactive-enforcement/vshalpnjabi`. The feature adds
`EnforcementMode::Interactive` to the sandbox proxy — holds a denied request
open while consulting an HTTP decision endpoint.

Full design background: `DESIGN.md` in this directory.
agentbox integration guide: `AGENTBOX_INTEGRATION.md` in this directory.

## Current status (as of 2026-05-28)

**All phases complete. PR is open at `vshalpnjabi/OpenShell#2` (draft).**

| Phase | Status |
|-------|--------|
| 1 — Types + policy schema | ✅ Done |
| 2 — `consult_interactive_endpoint()` + tests | ✅ Done |
| 3 — Wired into proxy decision path | ✅ Done |
| 4 — Compile-check + tests + commits | ✅ Done |
| 5 — Security review findings addressed | ✅ Done |
| 6 — PR open (`vshalpnjabi/OpenShell#2`) | ✅ Done (draft) |

## Latest commit (HEAD)

```
4ac551a fix(sandbox): warn when interactive enforcement falls back in WebSocket path
bc9175e fix(sandbox): address security review findings in interactive enforcement
491afc7 fix(sandbox): cap interactive enforcement timeout at 300 s
e0f6152 fix(sandbox): remove unnecessary clone in websocket enforcement match
25a1ac3 style: apply rustfmt to all changed files
d203fdf docs(sandbox): document interactive enforcement mode
ed6734c chore(docs): add fork-local Claude Code session instructions
```

## Key implementation files

| File | What changed |
|------|-------------|
| `crates/openshell-sandbox/src/l7/interactive.rs` | Core decision client; 15 tests |
| `crates/openshell-sandbox/src/l7/mod.rs` | `EnforcementMode::Interactive` with `secret`; `INTERACTIVE_MAX_TIMEOUT = 300s` |
| `crates/openshell-sandbox/src/l7/relay.rs` | Interactive arms destructure `secret`, pass to client |
| `crates/openshell-sandbox/src/l7/websocket.rs` | Interactive fallback arms with `tracing::warn!` |
| `crates/openshell-sandbox/src/proxy.rs` | Interactive arm: strips query string, passes `secret` |
| `crates/openshell-policy/src/lib.rs` | `InteractiveEnforcementDef { secret }`, SSRF validation |
| `crates/openshell-sandbox/Cargo.toml` | Added `serial_test = "3"` to dev-deps |

## Known limitations (documented, not blocking)

1. **`{`-heuristic proto encoding** — the policy value is stored as a JSON
   string in the proto `enforcement` field; detected by `{`-prefix. Needs a
   wire-breaking proto schema change to fix cleanly.
2. **Hostname-based SSRF gap** — SSRF check blocks loopback/link-local IPs but
   not hostnames that resolve to them. DNS resolution at validation time is
   unreliable; fix belongs in a separate PR.
3. **`secret` in plaintext YAML** — no secret injection mechanism yet.
   Separate feature request.
4. **WebSocket per-message fallback** — Interactive cannot consult the async
   decision endpoint from the sync WebSocket per-message path; applies
   `fallback` and logs `warn!`. Fixing this requires an async WebSocket
   refactor phase.
5. ~~**`pid` is `None` at relay sites**~~ — RESOLVED. `L7EvalContext` now
   carries `binary_pid` (the PID resolved for the L4 network decision, i.e. the
   same identity the allow/deny path bound to), and the three relay Interactive
   arms forward it as `InteractiveContext.pid`. The shared L4 identity
   resolution is unchanged, so allow/deny behavior is unaffected — only the
   Interactive decision request now includes the pid.

## Test results (last full run)

- `cargo test -p openshell-sandbox --lib` — 868 tests, all pass
- `cargo test -p openshell-policy --lib` — all pass

## Wire protocol summary

POST `<endpoint>` with:

```json
{
  "schema_version": 1,
  "request_id": "<uuid>",
  "sandbox_name": "<name>",
  "binary": "/path/to/binary",
  "pid": 1234,
  "host": "api.example.com",
  "port": 443,
  "method": "GET",
  "path": "/some/path",
  "protocol": "rest",
  "policy_name": "my-policy"
}
```

`Authorization: Bearer <secret>` header is added when `secret` is set.

Response: `{"decision":"allow"|"deny","reason":"..."}`, HTTP 2xx.

## Build notes

See `SANDBOX_BUILD_ENVIRONMENT.md` (in memory) for tarball bootstrap and
gold-linker OOM workaround details.

```bash
cargo build --workspace
cargo test -p openshell-policy
cargo test -p openshell-sandbox --lib -- l7::interactive
```
