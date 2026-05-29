# agentbox × OpenShell Interactive Enforcement — Integration Guide

**For:** A Claude Code session working inside the `agentbox` repository.
**Status:** OpenShell-side implementation is **complete** on branch
`1-interactive-enforcement/vshalpnjabi` of `vshalpnjabi/OpenShell`
(PR: `vshalpnjabi/OpenShell#2`, draft pending upstream review).
**Goal:** Add an HTTP decision server to agentbox so the OpenShell proxy can
hold denied requests open while the user approves or rejects them, instead of
immediately 403-ing.

---

## API changes since `cae4eb3` (old `interactive-enforcement` branch)

If your agentbox integration was written against the old `interactive-enforcement`
branch (latest `cae4eb3`), apply these changes:

### 1. New `secret` field in policy YAML — **required for production**

The enforcement object now supports a `secret` field:

```yaml
enforcement:
  mode: interactive
  endpoint: http://host.openshell.internal:53789/decide
  timeout_seconds: 60
  fallback: deny
  secret: <shared-bearer-token>   # NEW — was absent in cae4eb3
```

The proxy logs a `WARN` at policy load time if `secret` is absent. Omitting
it is valid but not recommended for production.

### 2. Decision server must validate bearer token — **security requirement**

The proxy now sends `Authorization: Bearer <token>` on every POST when
`secret` is configured. Your decision server **must**:

1. Check the `Authorization` header is present.
2. Verify the token matches your configured secret.
3. Return `401` or `403` for any request with a missing or wrong token.

The proxy treats any non-2xx response as an error and applies `fallback`
(default: `deny`). So a rejected auth response causes a clean deny — no
security hole.

### 3. Path field no longer includes query string

When `secret` is configured, the proxy strips the query string from
`path` before building the decision request body. Do not rely on query
parameters appearing in `path`.

### 4. `EnforcementMode::Interactive` struct (Rust code only)

If agentbox has Rust code that constructs `EnforcementMode::Interactive`
directly (e.g. in tests or policy builders), add `secret: None` or
`secret: Some("token".to_string())` to the struct literal:

```rust
// Before (cae4eb3):
EnforcementMode::Interactive { endpoint, timeout, fallback }

// After (current branch):
EnforcementMode::Interactive { endpoint, timeout, fallback, secret: None }
```

### 5. Wire protocol and response shape — unchanged

`schema_version: 1`, the full request JSON schema, and the
`{"decision":"allow"|"deny","reason":"..."}` response shape are identical
to `cae4eb3`. No JSON parsing changes needed.

---

## API change since `4ac551a`: the `pid` field is now populated

**Commit:** `663e5528c` on `vshalpnjabi/OpenShell#2` — the current PR head,
built on top of `4ac551a`.
**Impact on agentbox:** additive, **no required code change**. If your
`/decide` handler already treats `pid` as optional, nothing breaks — you just
start receiving a real value where you previously always got `null`/absent.

### What changed

Before this commit, the three relay enforcement arms hard-coded `pid: None`,
so the `pid` field was **always omitted** from the decision request body. The
wire-protocol table said "may be omitted if the proxy couldn't resolve it," but
in practice it was *never* present for interactive requests.

Now the proxy forwards the PID it resolved at **L4 CONNECT time** — the same
process identity the allow/deny path bound the policy decision to — so `pid` is
populated on virtually every interactive `/decide` call.

### What `pid` means (read this before you use it)

- It is the **socket-owner PID** from OpenShell's stock identity resolution:
  the process that owns the TCP socket inode for this connection, found via
  `/proc/<pid>/net/tcp` + `/proc/<pid>/fd`.
- It is **not guaranteed to be the leaf process**. If a child inherited the
  socket fd from a parent (fork without `FD_CLOEXEC`), the owner may be an
  ancestor. It is exactly the identity the `enforce`/`audit` allow-deny path
  attributes the connection to — no more, no less.
- It is still **nullable** (`number` or absent). It is absent only when L4
  could not resolve a single owner. Corollary worth knowing: when a socket has
  *multiple distinct-identity* owners (ambiguous shared socket), L4 **denies the
  connection outright before L7 runs**, so interactive never fires in that case.
  Net effect: when you receive an interactive `/decide` call, `pid` will almost
  always be present — but **still treat it as optional and code defensively**.

### How to use it in agentbox

- Map `pid` to a process in the sandbox's process tree to tell the user *which*
  process is making the request (e.g. "claude (pid 1244) wants github.com:443").
- Combine with `sandbox_name` + `binary` for a richer prompt or audit record.
- Do **not** assume the process still exists when the user clicks — it may have
  exited while the connection is held. Treat `pid` as a point-in-time snapshot
  for display/audit, not a live handle.

### How it was fixed (OpenShell side, for context)

Purely additive and localized to the interactive path — the shared allow/deny
logic was deliberately left untouched:

- New `binary_pid: Option<u32>` field on `L7EvalContext`, populated at the two
  production proxy construction sites from `decision.binary_pid` (the PID
  resolved for the L4 network decision).
- The three relay interactive arms forward it as `InteractiveContext.pid`.
- The shared L4 `resolve_process_identity` / `ConnectDecision` were **not
  changed**, so `enforce`/`audit` allow-deny behavior is byte-for-byte
  identical. Only the interactive decision request gained the pid.

**Minimum commit for a populated `pid`:** `663e5528c`. The core interactive
feature still works from `4ac551a`; only the `pid` value needs the newer commit.

---

## Background — why this matters

Today's flow (with SIGSTOP):

```
agent → request → proxy → 403 → agent sees failure
               ↓
         agentbox freezes agent (SIGSTOP)
         shows notification → user clicks Allow
         resumes agent (SIGCONT)
         agent RETRIES the request → succeeds
```

The problem: the 403 has already reached the agent's read buffer before the
user has decided anything. The agent must detect the failure and retry. This
is fragile — not all agents retry, and some interpret the 403 as a hard stop.

**With interactive enforcement:**

```
agent → request → proxy HOLDS connection → POSTs to agentbox's HTTP server
                                           agentbox shows notification
                                           user clicks Allow / Deny
                                           agentbox responds to proxy
                  proxy → 200 (Allow) ─────────────────────────────→ agent
                  proxy → 403 (Deny)  ─────────────────────────────→ agent
```

The agent is **already blocked** on its own outbound HTTP call — the proxy is
holding the TCP connection open. No SIGSTOP needed, no retry needed. The first
attempt is authoritative.

---

## What agentbox needs to add

A single HTTP handler:

```
POST /decide
Content-Type: application/json
Authorization: Bearer <shared-secret>
```

That's it. The OpenShell proxy will POST a JSON body, wait for your response,
and act on `"allow"` or `"deny"`.

---

## Wire protocol

### Request body (sent by OpenShell proxy → agentbox)

```json
{
  "schema_version": 1,
  "request_id":   "550e8400-e29b-41d4-a716-446655440000",
  "sandbox_name": "agentbox-myproject-abc12345",
  "binary":       "/usr/local/bin/claude",
  "pid":          1244,
  "host":         "api.anthropic.com",
  "port":         443,
  "method":       "GET",
  "path":         "/v1/models",
  "protocol":     "rest",
  "policy_name":  "agentbox-interactive"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | `u8` | Always `1` for now |
| `request_id` | `string` | UUID v4 — unique per in-flight request; use as idempotency key |
| `sandbox_name` | `string` | Matches the name in agentbox's sandbox registry |
| `binary` | `string` | Full path of the binary making the connection |
| `pid` | `number` or absent | Socket-owner PID resolved at L4 CONNECT time — the same identity the allow/deny path uses. Populated since `663e5528c` (was always absent before); still omitted if L4 couldn't resolve a single owner, so treat as optional. |
| `host` | `string` | Lowercase target hostname |
| `port` | `number` | Target port |
| `method` | `string` | HTTP method (`GET`, `POST`, etc.) |
| `path` | `string` | URL path (query string stripped when `secret` is set) |
| `protocol` | `string` | `"rest"`, `"graphql"`, or `"unknown"` |
| `policy_name` | `string` | Which policy rule matched this connection |

### Response body (agentbox → proxy)

```json
{ "decision": "allow", "reason": "user approved" }
```

or

```json
{ "decision": "deny", "reason": "user denied" }
```

| Field | Required | Notes |
|-------|----------|-------|
| `decision` | **yes** | Must be exactly `"allow"` or `"deny"` (lowercase). Any other value is treated as deny. |
| `reason` | no | Human-readable string; logged in the OCSF audit event. |

**HTTP status must be 2xx.** Any non-2xx status (even with `"decision":"allow"`
in the body) is treated as an error and the proxy applies its `fallback` mode
(default: deny).

### Error / timeout behaviour (proxy side)

The proxy has a per-endpoint `timeout_seconds` (default 60 s, max 300 s). If
agentbox doesn't respond within that window:
- The proxy applies the configured `fallback` (default: `deny`).
- The agent gets a clean 403.
- The proxy logs a warning with `timeout_ms`.

So agentbox should:
- Try to respond before `timeout_seconds − a few seconds` (leave buffer for
  network).
- If the user doesn't click in time, respond with `"deny"` explicitly rather
  than letting the proxy time out — cleaner for the audit log.

---

## Implementation checklist

### Step 1 — HTTP listener with bearer auth

Start an HTTP server bound to `0.0.0.0:53789` (or a configurable port) when
agentbox starts. This port must be reachable from the OpenShell gateway process.

> **Port note:** If OpenShell runs as a native daemon on macOS (not in a
> container), the proxy and agentbox are on the same machine, so `127.0.0.1`
> works fine. The policy YAML uses `host.openshell.internal` which resolves
> to the host machine's IP from within a sandbox container — so binding
> `0.0.0.0` is safer.

### Step 2 — Handle `POST /decide`

```
receive POST /decide
  0. Validate Authorization: Bearer <token> — reject with 401 if missing or wrong
  1. Parse JSON body → extract all fields (schema_version check optional for now)
  2. Look up sandbox by sandbox_name in agentbox's registry
  3. Generate a user-facing prompt:
       "[sandbox_name]  binary→host:port path"
       "[Allow]  [Deny]"
  4. Show notification (ntfy, macOS alert, TUI prompt — whatever agentbox uses)
  5. Wait for user click, with a deadline of (timeout_seconds − 5 s)
  6. Respond:
       Allow → HTTP 200, {"decision":"allow","reason":"user approved"}
       Deny  → HTTP 200, {"decision":"deny","reason":"user denied"}
       No response in time → HTTP 200, {"decision":"deny","reason":"timed out waiting for user"}
```

### Step 3 — Relationship to existing SIGSTOP / seen-list machinery

You do **not** need to SIGSTOP the agent when interactive enforcement is
active — the agent is already blocked on its own HTTP call. The proxy is
holding the TCP connection open.

Recommended: keep the SIGSTOP path as a fallback for cases where interactive
enforcement is not configured (i.e., the sandbox is using plain `enforce`
mode). Interactive and SIGSTOP are complementary:

| Situation | Mechanism |
|-----------|-----------|
| Policy is `interactive` mode | Proxy holds connection → agentbox responds |
| Policy is `enforce` mode | Proxy 403s immediately → agentbox freezes + notifies (existing flow) |

The seen-list machinery (`freeze_sandbox_agents`, etc.) is orthogonal and can
stay unchanged.

### Step 4 — Concurrent requests

The proxy caps concurrent in-flight interactive calls at 16 (semaphore per
sandbox process). In practice you'll rarely see more than 1-2 simultaneous
decision requests per sandbox. But your HTTP handler should support concurrent
requests — don't hold a global lock while waiting for user input; track
in-flight decisions by `request_id`.

### Step 5 — Policy template

#### Why the naive approach doesn't work

Before giving the template, it's worth understanding why three seemingly
reasonable attempts all silently fail:

| Attempt | What goes wrong |
|---------|-----------------|
| `enforcement: {mode: interactive}` with **no `protocol:`** | Interactive never fires. Without `protocol:`, the L7 engine never runs. The proxy allows/denies at L4 (host+port only) and the enforcement field is ignored. |
| `protocol: rest` with **no `access:` or `rules:`** | The L7 validator rejects the policy with `"protocol requires rules or access to define allowed traffic"`. |
| `protocol: rest` + **`access: full`** (no `deny_rules`) | Interactive never fires. `access: full` expands to an allow-all rule (`method: *, path: **`), so `allowed = true` for every request. The proxy only consults interactive enforcement when `allowed = false`. |
| **`host: "*"`** to catch all internet traffic | No matches. OPA's glob uses `.` as a segment delimiter, so `*` matches a single DNS label and never crosses dots. `glob.match("*", ["."], "api.example.com")` is false. |

#### The correct pattern

To make interactive fire for **every request to a given host**, you need three
ingredients together:

1. **`protocol: rest`** — enables L7 inspection (the path that consults enforcement mode)
2. **`access: full`** — satisfies the validator's `rules or access` requirement; establishes the base allow set
3. **`deny_rules: [{method: "*", path: "**"}]`** — overrides the base allow, making every request `allowed = false`; the proxy then calls your decision endpoint instead of forwarding

#### Minimal single-host example

```yaml
version: 1
network_policies:
  my-gated-api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement:
          mode: interactive
          endpoint: http://127.0.0.1:9999/decide
          timeout_seconds: 30
          fallback: deny
          secret: <shared-bearer-token>
        access: full
        deny_rules:
          - method: "*"
            path: "**"
    binaries:
      - path: "**"
```

#### Two-tier allow-list + interactive template

```yaml
version: 1

network_policies:
  # Tier 1: Claude API — always allowed, no prompts.
  claude-api:
    endpoints:
      - host: api.anthropic.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - path: "**"

  # Tier 2: GitHub — held for user approval.
  github-interactive:
    endpoints:
      - host: "*.github.com"
        port: 443
        protocol: rest
        enforcement:
          mode: interactive
          endpoint: http://host.openshell.internal:53789/decide
          timeout_seconds: 120
          fallback: deny
          secret: <shared-bearer-token>
        access: full
        deny_rules:
          - method: "*"
            path: "**"
    binaries:
      - path: "**"

  github-root-interactive:
    endpoints:
      - host: github.com
        port: 443
        protocol: rest
        enforcement:
          mode: interactive
          endpoint: http://host.openshell.internal:53789/decide
          timeout_seconds: 120
          fallback: deny
          secret: <shared-bearer-token>
        access: full
        deny_rules:
          - method: "*"
            path: "**"
    binaries:
      - path: "**"
```

> **Evaluation order note:** OpenShell evaluates all policies and picks the
> lexicographically smallest matching policy name. To prevent a later
> interactive policy from overriding an explicit enforce entry, give
> allow-list policy names that sort before interactive ones (e.g.
> `aaa-claude-api` before `zzz-interactive-gate`), or keep them in
> separate, non-overlapping host sets.

---

## What's been verified

**End-to-end confirmed working** against an agentbox `interactive-decide-server`
in an Ubuntu 24.04 (aarch64) Lima VM with a live OpenShell supervisor.

- OPA evaluation: `deny_request=true`, `allow_request=false` for the
  three-ingredient policy. ✅
- Proxy wiring: Interactive arm fires; supervisor POSTs to `/decide` and
  holds the TCP connection until a response or timeout. ✅
- Bearer auth: `Authorization: Bearer <token>` sent when `secret` set;
  non-2xx response → clean fallback. ✅
- Fallback: connection denied cleanly when `timeout_seconds` elapses. ✅
- DNS routing fix: `GaiResolver` (via `spawn_blocking(getaddrinfo)`) ensures
  `host.openshell.internal` resolves correctly from inside the container even
  when `reqwest`'s async resolver ignores `/etc/hosts`. ✅

**Root cause of earlier `L7_DENY_RULES_NOT_FIRING.md` report:** the live
supervisor inside the container was running a stale registry image that
pre-dated the Interactive implementation. Solution: rebuild OpenShell from
`4ac551a` or later **and** recreate the sandbox container so it pulls the
updated image.

> **Operational note:** always recreate the sandbox after upgrading the
> supervisor binary — a cached container image will keep running the old
> supervisor regardless of what the host binary reports.

---

## End-to-end test plan

### Prerequisites

1. OpenShell built from `vshalpnjabi/OpenShell` branch
   `1-interactive-enforcement/vshalpnjabi` (minimum commit: `4ac551a`)
   and installed.
2. agentbox running with the decision server listening on `:53789`.

### Quick smoke test (mock server, no agentbox changes yet)

```python
# mock_decider.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, sys

SECRET = sys.argv[2] if len(sys.argv) > 2 else None

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if SECRET and auth != f"Bearer {SECRET}":
            self.send_response(401)
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        print(f"\n→ {body['binary']} → {body['method']} {body['host']}:{body['port']}{body['path']}")
        print(f"  sandbox: {body['sandbox_name']}  request_id: {body['request_id']}")
        ans = input("  [a]llow / [d]eny: ").strip().lower()
        resp = json.dumps({"decision": "deny" if ans == "d" else "allow",
                           "reason": "manual test"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)
    def log_message(self, *_): pass

HTTPServer(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 9999), H).serve_forever()
```

```bash
python3 mock_decider.py 9999 my-secret-token
```

### Test matrix

| Test | Expected |
|------|----------|
| User clicks Allow | Agent's request succeeds on the **first** attempt |
| User clicks Deny | Agent gets clean 403 on the first attempt |
| Wrong or missing bearer token | Server returns 401/403; proxy applies fallback (deny) |
| agentbox server not running | Proxy logs "request failed"; fallback fires; agent gets 403 |
| User doesn't click within `timeout_seconds` | Proxy logs "timed out"; fallback fires; agent gets 403 |
| Two concurrent denied requests | Both prompts appear; both can be Allow/Deny independently |
| Allow-listed host (e.g. api.anthropic.com) | No prompt; request passes through with `enforce` rule |

---

## OpenShell installation (from the fork)

> **Critical:** `cargo install --path crates/openshell-cli` builds the
> gateway and CLI but **not the supervisor binary that runs inside the
> container**. The supervisor (`crates/openshell-sandbox`) must also be
> rebuilt and the cached image overwritten, then the sandbox recreated.

```bash
# Build from branch 1-interactive-enforcement/vshalpnjabi (minimum: 4ac551a)
cargo install --path crates/openshell-cli
cargo install --path crates/openshell-server

# Rebuild the supervisor binary and overwrite the cached copy
cargo build --release --package openshell-sandbox
CACHED=$(ls ~/.local/share/openshell/docker-supervisor/sha256-*/openshell-sandbox 2>/dev/null | head -1)
if [ -n "$CACHED" ]; then
  cp target/release/openshell-sandbox "$CACHED"
fi

# Destroy and recreate any existing sandboxes
openshell sandbox destroy <name>
openshell sandbox create <name> ...
```

---

## Reference

- **Full design doc:** `docs/interactive-enforcement/DESIGN.md` in this branch.
- **Wire protocol source of truth:** `crates/openshell-sandbox/src/l7/interactive.rs`
  (`DecisionRequest` struct, `consult_interactive_endpoint` function).
- **Policy schema:** `crates/openshell-policy/src/lib.rs`
  (`InteractiveEnforcementDef` struct).
- **OpenShell fork PR:** `vshalpnjabi/OpenShell#2`
