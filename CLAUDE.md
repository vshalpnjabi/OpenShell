# Working on this branch?

This is the `interactive-enforcement` worktree of `vshalpnjabi/OpenShell` (fork of NVIDIA/OpenShell).

The goal of this branch: add a third `EnforcementMode` to the sandbox proxy ("Interactive") that holds a denied request open while consulting an external HTTP decision endpoint — driven by [agentbox](https://github.com/vshalpnjabi/agentbox)'s need to give first-attempt Allow/Deny semantics.

Read these in order:

1. **`docs/interactive-enforcement/DESIGN.md`** — full plan, wire protocol, files to change, phased approach.
2. **`docs/interactive-enforcement/CLAUDE.md`** — operating instructions for a Claude Code session picking up the work.

Then start at Phase 1 in the CLAUDE.md checklist.

Don't read `crates/openshell-sandbox/src/proxy.rs` top-to-bottom — it's 6.6K lines. Jump to the line ranges called out in DESIGN.md.
