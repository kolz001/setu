# Setu — A System-Level MCP Broker for Linux

**Name:** **Setu**, Sanskrit for "bridge" — consistent with Tvastr/Sumantra naming convention. This document originated under the working title `mcpd`; the project adopted Setu in July 2026 and all occurrences below have been updated (binaries: `setu` daemon, `setuctl` CLI).

**One-line pitch:** D-Bus for the agent era. A privileged, policy-governed broker daemon that exposes core Linux system capabilities to AI agents as MCP servers — with per-agent authorization, audit trails, and rollback built in.

**Status:** Design document (July 2026). v0.1.0 implements Phase 1 and the core of Phase 2; see the README for what runs today.

---

## 1. Problem Statement

AI agents (Claude Code, OpenClaw-class agents, autonomous remediation pipelines) increasingly operate directly on Linux systems. Today they do so through a raw shell, which grants **ambient authority**: whatever the invoking user can do, the agent can do — with no scoping, no structured audit, and no rollback.

This is acceptable for a developer laptop. It is unacceptable for:

- Enterprise servers and regulated environments (audit/compliance requirements)
- Long-running autonomous agents operating without a human in the loop
- Multi-agent systems where different agents warrant different privilege levels

Existing answers are fragmented: SUSE SLES 16 ships OS-level MCP integration, but it is enterprise-specific and tied to one vendor's stack. Research proposals (AIOS, AgenticOS) define intent-based capability models but lack a practical, distro-agnostic implementation. There is **no open, portable equivalent of D-Bus or polkit for agent access to system capabilities**.

## 2. Goals and Non-Goals

### Goals

1. A single local endpoint (`/run/setu/setu.sock`) where any MCP-speaking agent discovers and invokes system capabilities.
2. Per-agent, per-tool, per-action **policy enforcement** at the broker — deny by default.
3. **Append-only audit log** of every tool call: agent identity, tool, arguments, decision, result.
4. **Reversibility** for destructive operations: filesystem snapshot (btrfs/ZFS/LVM) or transactional apply before mutation, with automatic rollback hooks.
5. Distro-agnostic: installable as a package on Debian/Ubuntu, Fedora, openSUSE, NixOS, Arch.
6. Human-in-the-loop escalation path for high-risk actions.

### Non-Goals

- Not a new kernel or a new OS. Runs entirely in userland on stock Linux.
- Not an agent framework. setu does not run, schedule, or reason about agents — it governs their access.
- Not a remote-management plane (v1 is local Unix socket only; remote transport is future work).
- Not a replacement for the shell. Agents may still use bash; setu is the governed alternative for privileged/system operations.

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Agents                           │
│   Claude Code · Tvastr · OpenClaw · custom agents       │
└───────────────┬─────────────────────────────────────────┘
                │  MCP over Unix socket (/run/setu/setu.sock)
                │  + agent identity (peer creds / token)
┌───────────────▼─────────────────────────────────────────┐
│                     setu broker                         │
│  ┌───────────┐ ┌──────────────┐ ┌────────────────────┐  │
│  │ Identity & │ │ Policy Engine│ │  Audit Logger      │  │
│  │ Session Mgr│ │ (deny-default│ │  (append-only,     │  │
│  │            │ │  rules DSL)  │ │   signed entries)  │  │
│  └───────────┘ └──────────────┘ └────────────────────┘  │
│  ┌──────────────────┐ ┌───────────────────────────────┐ │
│  │ Escalation Mgr    │ │ Snapshot / Rollback Manager   │ │
│  │ (HITL prompts)    │ │ (btrfs/ZFS/LVM, txn apply)    │ │
│  └──────────────────┘ └───────────────────────────────┘ │
└───────────────┬─────────────────────────────────────────┘
                │  internal tool dispatch
┌───────────────▼─────────────────────────────────────────┐
│              Built-in System MCP Servers                │
│  journal (read)  ·  systemd (query/act)  ·  pkg (query/ │
│  install)  ·  fs (scoped read/write)  ·  net (query)    │
│  + registration API for third-party system servers      │
└───────────────┬─────────────────────────────────────────┘
                │  native APIs
┌───────────────▼─────────────────────────────────────────┐
│    Linux: systemd, journald, apt/dnf/zypper, netlink,   │
│    filesystem, polkit (optional bridge)                 │
└─────────────────────────────────────────────────────────┘
```

## 4. Component Design

### 4.1 Broker daemon (`setu`)

- Runs as a systemd service (`setu.service`), privileged but heavily sandboxed itself (systemd hardening: `ProtectSystem=strict`, capability bounding, seccomp).
- Listens on a Unix domain socket; uses `SO_PEERCRED` for baseline caller identity (uid/gid/pid), plus optional per-agent tokens for finer identity ("Tvastr-fixer" vs "Tvastr-reviewer" under the same uid).
- Speaks standard MCP (JSON-RPC): agents use ordinary MCP clients — no custom SDK required. This is the adoption lever.
- Multiplexes built-in servers behind one endpoint; supports MCP discovery so agents enumerate only the tools their policy permits (least-privilege visibility, not just least-privilege execution).

### 4.2 Identity and sessions

- **Agent identity** = (uid, optional token, declared agent name). Tokens issued via `setuctl agent register`, stored hashed.
- Each connection opens a **session** with an immutable identity snapshot; policy is evaluated per session so a mid-run policy change applies on next connect, not mid-flight (predictability for long agent runs).
- Optional **task manifest** at session start: the agent declares its intent ("remediate lint errors in repo X"). v1 logs it; v2 can enforce against it (intent-scoped capabilities — the research-grade feature).

### 4.3 Policy engine

- **Deny by default.** No rule → no tool visible, no call permitted.
- Rules in a small declarative DSL (TOML/YAML), evaluated top-down, first match wins — deliberately polkit/sudoers-like so admins find it familiar.
- Decision outcomes: `allow`, `deny`, `ask` (human escalation), `allow_with_snapshot`.

Example policy sketch:

```toml
[[rule]]
agent   = "tvastr-*"
tool    = "journal.read"
action  = "allow"

[[rule]]
agent   = "tvastr-fixer"
tool    = "fs.write"
scope   = { path_prefix = "/srv/repos/" }
action  = "allow_with_snapshot"

[[rule]]
agent   = "*"
tool    = "systemd.restart"
units   = ["nginx.service"]
action  = "ask"          # human-in-the-loop

[[rule]]
agent   = "*"
tool    = "pkg.install"
action  = "deny"         # default posture; loosen per host
```

- Constraint types: path prefixes, unit allowlists, package allowlists (with signature requirements), rate limits (calls/minute), time windows.

### 4.4 Audit logger

- Every call → structured record: timestamp, session id, agent identity, tool, canonicalized arguments, policy rule matched, decision, result summary, snapshot id (if any).
- Append-only file (or journald namespace) with hash chaining per entry; optional periodic signing for tamper evidence.
- `setuctl audit query` for operators; export to SIEM as JSON lines.

### 4.5 Snapshot / rollback manager

- Before any `allow_with_snapshot` mutation: btrfs/ZFS snapshot of affected subvolume/dataset, or LVM snapshot, or file-level copy fallback.
- Snapshot id recorded in the audit entry → `setuctl rollback <call-id>` restores pre-call state.
- Package operations use the manager's native transaction where available (e.g., zypper/dnf history undo) instead of raw snapshots.

### 4.6 Escalation manager (human-in-the-loop)

- `ask` decisions block the call and notify: desktop notification, terminal prompt via `setuctl approve`, or webhook (Slack/Matrix) for servers.
- Approvals are single-call by default; optional TTL grants ("allow systemd.restart nginx for 1 hour").
- Timeouts default to deny.

### 4.7 Built-in system MCP servers (v1 set)

| Server | Tools (indicative) | Risk tier |
|---|---|---|
| `journal` | read/query logs, follow with filters | Low (read-only) |
| `systemd` | list/status units; start/stop/restart (policy-gated) | Medium/High |
| `pkg` | search/info; install/remove (policy-gated, allowlist) | High |
| `fs` | scoped read/write/list within policy path prefixes | Medium |
| `net` | interface/route/socket queries (read-only in v1) | Low |

Third-party system servers register with the broker via a manifest declaring their tools and risk tiers; the broker enforces policy uniformly regardless of who wrote the server.

## 5. Security Model

### 5.0 Deployment model — the one rule that makes everything work

**setu only secures anything if it is the agent's *only* door to the system.**

- The agent process runs confined: no shell, no direct filesystem access, no root. Concretely: a container, a lightweight VM, or a locked-down systemd unit (`NoNewPrivileges`, no shell binary, restricted mounts).
- Its single channel to system capabilities is the Unix socket to `setu`.
- The agent therefore starts with **zero** access, and every capability it has was explicitly *granted* by policy (additive) — rather than starting with full user access that we try to restrict (subtractive).
- If the agent keeps a raw shell alongside setu, the policy layer is decorative — it can simply bypass the broker. Confinement of the agent and the broker are two halves of one boundary.

### 5.1 Threat model

- **Threat model in scope:** prompt-injected or misbehaving agent attempting actions outside its task; compromised agent process attempting privilege expansion through setu; replay or spoofed identity on the socket.
- **Out of scope (v1):** kernel exploits, a compromised setu itself (mitigated by its own sandboxing, not eliminated), side channels.
- Key properties:
  1. Agents never receive credentials or raw root — only mediated tool results.
  2. Least-privilege *visibility*: undiscoverable tools reduce the prompt-injection surface ("call pkg.install" fails at discovery, not just execution).
  3. Canonicalized arguments (resolved paths, validated unit names) before policy evaluation — no string-matching bypasses via `../` or aliases.
  4. Broker is the single choke point → single place to audit, rate-limit, and kill-switch (`setuctl freeze <agent>`).

## 6. What Exists vs. What's Novel

| Prior art | What it provides | Gap setu fills |
|---|---|---|
| D-Bus / polkit | System bus + per-action authorization for humans/apps | Not MCP; no agent identity, intent, audit-for-LLM, or rollback semantics |
| SUSE SLES 16 agentic OS | OS-level MCP + policy + audit | Vendor-specific, enterprise stack; not portable or community-governed |
| AIOS (COLM 2025) | Agent resource management as an OS abstraction | Research kernel-layer framing; no production policy broker |
| AgenticOS (arXiv 2026) | Intent-based capability theory | No implementation; setu's task manifests are a practical on-ramp to it |
| Raw shell / CLI agents | Maximum flexibility | Ambient authority, no audit, no rollback — the exact problem |

**Novel contribution (publishable):** a deployed, distro-agnostic policy broker for agent–OS interaction with (a) least-privilege tool *discovery*, (b) snapshot-coupled mutations, and (c) a migration path from static rules to intent-scoped capabilities. Evaluation axes: policy-bypass resistance under prompt-injection test suites, overhead vs. raw shell, rollback correctness.

## 7. Roadmap

**Phase 0 — Spec (2–3 weeks):** finalize policy DSL, audit schema, identity model; write threat model doc; publish RFC-style design for feedback.

**Phase 1 — MVP broker (6–8 weeks):** broker daemon + `journal` and `systemd` (read-only) servers + policy engine + audit log + `setuctl`. Language: Go (decided; see [ADR 0001](decisions/0001-go-over-rust.md)). Deb/RPM packaging.

**Phase 2 — Mutation + rollback (6–8 weeks):** `fs` and `pkg` servers, snapshot manager, escalation manager, `allow_with_snapshot` path end-to-end. Tvastr integrated as first real consumer (Fixer writes only through `fs`, gated + snapshotted).

**Phase 3 — Ecosystem (ongoing):** third-party server registration API, NixOS module + immutable-distro reference image ("agent-ready Linux" spin), prompt-injection red-team suite, technical report / paper submission.

## 8. Relationship to Tvastr

Tvastr becomes setu's flagship consumer and the demonstration of the full story:

- Tvastr's Analyzer runs with read-only grants (`journal.read`, `fs.read`).
- The Fixer's writes go through `fs.write` under `allow_with_snapshot` — every remediation is reversible and audited.
- The Reviewer gains a new signal: the setu audit trail of exactly what the Fixer changed.
- Combined narrative: *an autonomous remediation agent operating entirely within a governed, reversible system boundary* — a materially stronger claim than "an agent that edits code."

## 9. Open Questions

1. ~~Rust vs. Go for the broker (safety vs. contributor velocity).~~ **Resolved: Go** — see [ADR 0001](decisions/0001-go-over-rust.md), including when Rust would become the right call.
2. Policy DSL: custom TOML rules vs. embedding an existing engine (OPA/Rego, Cedar) — familiarity vs. power.
3. Identity hardening beyond `SO_PEERCRED` + tokens: SPIFFE-style workload identity worth it in v1?
4. Should `ask` approvals integrate with polkit agents directly to reuse existing desktop prompt UX?
5. Governance: personal repo first, or propose under a neutral home (e.g., AAIF-adjacent) once the RFC lands?

---

*Draft for discussion — feedback welcome on the policy model (§4.3) and the v1 server set (§4.7) in particular.*
