# Setu

*Sanskrit for "bridge" — formerly `mcpd`.*

**D-Bus for the agent era.** A policy-governed broker daemon that exposes core Linux system capabilities to AI agents as MCP servers — with per-agent authorization, hash-chained audit trails, snapshot-coupled mutations, and human-in-the-loop escalation built in.

AI agents operating through a raw shell hold **ambient authority**: everything their uid can do, unscoped, unaudited, irreversible. setu replaces that with a single governed endpoint: agents start with **zero** access and every capability they hold was explicitly granted by policy.

```
Agents (Claude Code, Tvastr, custom)          Operator
        │  MCP over unix socket                  │ setuctl
        │  + peer creds / token                  │
┌───────▼─────────────────────────────────┬──────▼──────┐
│  broker: identity → canonicalize →      │ control     │
│  policy (deny-default) → ask/snapshot → │ plane       │
│  execute → audit (hash-chained)         │ (owner-only)│
├─────────────────────────────────────────┴─────────────┤
│  built-in servers: journal · systemd · fs · pkg · net │
└────────────────────────────────────────────────────────┘
```

## Status

Working MVP (v0.1.0): everything below runs today, on Linux with real system backends (journalctl, systemctl, apt/dnf/zypper/pacman, ip/ss) and on macOS/dev machines with mock backends auto-substituted. See [docs/architecture.md](docs/architecture.md) for the full design and roadmap.

- **Deny-by-default policy** — TOML rules, top-down, first match wins; constraints on path prefixes, unit allowlists, package allowlists, rate limits, time windows, uid, token-authentication
- **Least-privilege discovery** — `tools/list` only shows tools the agent's policy could allow; a prompt-injected "call pkg.install" fails at discovery, not just execution
- **Argument canonicalization before policy** — paths made absolute with `..` and symlinks resolved, unit/package names syntax-validated; no string-matching bypasses
- **Hash-chained audit log** — every call (including denies) is one JSONL entry chained by SHA-256; edits, removals, and truncation are detectable via `setuctl audit verify`
- **Snapshot-coupled mutation** — `allow_with_snapshot` captures pre-call file state first (no snapshot → no mutation) and `setuctl rollback <id>` restores it
- **Human-in-the-loop** — `ask` blocks the call until `setuctl approve`/`deny`; timeout defaults to deny; approvals can carry a TTL grant
- **Agent identity** — kernel peer credentials (SO_PEERCRED / LOCAL_PEERCRED) plus registered per-agent tokens (stored hashed, shown once); registered names cannot be assumed without the token
- **Kill switch** — `setuctl freeze <agent>` denies everything from that identity instantly
- **Live policy reload** — `setuctl policy reload` re-parses the policy file into the running broker (atomic rule-set swap; invalid files are rejected and the old rules stay)

## Quickstart (any machine)

```sh
go build ./cmd/...

# 1. start the daemon with the dev policy (mock backends on non-Linux)
./setu --policy examples/policy-dev.toml \
       --state-dir /tmp/setu-state &

# 2. see what a given identity is allowed to discover
./setuctl tools --agent demo

# 3. read logs (allowed), then try something not granted (denied + audited)
./setuctl call journal.read '{"lines": 5}' --agent demo
./setuctl call pkg.install '{"package": "htop"}' --agent demo   # → denied

# 4. a snapshotted write, then roll it back
mkdir -p /tmp/setu-demo
./setuctl call fs.write '{"path":"/tmp/setu-demo/a.txt","content":"v1"}' --agent demo
./setuctl snapshots
./setuctl rollback <snapshot-id>

# 5. human-in-the-loop: this blocks until approved in another terminal
./setuctl call systemd.restart '{"unit":"nginx.service"}' --agent demo &
./setuctl approvals
./setuctl approve <id>          # or: deny <id>; --ttl 30m adds a grant

# 6. inspect and verify the audit trail
./setuctl audit query --last 10
./setuctl audit verify
```

### Registered agents (token identity)

```sh
./setuctl agent register tvastr-fixer        # prints the token once
SETU_TOKEN=<token> ./setuctl call fs.write '…' --agent tvastr-fixer
```

Once a name is registered, connections claiming it without the token are rejected at `initialize`. Tokens can be pinned to a uid (`--uid`).

### Connecting a real MCP client

Any stdio-transport MCP client can use the broker through the bridge:

```sh
claude mcp add setu -- setuctl proxy --agent my-agent --token $SETU_TOKEN
```

The proxy injects the agent identity into `initialize` `_meta.setu`; everything else passes through verbatim. Native socket clients connect to `/run/setu/setu.sock` directly.

## Policy

```toml
[[rule]]
agent  = "tvastr-*"          # glob on agent name
tool   = "journal.read"      # glob on tool name
action = "allow"             # allow | deny | ask | allow_with_snapshot

[[rule]]
agent         = "tvastr-fixer"
tool          = "fs.write"
require_token = true                          # only authenticated identity
scope         = { path_prefix = "/srv/repos" }  # component-aware prefix
action        = "allow_with_snapshot"

[[rule]]
agent  = "*"
tool   = "systemd.restart"
units  = ["nginx.service"]   # constraint mismatch falls through, not deny
action = "ask"

[[rule]]
agent  = "*"
tool   = "systemd.list_units"
rate   = { calls_per_minute = 30 }
time   = { after = "09:00", before = "17:00" }
action = "allow"
```

Semantics worth knowing:

- **First match wins, deny by default.** No matching rule → the call is denied and the tool isn't even listed.
- **Constraints narrow matching, they don't deny.** An out-of-scope path falls through to later rules (usually to the default deny) — firewall-style.
- **Omitting a constrained argument doesn't satisfy the constraint.** A `units` allowlist on `journal.read` matches only calls that name an allowlisted unit; a call that leaves `unit` out falls through. (A constraint on an argument kind the tool doesn't take at all, e.g. `units` on `systemd.list_units`, is ignored.)
- **Prefixes are component-aware.** `/srv/repos` matches `/srv/repos/x` but not `/srv/repos-evil`.
- **Canonicalization happens first.** Policy sees the symlink-resolved absolute path, never the agent's raw string. Dangling symlinks are rejected, and `fs` handlers run inside an `os.Root` anchored at the matched scope, so a symlink swapped in after the policy check still can't lead out of it.
- **Unregistered agent names are self-declared.** Any local user who can reach the socket can claim one. Use `require_token = true` or a `uid` pin on rules that must tell callers apart.

## Built-in servers

| Server | Tools | Notes |
|---|---|---|
| `journal` | `journal.read` | read-only; journalctl |
| `systemd` | `list_units`, `status`, `start`, `stop`, `restart` | mutations policy-gated |
| `fs` | `read`, `list`, `write`, `mkdir` | scoped by `path_prefix`; write/mkdir snapshot-eligible |
| `pkg` | `search`, `info`, `install`, `remove` | apt/dnf/zypper/pacman/brew auto-detected; mutations deny-by-default posture |
| `net` | `interfaces`, `routes`, `sockets` | read-only in v1 |

Backends auto-detect: on hosts without journalctl/systemctl (e.g. a dev Mac) mock backends serve synthetic data so policies and integrations can be developed anywhere. `--backend mock` forces all-mock.

## Security model (the one rule)

**setu only secures anything if it is the agent's only door to the system.** Run the agent confined — container, VM, or a locked-down systemd unit with no shell — with the broker socket as its single channel. Confinement of the agent and policy at the broker are two halves of one boundary; an agent that keeps a raw shell can simply walk around the broker. `packaging/setu.service` ships with the broker's own sandboxing (ProtectSystem=strict, syscall filter, bounded capabilities).

Threat model, properties, and non-goals: [docs/architecture.md §5](docs/architecture.md).

## Why Go (and not Rust)

Both were serious candidates ([decision record](docs/decisions/0001-go-over-rust.md)). Go won on the grounds that matter for *this* codebase at *this* stage:

1. **The broker's risk profile is logic, not memory.** setu is a policy gateway: its failure modes are wrong policy evaluation, missed audit entries, identity confusion — logic bugs a borrow checker doesn't catch. Go is memory-safe too (GC, no pointer arithmetic); Rust's additional guarantee — freedom from data races — matters, but the broker's concurrency is a handful of well-worn patterns (mutex-guarded maps, channel per pending approval) at trivial throughput: one JSON-RPC call at a time per agent, no shared-state hot paths.
2. **Velocity to a falsifiable MVP.** The open questions (policy DSL ergonomics, ask-flow UX, snapshot semantics) are design risks, not implementation risks. Getting a working broker into the hands of real agents fast is worth more than maximal assurance on v0 code that will be reshaped by feedback.
3. **The domain is process orchestration and plumbing.** Unix sockets with peer creds, exec-ing systemctl/journalctl/package managers, JSON everywhere: Go's stdlib covers all of it; the whole project has two dependencies (TOML parsing, x/sys). Contributor pool for systems-plumbing Go is also broader — relevant for a project that wants community server contributions.
4. **Single static binary per arch** keeps deb/rpm/Nix packaging trivial, matching the distro-agnostic goal.

What we give up, honestly: Rust's stronger compile-time story for a long-lived privileged daemon and its cachet with the security community. Mitigations: the broker never constructs shell commands (argv-only exec), runs under a strict systemd sandbox, and the protocol surface is small enough that a future Rust rewrite of the core (keeping the wire contracts: policy TOML, audit schema, MCP framing) remains feasible if the project earns it. The interfaces, not the language, are the durable artifact.

**Will setu move to Rust?** Not by default. The pre-release review's three security bugs (a symlink scope escape, an allowlist bypass, an audit-log denial of service) were all logic bugs that Rust would have compiled just the same. Rust becomes the right choice if the threat profile changes: remote network transport, untrusted in-process plugins (a WASM host), or a much larger concurrency surface. Even then the plan is an incremental port behind the same wire contracts and e2e tests, not a rewrite. Details: [ADR 0001 — Is the future Rust?](docs/decisions/0001-go-over-rust.md#is-the-future-rust)

## Layout

```
cmd/setu            daemon entrypoint
cmd/setuctl         operator CLI + MCP test client + stdio proxy
internal/broker     session handling, governed call pipeline, canonicalization
internal/policy     TOML DSL, deny-default first-match engine, rate limits
internal/identity   peer credentials (linux/darwin), token registry
internal/audit      hash-chained JSONL log: append, query, verify
internal/snapshot   pre-mutation capture + rollback
internal/escalate   ask flow: pending approvals, TTL grants
internal/servers    journal/systemd/fs/pkg/net servers, real + mock backends
internal/control    owner-only admin socket (setuctl's API)
internal/daemon     wiring; embedded by cmd/setu and the e2e tests
```

## Development

Requires Go 1.25+.

```sh
go build ./...
go test ./...        # unit + full end-to-end broker tests (run anywhere)
go vet ./...
```

The e2e suite (`internal/daemon/e2e_test.go`) boots a real daemon on a temp socket with mock backends and exercises discovery filtering, deny-default, scope traversal attacks, snapshot/rollback, ask/approve, freeze, token auth, and audit-chain verification.

### Documentation standards

Code documentation follows godoc conventions, enforced at review:

- Every package has a package comment covering its purpose, and where relevant its concurrency model and security invariants.
- Every exported type, function, method, constant, and struct field has a doc comment beginning with the identifier's name. Functions document error semantics and blocking behavior when non-obvious.
- Unexported helpers get a comment when they encode a decision (why, not what); mechanical one-liners may go bare.
- Security-relevant behavior (canonicalize-before-policy, argv-only exec, fail-closed paths, socket permission rationale) is documented at the site that implements it, not only in this README.

## Roadmap

Done:

- [x] The broker, policy rules, audit log, and the `setuctl` admin tool
- [x] File and package tools, undo for file changes, and asking a human before risky actions

Next:

- [ ] Test on real Linux machines (today's tests use simulated system tools)
- [ ] Faster, safer undo using filesystem snapshots, and undo for package installs
- [ ] Let other people plug in their own tools
- [ ] Let an agent declare its task up front, and limit it to only what that task needs
- [ ] Approval requests by desktop notification or chat message, not just the command line
- [ ] Install packages for common Linux distributions
- [ ] A test suite of prompt-injection attacks

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
