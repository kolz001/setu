# ADR 0001: Implementation language — Go over Rust

**Status:** accepted (July 2026)
**Context:** the architecture draft left the broker language open ("Rust
(safety case for a privileged broker) or Go (velocity); decide in Phase 0").

## Decision

Implement setu in Go.

## Rationale

### 1. The broker's actual risk is logic, not memory

setu's security-critical work is policy evaluation, identity resolution,
argument canonicalization, and audit integrity. Every historical failure mode
we care about — a rule matching too broadly, a path prefix check bypassable
via symlink, an unaudited deny path, token confusion between agents — is a
logic bug. Rust's ownership model prevents none of them.

The class of bugs Rust *does* eliminate beyond Go (data races; Go is already
memory-safe with respect to buffer overflows, use-after-free, and pointer
arithmetic) is narrow here: the broker's concurrency is deliberately boring —
one goroutine per connection, mutex-guarded registries, a channel per pending
approval — with per-call throughput measured in single-digit requests per
second. `go test -race` covers the remainder in CI.

### 2. Velocity toward the real open questions

Phase 0/1's genuine risks are design questions: is the TOML DSL expressive
enough? Does the ask flow have acceptable UX? Are file-copy snapshots the
right reversibility granularity? These only get answered by running the
broker against real agents. Go got us a complete, tested MVP (broker, five
servers, policy engine, audit chain, escalation, CLI) in one pass; the same
scope in Rust would have traded that iteration speed for assurances the v0
design doesn't yet deserve — most of this code will be reshaped by feedback.

### 3. Domain fit

The daemon is Unix plumbing: peer-credential sockets, exec-ing systemctl /
journalctl / package managers with argv vectors, JSON-RPC framing, TOML
config. Go's standard library covers essentially all of it — the project has
exactly two third-party dependencies (BurntSushi/toml, golang.org/x/sys).
Static single-binary output per architecture keeps deb/rpm/Nix packaging
trivial, which is load-bearing for the "distro-agnostic" goal.

### 4. Contributor surface

setu wants third-party system servers and distro packagers. The pool of
contributors fluent in systems-plumbing Go (the docker/kubernetes/systemd
tooling ecosystem) is materially larger than the equivalent Rust pool, and
the codebase stays readable to security reviewers who are not Rust experts.

## What we give up

- Rust's compile-time freedom from data races and its stronger story for a
  long-lived privileged daemon.
- Security-community signaling ("written in Rust" carries weight in exactly
  the audience setu courts).
- GC pauses — irrelevant at this throughput, listed for completeness.

## Mitigations

- No shell interpolation anywhere: system binaries are exec'd with argv
  vectors only, after canonicalization and syntax validation of every
  policy-relevant argument.
- The daemon ships with a strict systemd sandbox (`ProtectSystem=strict`,
  syscall filtering, bounded capabilities) so a broker compromise is
  contained by the OS, not only by the language.
- `-race` in CI; the concurrency inventory is small and documented.
- The durable artifacts are the **wire contracts** — policy TOML schema,
  audit entry schema and hash chain, MCP framing, control API. A future Rust
  rewrite of the core behind the same contracts stays feasible if the
  project's threat profile ever demands it.

## Evidence since the decision

The pre-release security review (September 2026) found three
vulnerabilities, all fixed before the first public release:

1. A dangling symlink inside a granted scope let `fs.write` create a file
   outside it.
2. Omitting a constrained argument (e.g. `unit` on `journal.read`) satisfied
   an allowlist instead of failing it.
3. One oversized call from any local user wrote an audit line too long to
   re-read, stopping the daemon from restarting.

All three are logic and resource-bounding bugs, and Rust would have
compiled every one of them. That is the premise of point 1 above, borne
out: what protects setu is its tests and review of path handling, policy
semantics, and input bounds, not the language.

## Is the future Rust?

**Not by default — and not as a rewrite for its own sake.** Go stays the
implementation language while setu's risk is dominated by logic in a
local, single-host broker. Rust becomes the right call if the threat
profile changes in one of these specific ways:

| Trigger | Why it changes the answer | Likely shape |
|---|---|---|
| Remote transport (TCP/TLS, multi-host) | Network-reachable parsing in a privileged process raises exploitation stakes; memory-safety guarantees beyond Go's and freedom from data races start to carry real weight | Rust front-end (transport, framing, auth) in front of the existing core |
| Third-party in-process plugins | Running untrusted code in the broker needs strong isolation | WASM plugin host, most mature from Rust (wasmtime); servers stay out-of-process until then |
| Much larger concurrency surface (high-throughput, shared hot state) | Data races become a realistic bug class, which Rust rules out at compile time | Targeted Rust components, not the whole daemon |
| Adopters who require it (distro, regulated environment) | Being written in Rust counts with this audience | Incremental port behind the wire contracts |

Why a move, if it comes, would be incremental rather than a big-bang
rewrite: the durable artifacts are the **wire contracts** — policy TOML,
audit entry schema and hash chain, MCP framing, control API — and the
end-to-end test suite that exercises them over the socket. A Rust
component can replace a Go one behind the same contract and be proven
equivalent by the same tests. The policy engine is the natural first
candidate (pure, well-tested, no I/O), which could also be exposed as a
library for other brokers.

What would *not* justify a move: Rust's popularity, or a general feeling
that security software "should" be in Rust. The review above is the
counter-evidence: the bugs that matter here are ones no compiler catches.

## Revisit when

- The broker grows remote (non-local-socket) transport, raising the
  exploitation stakes.
- Third-party in-process plugins are considered (Rust/WASM isolation would
  become relevant; today third-party servers are out-of-process by design).
- Concurrency or throughput requirements grow well beyond one call at a
  time per agent session.
