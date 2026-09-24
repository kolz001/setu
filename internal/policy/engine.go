// Evaluation half of package policy: the Engine walks the parsed rules
// top-down for every call (Evaluate) and every discovery listing
// (ToolVisible). See policy.go for the DSL and its parsing.

package policy

import (
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/kolz001/setu/internal/identity"
)

// Args are the canonicalized, policy-relevant arguments of a tool call.
// Canonicalization (symlink/'..' resolution, unit/package-name validation)
// happens in the broker before evaluation, so constraints match real
// targets, not attacker-controlled strings. A value field is empty when the
// call carries no argument of that kind.
//
// The Takes* flags record which kinds the tool declares at all, whether or
// not this call supplied them. They let a constraint on an omitted argument
// fail closed: without them, "units = [nginx.service]" on journal.read
// would be satisfied by leaving unit out and reading every unit's logs.
type Args struct {
	Path    string // absolute canonical path, if the call has one
	Unit    string // validated systemd unit name, if any
	Package string // validated package name, if any

	TakesPath, TakesUnit, TakesPackage bool
}

// Decision is the outcome of evaluating one call.
type Decision struct {
	// Action is what the broker must do: allow, deny, ask, or
	// allow_with_snapshot.
	Action Action
	// RuleIndex is the zero-based index of the matched rule, or -1 for the
	// default deny. Recorded in the audit entry so operators can trace every
	// decision to a line of policy.
	RuleIndex int
	// Reason is a human-readable explanation, recorded in audit.
	Reason string
	// Scope is the canonical path prefix that authorized the call's path,
	// or empty when the matched rule has no path scope. The broker confines
	// filesystem handlers to it (see servers.WithScope), so a path swapped
	// for a symlink after evaluation still cannot reach outside the scope.
	Scope string
}

// Engine evaluates rules top-down, first match wins, deny by default.
//
// Concurrency: all methods are safe for concurrent use; a single mutex
// serializes evaluation, which also makes rate-limit accounting exact.
// Throughput is bounded by agent tool calls (single-digit per second), so
// contention is a non-issue by design.
type Engine struct {
	mu      sync.Mutex
	rules   []Rule
	limiter *limiter
	now     func() time.Time // injectable clock, fixed in tests
}

// Rules returns a copy of the rule list (for status and introspection; the
// copy keeps callers from mutating engine state).
func (e *Engine) Rules() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Rule(nil), e.rules...)
}

// Reload swaps in the rule set of a freshly parsed engine, atomically with
// respect to Evaluate/ToolVisible: every evaluation sees either the old or
// the new rules in full, never a mix. Rate-limiter state resets (windows
// restart); in-flight evaluations complete under whichever rule set they
// started with.
func (e *Engine) Reload(from *Engine) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = from.Rules()
	e.limiter = newLimiter()
}

// globMatch reports whether s matches the path.Match pattern; a malformed
// pattern matches nothing (Parse validates patterns, so this is belt and
// braces).
func globMatch(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}

// ruleApplies checks the identity-and-tool half of a rule: agent glob, tool
// glob, uid pin, and token requirement. Argument constraints and rate are
// checked separately so ToolVisible can reuse this.
func ruleApplies(r *Rule, id identity.Identity, tool string) bool {
	if !globMatch(r.Agent, id.Name) {
		return false
	}
	if !globMatch(r.Tool, tool) {
		return false
	}
	if r.UID != nil && *r.UID != id.Peer.UID {
		return false
	}
	if r.RequireToken && !id.Authenticated {
		return false
	}
	return true
}

// argsMatch checks a rule's argument constraints against the call's
// canonicalized arguments, returning whether they hold and, for a path
// scope, the prefix that covered the path (the longest, when several do).
//
// A constraint on an argument kind the tool does not take at all is
// treated as matching: it narrows targets, and the tool has none of that
// kind (so "systemd.*" with a unit allowlist still covers list_units). A
// constraint on a kind the tool takes but the call omitted does NOT match:
// the call would otherwise escape the constraint by leaving the argument
// out.
func argsMatch(r *Rule, a Args) (bool, string) {
	scope := ""
	if ps := prefixes(r.Scope); len(ps) > 0 && (a.Path != "" || a.TakesPath) {
		if a.Path == "" {
			return false, ""
		}
		for _, p := range ps {
			if pathHasPrefix(a.Path, p) && len(p) > len(scope) {
				scope = p
			}
		}
		if scope == "" {
			return false, ""
		}
	}
	if len(r.Units) > 0 && (a.Unit != "" || a.TakesUnit) && !contains(r.Units, a.Unit) {
		return false, ""
	}
	if len(r.Packages) > 0 && (a.Package != "" || a.TakesPackage) && !contains(r.Packages, a.Package) {
		return false, ""
	}
	return true, scope
}

// pathHasPrefix is a path-component-aware prefix check: "/srv/repos" covers
// "/srv/repos" and "/srv/repos/x" but not "/srv/repos-evil". Both sides are
// already canonical (see pathutil.Canonical), so string comparison is sound.
func pathHasPrefix(p, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return true // prefix "/" scopes to everything
	}
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// contains reports whether s is an element of l (allowlists are short;
// linear scan is fine).
func contains(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}

// inWindow reports whether the engine's current local time falls inside w
// (nil means unconstrained). Windows are [after, before) and may wrap
// midnight.
func (e *Engine) inWindow(w *TimeWindow) bool {
	if w == nil {
		return true
	}
	now := e.now().Local()
	cur := now.Hour()*60 + now.Minute()
	after := hm(w.After)
	before := hm(w.Before)
	if after <= before {
		return cur >= after && cur < before
	}
	return cur >= after || cur < before // wraps midnight
}

// hm converts a pre-validated "HH:MM" string to minutes since midnight.
func hm(s string) int {
	t, _ := time.Parse("15:04", s)
	return t.Hour()*60 + t.Minute()
}

// Evaluate returns the decision for one canonicalized call: the first rule
// (top-down) whose identity, tool, argument constraints, and time window all
// match decides the action. No match is the default deny (RuleIndex -1).
//
// Rate limits are enforced at match time: if the winning rule has one and
// the (agent, rule) window is exhausted, the result is a deny attributed to
// that rule — not a fall-through, which would let a later broader rule
// silently take over.
func (e *Engine) Evaluate(id identity.Identity, tool string, a Args) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.rules {
		r := &e.rules[i]
		if !ruleApplies(r, id, tool) {
			continue
		}
		ok, scope := argsMatch(r, a)
		if !ok {
			continue
		}
		if !e.inWindow(r.Time) {
			continue // outside the rule's time window: fall through
		}
		if r.Action != Deny && r.Rate != nil {
			key := fmt.Sprintf("%s|%d", id.Name, i)
			if !e.limiter.allow(key, r.Rate.CallsPerMinute, e.now()) {
				return Decision{Action: Deny, RuleIndex: i,
					Reason: fmt.Sprintf("rate limit exceeded (%d calls/minute, rule %d)", r.Rate.CallsPerMinute, i)}
			}
		}
		return Decision{Action: r.Action, RuleIndex: i, Reason: fmt.Sprintf("rule %d", i), Scope: scope}
	}
	return Decision{Action: Deny, RuleIndex: -1, Reason: "no matching rule (deny by default)"}
}

// ToolVisible reports whether the agent should see this tool in tools/list.
//
// Least-privilege visibility: a tool is listed only if some rule could allow
// it, shrinking the prompt-injection surface — "call pkg.install" fails at
// discovery, not just execution. Iteration mirrors Evaluate: an
// unconditional deny reached first hides the tool definitively; a
// potentially-allowing rule (any action but deny) reveals it. Argument
// constraints are ignored here — a scoped allow still lists the tool, since
// some calls could succeed — and so are time windows and rate limits, which
// vary call to call.
func (e *Engine) ToolVisible(id identity.Identity, tool string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.rules {
		r := &e.rules[i]
		if !ruleApplies(r, id, tool) {
			continue
		}
		if r.Action == Deny {
			// A deny with argument constraints only blocks some targets;
			// keep scanning. An unconstrained deny is definitive.
			if r.Scope == nil && len(r.Units) == 0 && len(r.Packages) == 0 {
				return false
			}
			continue
		}
		return true
	}
	return false
}

// limiter implements sliding one-minute-window rate limiting, keyed by
// (agent name, rule index). State is in-memory only: restarts and policy
// reloads reset windows, which errs on the permissive side for at most one
// minute. Guarded by Engine.mu.
type limiter struct {
	calls map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{calls: map[string][]time.Time{}} }

// allow records a call at time now if fewer than perMinute calls remain in
// key's trailing one-minute window, pruning expired timestamps as it goes.
func (l *limiter) allow(key string, perMinute int, now time.Time) bool {
	cutoff := now.Add(-time.Minute)
	kept := l.calls[key][:0]
	for _, t := range l.calls[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= perMinute {
		l.calls[key] = kept
		return false
	}
	l.calls[key] = append(kept, now)
	return true
}
