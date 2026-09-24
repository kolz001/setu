// Package policy implements setu's deny-by-default rule engine.
//
// Rules live in a small declarative TOML DSL and are evaluated top-down,
// first match wins — deliberately polkit/sudoers-like so system
// administrators find the semantics familiar. The important properties:
//
//   - Deny by default. A call with no matching rule is denied, and a tool
//     with no potentially-allowing rule is invisible to the agent
//     (Engine.ToolVisible).
//   - Constraints narrow matching; they do not deny. A rule whose scope or
//     allowlist doesn't cover the call's target simply doesn't match, and
//     evaluation falls through to later rules (firewall-style).
//   - The engine only ever sees canonicalized arguments (absolute
//     symlink-resolved paths, validated unit/package names) — see package
//     pathutil and the broker's canonicalize step.
//
// This file covers parsing and validation; engine.go covers evaluation.
package policy

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/kolz001/setu/internal/pathutil"
)

// Action is a policy decision outcome, the value of a rule's `action` key.
type Action string

// The four rule actions. AllowWithSnapshot behaves like Allow but forces a
// pre-mutation snapshot; if the snapshot cannot be taken, the call is
// refused (reversibility is the contract, not a best effort).
const (
	Allow             Action = "allow"
	Deny              Action = "deny"
	Ask               Action = "ask" // block pending human approval; timeout denies
	AllowWithSnapshot Action = "allow_with_snapshot"
)

// valid reports whether a is one of the defined actions.
func (a Action) valid() bool {
	switch a {
	case Allow, Deny, Ask, AllowWithSnapshot:
		return true
	}
	return false
}

// StringList is a []string that also accepts a single TOML string, so
// admins can write `path_prefix = "/srv"` or `path_prefix = ["/srv", "/opt"]`
// interchangeably.
type StringList []string

// UnmarshalTOML implements toml.Unmarshaler.
func (s *StringList) UnmarshalTOML(v any) error {
	switch t := v.(type) {
	case string:
		*s = []string{t}
	case []any:
		for _, e := range t {
			str, ok := e.(string)
			if !ok {
				return fmt.Errorf("expected string, got %T", e)
			}
			*s = append(*s, str)
		}
	default:
		return fmt.Errorf("expected string or array of strings, got %T", v)
	}
	return nil
}

// Scope constrains a rule to filesystem targets under the given prefixes.
// Prefixes are canonicalized at load time (symlinks resolved) and compared
// component-wise: "/srv/repos" covers "/srv/repos/x" but not
// "/srv/repos-evil".
type Scope struct {
	PathPrefix StringList `toml:"path_prefix"`
}

// Rate limits how often the matching rule may fire: a sliding one-minute
// window per (agent, rule). Exceeding it is a hard deny (audited as
// rate-limited), not a fall-through — otherwise a later, broader rule could
// silently take over once the limit trips.
type Rate struct {
	CallsPerMinute int `toml:"calls_per_minute"`
}

// TimeWindow constrains when a rule matches, in the daemon's local time,
// "HH:MM" inclusive-start exclusive-end. A window may wrap midnight
// (after="22:00", before="06:00"). Outside the window the rule is skipped
// (fall-through), consistent with other constraints.
type TimeWindow struct {
	After  string `toml:"after"`
	Before string `toml:"before"`
}

// Rule is one policy entry.
//
// Agent and Tool are glob patterns in path.Match syntax; '*' does not match
// '/' but paths never appear in these names, and '.' is an ordinary
// character, so "tvastr-*" and "journal.*" behave as expected.
//
// The zero value is not a valid rule; Parse enforces that agent, tool, and
// a valid action are present.
type Rule struct {
	// Agent matches the session's effective agent name.
	Agent string `toml:"agent"`
	// Tool matches the tool being called (e.g. "fs.write", "systemd.*").
	Tool string `toml:"tool"`
	// Action is what happens when this rule is the first match.
	Action Action `toml:"action"`
	// UID, if set, additionally requires the peer's kernel uid to match.
	UID *int `toml:"uid"`
	// RequireToken, if true, makes the rule match only token-authenticated
	// sessions (a self-declared name is not enough).
	RequireToken bool `toml:"require_token"`
	// Scope constrains path arguments (see Scope).
	Scope *Scope `toml:"scope"`
	// Units is an allowlist for systemd unit arguments.
	Units StringList `toml:"units"`
	// Packages is an allowlist for package-name arguments.
	Packages StringList `toml:"packages"`
	// Rate, if set, rate-limits this rule (see Rate).
	Rate *Rate `toml:"rate"`
	// Time, if set, restricts the rule to a local-time window.
	Time *TimeWindow `toml:"time"`
	// Comment is free-form admin documentation, ignored by the engine.
	Comment string `toml:"comment"`
}

// File is the top-level structure of a policy document: a list of
// [[rule]] tables.
type File struct {
	Rule []Rule `toml:"rule"`
}

// Load reads and parses the policy file at path. See Parse for validation
// semantics.
func Load(path string) (*Engine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse parses and validates policy TOML, returning a ready Engine.
//
// Validation is strict and fail-closed: unknown keys (typos), invalid
// actions, malformed glob patterns, non-absolute or unresolvable scope
// prefixes, bad time formats, and non-positive rates all reject the whole
// document. A daemon must not start (and a reload must not apply) with a
// policy the admin didn't fully express.
//
// Scope prefixes are canonicalized here with the same resolution the broker
// applies to call paths (e.g. macOS "/tmp" → "/private/tmp"), so admins can
// write the path they know and comparisons stay like-for-like.
func Parse(b []byte) (*Engine, error) {
	var f File
	md, err := toml.Decode(string(b), &f)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		return nil, fmt.Errorf("policy: unknown keys: %v (typo in a rule?)", undec)
	}
	for i, r := range f.Rule {
		if r.Agent == "" {
			return nil, fmt.Errorf("policy rule %d: missing agent", i)
		}
		if r.Tool == "" {
			return nil, fmt.Errorf("policy rule %d: missing tool", i)
		}
		if !r.Action.valid() {
			return nil, fmt.Errorf("policy rule %d: invalid action %q (allow|deny|ask|allow_with_snapshot)", i, r.Action)
		}
		if _, err := path.Match(r.Agent, "x"); err != nil {
			return nil, fmt.Errorf("policy rule %d: bad agent pattern %q", i, r.Agent)
		}
		if _, err := path.Match(r.Tool, "x"); err != nil {
			return nil, fmt.Errorf("policy rule %d: bad tool pattern %q", i, r.Tool)
		}
		if r.Time != nil {
			for _, hm := range []string{r.Time.After, r.Time.Before} {
				if _, err := time.Parse("15:04", hm); err != nil {
					return nil, fmt.Errorf("policy rule %d: bad time %q (want HH:MM)", i, hm)
				}
			}
		}
		if r.Rate != nil && r.Rate.CallsPerMinute <= 0 {
			return nil, fmt.Errorf("policy rule %d: rate.calls_per_minute must be positive", i)
		}
		for j, p := range prefixes(r.Scope) {
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("policy rule %d: scope.path_prefix %q must be absolute", i, p)
			}
			canon, err := pathutil.Canonical(p)
			if err != nil {
				return nil, fmt.Errorf("policy rule %d: scope.path_prefix %q: %v", i, p, err)
			}
			f.Rule[i].Scope.PathPrefix[j] = canon
		}
	}
	return &Engine{rules: f.Rule, limiter: newLimiter(), now: time.Now}, nil
}

// prefixes returns s's path prefixes, tolerating a nil scope.
func prefixes(s *Scope) []string {
	if s == nil {
		return nil
	}
	return s.PathPrefix
}
