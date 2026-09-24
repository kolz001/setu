// Package servers defines setu's built-in system MCP servers — journal,
// systemd, fs, pkg, net — and the registry the broker dispatches through.
//
// Two design rules run through every server here:
//
//   - Declarative security metadata. Each Tool declares which of its
//     arguments are paths / unit names / package names (ArgKinds) so the
//     broker canonicalizes and validates them *before* policy evaluation —
//     constraints match real targets, not attacker-controlled strings — and
//     whether it mutates state (Mutating/SnapshotArgs), which drives
//     allow_with_snapshot.
//
//   - Pluggable backends. Every server that touches a system facility is
//     defined against a small backend interface with two implementations: a
//     real one that execs the native tool (journalctl, systemctl, apt/dnf/
//     zypper/pacman/brew, ip/ss) and a mock serving synthetic data, so the
//     whole broker runs and tests identically on hosts without those
//     facilities (developer Macs, CI). Selection happens in package daemon.
//
// Handlers never construct shell command lines; system binaries are exec'd
// with argv vectors only (see runCmd).
package servers

import (
	"context"
	"fmt"
	"regexp"
	"sort"
)

// ArgKind classifies a tool argument for pre-policy canonicalization. The
// broker rewrites/validates every argument a tool declares here before the
// policy engine sees the call; arguments without a kind pass through
// untouched (and are invisible to policy constraints).
type ArgKind string

const (
	ArgPath    ArgKind = "path"    // canonicalized to an absolute, symlink-resolved path
	ArgUnit    ArgKind = "unit"    // validated systemd unit name
	ArgPackage ArgKind = "package" // validated package name
)

// Handler executes a tool call and returns a plain-text result or an error
// (surfaced to the agent as a tool-level error, and summarized in audit).
// Arguments arrive already canonicalized per the tool's ArgKinds. The
// context carries the broker's per-call timeout; handlers that shell out
// must respect it (runCmd does).
type Handler func(ctx context.Context, args map[string]any) (string, error)

// Tool is one registered capability: an MCP tool descriptor plus the
// broker-facing metadata (canonicalization spec, mutation/snapshot
// behavior) that governs how calls to it are processed.
type Tool struct {
	// Name is the dotted tool identifier, e.g. "fs.write"; the server prefix
	// before the dot groups tools and is what policy globs like "fs.*" match.
	Name string
	// Description is shown to agents in tools/list; state risk posture here
	// ("Read-only.", "Mutating; policy-gated.") since it steers model choices.
	Description string
	// InputSchema is the JSON Schema for Arguments (see the schema helper).
	InputSchema map[string]any
	// ArgKinds maps argument name → kind for pre-policy canonicalization.
	ArgKinds map[string]ArgKind
	// Mutating marks tools that change system state. Only mutating tools
	// trigger snapshots under allow_with_snapshot.
	Mutating bool
	// SnapshotArgs names the path-kind arguments whose targets are captured
	// before a snapshot-gated call runs. Empty for mutating tools whose
	// reversibility comes from elsewhere (e.g. pkg via manager transactions).
	SnapshotArgs []string
	// Handler executes the call.
	Handler Handler
}

// Registry is the broker's tool table, assembled once at daemon startup and
// read-only afterwards (hence no locking).
type Registry struct {
	tools map[string]*Tool
}

// NewRegistry returns an empty tool table.
func NewRegistry() *Registry { return &Registry{tools: map[string]*Tool{}} }

// Register adds tools to the table. Duplicate names are a wiring bug in
// daemon startup, so it panics rather than returning an error.
func (r *Registry) Register(tools ...*Tool) {
	for _, t := range tools {
		if _, dup := r.tools[t.Name]; dup {
			panic(fmt.Sprintf("duplicate tool %q", t.Name))
		}
		r.tools[t.Name] = t
	}
}

// Get returns the tool named name, and whether it exists.
func (r *Registry) Get(name string) (*Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// All returns every registered tool, sorted by name for stable listings.
func (r *Registry) All() []*Tool {
	out := make([]*Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// --- shared helpers ---

// strArg returns args[key] as a string, or "" when absent or not a string.
// Handlers treat "" as "argument not provided".
func strArg(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}

// intArg returns args[key] as an int, or def when absent or non-numeric.
// JSON numbers arrive as float64 after unmarshaling into map[string]any,
// which is the case this helper exists to normalize.
func intArg(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return def
}

// schema builds the JSON-Schema object for a tool's InputSchema from its
// property map and required-property names, keeping tool definitions terse.
func schema(required []string, props map[string]any) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// unitRe matches "name.type" for systemd's unit types. The character class
// covers legal unit-name characters (including template '@' and escaped
// '\x2d' sequences) while excluding whitespace and shell metacharacters, so
// a validated unit name is safe to pass as a single argv element.
var unitRe = regexp.MustCompile(`^[a-zA-Z0-9:_.\\@-]+\.(service|socket|timer|target|mount|path|slice|scope)$`)

// ValidUnit reports whether s is a plausible systemd unit name. Called
// during broker canonicalization, before policy evaluation, so unit
// allowlists compare against validated names only.
func ValidUnit(s string) bool { return unitRe.MatchString(s) }

// pkgRe requires an alphanumeric first character — a name can therefore
// never start with '-' and be parsed as a flag by the package manager —
// followed by characters common to deb/rpm/pacman/brew package names.
var pkgRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._@-]*$`)

// ValidPackage reports whether s is a plausible package name, by the same
// canonicalize-before-policy contract as ValidUnit.
func ValidPackage(s string) bool { return pkgRe.MatchString(s) }
