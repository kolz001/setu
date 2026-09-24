package broker

import (
	"fmt"

	"github.com/kolz001/setu/internal/pathutil"
	"github.com/kolz001/setu/internal/policy"
	"github.com/kolz001/setu/internal/servers"
)

// canonicalize validates and normalizes a call's policy-relevant arguments
// per the tool's ArgKinds declaration, returning the extracted policy.Args.
//
// It runs before policy evaluation so rules match real targets rather than
// agent-controlled strings: path arguments are rewritten *in place* to
// their canonical form (absolute, '..' collapsed, symlinks resolved — see
// pathutil.Canonical), so the handler later operates on exactly the path
// policy approved; unit and package names are syntax-checked (see
// servers.ValidUnit / servers.ValidPackage).
//
// Absent or empty arguments are skipped — required-argument enforcement
// belongs to the tool's schema and handler, not here — but the kinds the
// tool declares are always recorded (policy.Args.Takes*), so a policy
// constraint on an omitted argument fails closed. Any violation rejects
// the whole call; the broker audits it as a deny with the reason.
func canonicalize(tool *servers.Tool, args map[string]any) (policy.Args, error) {
	var out policy.Args
	for _, kind := range tool.ArgKinds {
		switch kind {
		case servers.ArgPath:
			out.TakesPath = true
		case servers.ArgUnit:
			out.TakesUnit = true
		case servers.ArgPackage:
			out.TakesPackage = true
		}
	}
	for name, kind := range tool.ArgKinds {
		raw, present := args[name]
		if !present || raw == nil {
			continue
		}
		s, ok := raw.(string)
		if !ok {
			return out, fmt.Errorf("argument %q must be a string", name)
		}
		if s == "" {
			continue
		}
		switch kind {
		case servers.ArgPath:
			p, err := pathutil.Canonical(s)
			if err != nil {
				return out, fmt.Errorf("argument %q: %v", name, err)
			}
			args[name] = p
			out.Path = p
		case servers.ArgUnit:
			if !servers.ValidUnit(s) {
				return out, fmt.Errorf("argument %q: %q is not a valid unit name", name, s)
			}
			out.Unit = s
		case servers.ArgPackage:
			if !servers.ValidPackage(s) {
				return out, fmt.Errorf("argument %q: %q is not a valid package name", name, s)
			}
			out.Package = s
		}
	}
	return out, nil
}
