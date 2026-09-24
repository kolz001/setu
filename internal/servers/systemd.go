package servers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// SystemdBackend queries and controls service units. Unit arguments are
// already syntax-validated by canonicalization before any method is called.
// ListUnits takes an optional glob pattern; the mutating methods return a
// short confirmation on success.
type SystemdBackend interface {
	ListUnits(ctx context.Context, pattern string) (string, error)
	Status(ctx context.Context, unit string) (string, error)
	Start(ctx context.Context, unit string) (string, error)
	Stop(ctx context.Context, unit string) (string, error)
	Restart(ctx context.Context, unit string) (string, error)
}

// SystemdTools returns the systemd server's tools bound to backend b.
// Queries (list_units, status) are low risk; start/stop/restart are marked
// Mutating and meant to be policy-gated behind ask or unit allowlists.
func SystemdTools(b SystemdBackend) []*Tool {
	unitProp := map[string]any{"type": "string", "description": "unit name, e.g. nginx.service"}
	// action builds the three identically-shaped mutating unit tools.
	action := func(name, desc string, fn func(ctx context.Context, unit string) (string, error)) *Tool {
		return &Tool{
			Name:        name,
			Description: desc,
			InputSchema: schema([]string{"unit"}, map[string]any{"unit": unitProp}),
			ArgKinds:    map[string]ArgKind{"unit": ArgUnit},
			Mutating:    true,
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				return fn(ctx, strArg(args, "unit"))
			},
		}
	}
	return []*Tool{
		{
			Name:        "systemd.list_units",
			Description: "List systemd units, optionally filtered by a glob pattern. Read-only.",
			InputSchema: schema(nil, map[string]any{
				"pattern": map[string]any{"type": "string", "description": "glob, e.g. 'nginx*'"},
			}),
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				return b.ListUnits(ctx, strArg(args, "pattern"))
			},
		},
		{
			Name:        "systemd.status",
			Description: "Show status of one unit. Read-only.",
			InputSchema: schema([]string{"unit"}, map[string]any{"unit": unitProp}),
			ArgKinds:    map[string]ArgKind{"unit": ArgUnit},
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				return b.Status(ctx, strArg(args, "unit"))
			},
		},
		action("systemd.start", "Start a unit. Mutating; policy-gated.", b.Start),
		action("systemd.stop", "Stop a unit. Mutating; policy-gated.", b.Stop),
		action("systemd.restart", "Restart a unit. Mutating; policy-gated.", b.Restart),
	}
}

// SystemctlBackend implements SystemdBackend by exec-ing systemctl (Linux
// hosts).
type SystemctlBackend struct{}

// ListUnits lists service-type units, optionally filtered by pattern.
func (SystemctlBackend) ListUnits(ctx context.Context, pattern string) (string, error) {
	argv := []string{"list-units", "--no-pager", "--plain", "--type=service"}
	if pattern != "" {
		argv = append(argv, pattern)
	}
	return runCmd(ctx, "systemctl", argv...)
}

// Status shows one unit's status. `systemctl status` exits nonzero for
// inactive units; that's still a useful answer, so its output is returned
// without the error in that case.
func (SystemctlBackend) Status(ctx context.Context, unit string) (string, error) {
	out, err := runCmd(ctx, "systemctl", "status", "--no-pager", "--lines=0", unit)
	if err != nil && out != "" {
		return out, nil
	}
	return out, err
}

// Start starts a unit.
func (SystemctlBackend) Start(ctx context.Context, unit string) (string, error) {
	if _, err := runCmd(ctx, "systemctl", "start", unit); err != nil {
		return "", err
	}
	return "started " + unit, nil
}

// Stop stops a unit.
func (SystemctlBackend) Stop(ctx context.Context, unit string) (string, error) {
	if _, err := runCmd(ctx, "systemctl", "stop", unit); err != nil {
		return "", err
	}
	return "stopped " + unit, nil
}

// Restart restarts a unit.
func (SystemctlBackend) Restart(ctx context.Context, unit string) (string, error) {
	if _, err := runCmd(ctx, "systemctl", "restart", unit); err != nil {
		return "", err
	}
	return "restarted " + unit, nil
}

// MockSystemd implements SystemdBackend over an in-memory unit table, for
// hosts without systemd and for tests. Start/Stop/Restart flip the state of
// known units and error on unknown ones, mimicking systemctl closely enough
// for policy-flow testing. Safe for concurrent use.
type MockSystemd struct {
	mu    sync.Mutex
	Units map[string]string // unit → active|inactive|failed
}

// NewMockSystemd returns a MockSystemd preloaded with a few familiar units.
func NewMockSystemd() *MockSystemd {
	return &MockSystemd{Units: map[string]string{
		"nginx.service": "active",
		"sshd.service":  "active",
		"cron.service":  "inactive",
	}}
}

// ListUnits lists the mock unit table, filtered by a substring of pattern.
func (m *MockSystemd) ListUnits(_ context.Context, pattern string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.Units))
	for u := range m.Units {
		names = append(names, u)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, u := range names {
		if pattern != "" && !strings.Contains(u, strings.Trim(pattern, "*")) {
			continue
		}
		fmt.Fprintf(&b, "%-24s loaded %s running\n", u, m.Units[u])
	}
	if b.Len() == 0 {
		return "0 loaded units listed.", nil
	}
	return b.String(), nil
}

// Status reports one mock unit's state.
func (m *MockSystemd) Status(_ context.Context, unit string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.Units[unit]
	if !ok {
		return "", fmt.Errorf("unit %s not found", unit)
	}
	return fmt.Sprintf("● %s\n   Active: %s", unit, st), nil
}

// set transitions a known unit to state, erroring on unknown units.
func (m *MockSystemd) set(unit, state string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Units[unit]; !ok {
		return "", fmt.Errorf("unit %s not found", unit)
	}
	m.Units[unit] = state
	return fmt.Sprintf("%s → %s", unit, state), nil
}

// Start, Stop, and Restart implement the mutating half of SystemdBackend
// as state transitions on the mock table.
func (m *MockSystemd) Start(_ context.Context, u string) (string, error)   { return m.set(u, "active") }
func (m *MockSystemd) Stop(_ context.Context, u string) (string, error)    { return m.set(u, "inactive") }
func (m *MockSystemd) Restart(_ context.Context, u string) (string, error) { return m.set(u, "active") }
