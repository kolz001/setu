package servers

import (
	"context"
	"fmt"
	"sync"
)

// PkgBackend queries and mutates the system package manager. Package
// arguments are already syntax-validated (ValidPackage) before any method
// is called, so implementations may pass them to native tools as single
// argv elements.
type PkgBackend interface {
	Search(ctx context.Context, query string) (string, error)
	Info(ctx context.Context, pkg string) (string, error)
	Install(ctx context.Context, pkg string) (string, error)
	Remove(ctx context.Context, pkg string) (string, error)
}

// PkgTools returns the pkg server's tools bound to backend b. Search/info
// are read-only; install/remove are high-risk mutations meant to stay
// deny-by-default in policy, loosened per host with package allowlists.
// They carry no SnapshotArgs — reversibility for package operations comes
// from the manager's own transaction history (dnf history undo, zypper
// rollback; roadmap), not file snapshots.
func PkgTools(b PkgBackend) []*Tool {
	pkgProp := map[string]any{"type": "string", "description": "package name"}
	return []*Tool{
		{
			Name:        "pkg.search",
			Description: "Search the package repositories. Read-only.",
			InputSchema: schema([]string{"query"}, map[string]any{"query": map[string]any{"type": "string"}}),
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				q := strArg(args, "query")
				if !ValidPackage(q) {
					return "", fmt.Errorf("invalid search query %q", q)
				}
				return b.Search(ctx, q)
			},
		},
		{
			Name:        "pkg.info",
			Description: "Show details for one package. Read-only.",
			InputSchema: schema([]string{"package"}, map[string]any{"package": pkgProp}),
			ArgKinds:    map[string]ArgKind{"package": ArgPackage},
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				return b.Info(ctx, strArg(args, "package"))
			},
		},
		{
			Name:        "pkg.install",
			Description: "Install a package. Mutating and high-risk; policy-gated with allowlists.",
			InputSchema: schema([]string{"package"}, map[string]any{"package": pkgProp}),
			ArgKinds:    map[string]ArgKind{"package": ArgPackage},
			Mutating:    true,
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				return b.Install(ctx, strArg(args, "package"))
			},
		},
		{
			Name:        "pkg.remove",
			Description: "Remove a package. Mutating and high-risk; policy-gated with allowlists.",
			InputSchema: schema([]string{"package"}, map[string]any{"package": pkgProp}),
			ArgKinds:    map[string]ArgKind{"package": ArgPackage},
			Mutating:    true,
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				return b.Remove(ctx, strArg(args, "package"))
			},
		},
	}
}

// DetectPkgBackend probes PATH for a known package manager (apt, dnf,
// zypper, pacman, brew — in that order) and returns an exec-backed
// PkgBackend for the first hit, or nil when the host has none (the daemon
// then falls back to MockPkg).
func DetectPkgBackend() PkgBackend {
	switch {
	case haveBinary("apt-get"):
		return execPkg{search: []string{"apt-cache", "search"}, info: []string{"apt-cache", "show"},
			install: []string{"apt-get", "install", "-y"}, remove: []string{"apt-get", "remove", "-y"}}
	case haveBinary("dnf"):
		return execPkg{search: []string{"dnf", "search"}, info: []string{"dnf", "info"},
			install: []string{"dnf", "install", "-y"}, remove: []string{"dnf", "remove", "-y"}}
	case haveBinary("zypper"):
		return execPkg{search: []string{"zypper", "search"}, info: []string{"zypper", "info"},
			install: []string{"zypper", "--non-interactive", "install"}, remove: []string{"zypper", "--non-interactive", "remove"}}
	case haveBinary("pacman"):
		return execPkg{search: []string{"pacman", "-Ss"}, info: []string{"pacman", "-Si"},
			install: []string{"pacman", "-S", "--noconfirm"}, remove: []string{"pacman", "-R", "--noconfirm"}}
	case haveBinary("brew"):
		return execPkg{search: []string{"brew", "search"}, info: []string{"brew", "info"},
			install: []string{"brew", "install"}, remove: []string{"brew", "uninstall"}}
	}
	return nil
}

// execPkg implements PkgBackend as four command templates (binary +
// leading flags); the validated package name is appended as the final argv
// element.
type execPkg struct {
	search, info, install, remove []string
}

// run executes one command template with arg appended, copying the template
// so a template slice is never mutated.
func (e execPkg) run(ctx context.Context, argv []string, arg string) (string, error) {
	return runCmd(ctx, argv[0], append(append([]string{}, argv[1:]...), arg)...)
}

// Search, Info, Install, and Remove implement PkgBackend via the
// corresponding command template.
func (e execPkg) Search(ctx context.Context, q string) (string, error) {
	return e.run(ctx, e.search, q)
}
func (e execPkg) Info(ctx context.Context, p string) (string, error) { return e.run(ctx, e.info, p) }
func (e execPkg) Install(ctx context.Context, p string) (string, error) {
	return e.run(ctx, e.install, p)
}
func (e execPkg) Remove(ctx context.Context, p string) (string, error) {
	return e.run(ctx, e.remove, p)
}

// MockPkg implements PkgBackend over an in-memory package database, for
// hosts without a package manager and for tests. Install/Remove mutate the
// Installed set with plausible not-found/not-installed errors. Safe for
// concurrent use.
type MockPkg struct {
	mu        sync.Mutex
	Installed map[string]bool
	Known     map[string]string // name → description
}

// NewMockPkg returns a MockPkg preloaded with a few packages, one installed.
func NewMockPkg() *MockPkg {
	return &MockPkg{
		Installed: map[string]bool{"nginx": true},
		Known: map[string]string{
			"nginx":   "high performance web server",
			"htop":    "interactive process viewer",
			"ripgrep": "line-oriented search tool",
		},
	}
}

// Search lists the known packages (the query is accepted but not used to
// filter — the mock database is three entries).
func (m *MockPkg) Search(_ context.Context, q string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := ""
	for name, desc := range m.Known {
		out += fmt.Sprintf("%s - %s\n", name, desc)
		_ = q
	}
	return out, nil
}

// Info describes one known package, including installation state.
func (m *MockPkg) Info(_ context.Context, p string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	desc, ok := m.Known[p]
	if !ok {
		return "", fmt.Errorf("package %q not found", p)
	}
	return fmt.Sprintf("Package: %s\nDescription: %s\nInstalled: %v", p, desc, m.Installed[p]), nil
}

// Install marks a known package installed.
func (m *MockPkg) Install(_ context.Context, p string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Known[p]; !ok {
		return "", fmt.Errorf("package %q not found", p)
	}
	m.Installed[p] = true
	return "installed " + p, nil
}

// Remove unmarks an installed package.
func (m *MockPkg) Remove(_ context.Context, p string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.Installed[p] {
		return "", fmt.Errorf("package %q not installed", p)
	}
	delete(m.Installed, p)
	return "removed " + p, nil
}
