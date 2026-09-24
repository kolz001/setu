package servers

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// JournalBackend reads system logs. Read returns formatted log lines
// filtered by any non-empty parameters: unit (already validated by
// canonicalization), a journalctl-style since expression, a max priority,
// and a message pattern; lines caps the count (the tool clamps it to
// [1, 1000] before calling).
type JournalBackend interface {
	Read(ctx context.Context, unit, since, priority, grep string, lines int) (string, error)
}

// JournalTools returns the journal server's tools (read-only, low risk)
// bound to backend b.
func JournalTools(b JournalBackend) []*Tool {
	return []*Tool{{
		Name:        "journal.read",
		Description: "Read system journal entries with optional filters. Read-only.",
		InputSchema: schema(nil, map[string]any{
			"unit":     map[string]any{"type": "string", "description": "systemd unit to filter by"},
			"since":    map[string]any{"type": "string", "description": "e.g. '1 hour ago', '2026-07-09 10:00'"},
			"priority": map[string]any{"type": "string", "description": "max priority: emerg..debug or 0..7"},
			"grep":     map[string]any{"type": "string", "description": "pattern to match in messages"},
			"lines":    map[string]any{"type": "integer", "description": "max lines (default 100, cap 1000)"},
		}),
		ArgKinds: map[string]ArgKind{"unit": ArgUnit},
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			lines := intArg(args, "lines", 100)
			if lines > 1000 {
				lines = 1000
			}
			if lines < 1 {
				lines = 1
			}
			return b.Read(ctx, strArg(args, "unit"), strArg(args, "since"),
				strArg(args, "priority"), strArg(args, "grep"), lines)
		},
	}}
}

// JournalctlBackend reads logs by exec-ing journalctl (Linux hosts).
type JournalctlBackend struct{}

// Read implements JournalBackend by mapping each filter to the
// corresponding journalctl flag.
func (JournalctlBackend) Read(ctx context.Context, unit, since, priority, grep string, lines int) (string, error) {
	argv := []string{"--no-pager", "-o", "short-iso", "-n", strconv.Itoa(lines)}
	if unit != "" {
		argv = append(argv, "-u", unit)
	}
	if since != "" {
		argv = append(argv, "--since", since)
	}
	if priority != "" {
		argv = append(argv, "-p", priority)
	}
	if grep != "" {
		argv = append(argv, "-g", grep)
	}
	return runCmd(ctx, "journalctl", argv...)
}

// MockJournal serves canned log lines on hosts without journald and in
// tests. Populate Lines to control the data; leaving it nil serves a small
// built-in sample.
type MockJournal struct {
	Lines []string
}

// Read implements JournalBackend over the in-memory lines. Only the unit
// and grep filters are simulated (substring matches); since and priority
// are accepted and ignored.
func (m *MockJournal) Read(_ context.Context, unit, since, priority, grep string, lines int) (string, error) {
	src := m.Lines
	if len(src) == 0 {
		src = []string{
			"2026-07-09T10:00:01+0000 host systemd[1]: Started nginx.service.",
			"2026-07-09T10:00:05+0000 host nginx[812]: worker process started",
			"2026-07-09T10:01:12+0000 host sshd[901]: Accepted publickey for deploy",
		}
	}
	var out []string
	for _, l := range src {
		if unit != "" && !strings.Contains(l, strings.TrimSuffix(unit, ".service")) {
			continue
		}
		if grep != "" && !strings.Contains(l, grep) {
			continue
		}
		out = append(out, l)
		if len(out) >= lines {
			break
		}
	}
	if len(out) == 0 {
		return "-- no entries --", nil
	}
	return fmt.Sprintf("%s\n", strings.Join(out, "\n")), nil
}
