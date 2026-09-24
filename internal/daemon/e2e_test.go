package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kolz001/setu/internal/audit"
	"github.com/kolz001/setu/internal/jsonrpc"
	"github.com/kolz001/setu/internal/mcp"
)

const e2ePolicy = `
[[rule]]
agent  = "reader"
tool   = "journal.read"
action = "allow"

[[rule]]
agent  = "reader"
tool   = "net.*"
action = "allow"

[[rule]]
agent  = "fixer"
tool   = "fs.*"
scope  = { path_prefix = "%s" }
action = "allow_with_snapshot"

[[rule]]
agent  = "asker"
tool   = "systemd.restart"
units  = ["nginx.service"]
action = "ask"
`

type testEnv struct {
	d       *Daemon
	socket  string
	repoDir string
}

// startDaemon brings up a full daemon on short /tmp socket paths (Unix
// socket paths are length-limited) with mock system backends.
func startDaemon(t *testing.T) *testEnv {
	t.Helper()
	return startDaemonWithPolicy(t, e2ePolicy)
}

// startDaemonWithPolicy is startDaemon with a caller-supplied policy; the
// policy is a format string whose single %s receives the repo directory.
func startDaemonWithPolicy(t *testing.T, policyFmt string) *testEnv {
	t.Helper()
	sockDir, err := os.MkdirTemp("/tmp", "setut")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })

	stateDir := t.TempDir()
	repoDir := filepath.Join(stateDir, "repos")
	os.MkdirAll(repoDir, 0o755)
	// Policy prefixes must match canonicalized (symlink-resolved) paths.
	repoDir, _ = filepath.EvalSymlinks(repoDir)

	policyPath := filepath.Join(stateDir, "policy.toml")
	os.WriteFile(policyPath, []byte(fmt.Sprintf(policyFmt, repoDir)), 0o600)

	opts := Options{
		SocketPath:  filepath.Join(sockDir, "setu.sock"),
		ControlPath: filepath.Join(sockDir, "ctl.sock"),
		PolicyPath:  policyPath,
		StateDir:    filepath.Join(stateDir, "state"),
		AskTimeout:  5 * time.Second,
		Backend:     "mock",
	}
	d, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(opts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)
	return &testEnv{d: d, socket: opts.SocketPath, repoDir: repoDir}
}

func (e *testEnv) connect(t *testing.T, agent, token string) *jsonrpc.Client {
	t.Helper()
	cl, err := e.tryConnect(t, agent, token)
	if err != nil {
		t.Fatalf("initialize as %s: %v", agent, err)
	}
	return cl
}

func (e *testEnv) tryConnect(t *testing.T, agent, token string) (*jsonrpc.Client, error) {
	t.Helper()
	conn, err := net.Dial("unix", e.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	cl := jsonrpc.NewClient(conn)
	params := map[string]any{
		"protocolVersion": mcp.ProtocolVersion,
		"clientInfo":      map[string]string{"name": agent, "version": "test"},
		"_meta":           map[string]any{"setu": map[string]string{"agent": agent, "token": token}},
	}
	var res mcp.InitializeResult
	if err := cl.Call("initialize", params, &res); err != nil {
		return nil, err
	}
	return cl, nil
}

func listTools(t *testing.T, cl *jsonrpc.Client) []string {
	t.Helper()
	var res mcp.ListToolsResult
	if err := cl.Call("tools/list", map[string]any{}, &res); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func call(t *testing.T, cl *jsonrpc.Client, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	var res mcp.CallToolResult
	if err := cl.Call("tools/call", mcp.CallToolParams{Name: tool, Arguments: args}, &res); err != nil {
		t.Fatal(err)
	}
	return &res
}

func TestLeastPrivilegeVisibility(t *testing.T) {
	env := startDaemon(t)
	reader := env.connect(t, "reader", "")
	tools := listTools(t, reader)
	want := map[string]bool{"journal.read": true, "net.interfaces": true, "net.routes": true, "net.sockets": true}
	if len(tools) != len(want) {
		t.Fatalf("reader should see exactly %d tools, saw %v", len(want), tools)
	}
	for _, n := range tools {
		if !want[n] {
			t.Fatalf("reader should not see %s", n)
		}
	}

	stranger := env.connect(t, "stranger", "")
	if got := listTools(t, stranger); len(got) != 0 {
		t.Fatalf("stranger should see no tools, saw %v", got)
	}
}

func TestAllowAndDeny(t *testing.T) {
	env := startDaemon(t)
	reader := env.connect(t, "reader", "")

	res := call(t, reader, "journal.read", map[string]any{"lines": 5})
	if res.IsError {
		t.Fatalf("journal.read should succeed: %v", res.Content)
	}

	// Hidden tool: call fails at discovery-equivalent level.
	res = call(t, reader, "pkg.install", map[string]any{"package": "htop"})
	if !res.IsError {
		t.Fatal("pkg.install must be denied for reader")
	}
}

func TestSnapshotAndRollback(t *testing.T) {
	env := startDaemon(t)
	fixer := env.connect(t, "fixer", "")

	target := filepath.Join(env.repoDir, "main.go")
	os.WriteFile(target, []byte("v1"), 0o644)

	res := call(t, fixer, "fs.write", map[string]any{"path": target, "content": "v2"})
	if res.IsError {
		t.Fatalf("in-scope write should succeed: %v", res.Content)
	}
	if b, _ := os.ReadFile(target); string(b) != "v2" {
		t.Fatal("write did not land")
	}

	snaps, err := env.d.Snapshots.List()
	if err != nil || len(snaps) != 1 {
		t.Fatalf("expected exactly one snapshot, got %v err %v", snaps, err)
	}
	if err := env.d.Snapshots.Rollback(snaps[0].ID); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "v1" {
		t.Fatalf("rollback should restore v1, got %q", b)
	}

	// Audit entry carries the snapshot id.
	entries, _ := audit.Query(env.d.AuditPath, audit.QueryFilter{Tool: "fs.write"})
	if len(entries) != 1 || entries[0].SnapshotID != snaps[0].ID {
		t.Fatalf("audit should record snapshot id, got %+v", entries)
	}
}

func TestScopeEnforcementViaTraversal(t *testing.T) {
	env := startDaemon(t)
	fixer := env.connect(t, "fixer", "")

	// Traversal out of scope canonicalizes to a path the rule doesn't cover.
	sneaky := env.repoDir + "/../escape.txt"
	res := call(t, fixer, "fs.write", map[string]any{"path": sneaky, "content": "x"})
	if !res.IsError {
		t.Fatal("traversal outside scope must be denied")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(env.repoDir), "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("file must not have been created")
	}
}

func TestAskApproveFlow(t *testing.T) {
	env := startDaemon(t)
	asker := env.connect(t, "asker", "")

	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		var res mcp.CallToolResult
		conn, _ := net.Dial("unix", env.socket)
		defer conn.Close()
		cl := jsonrpc.NewClient(conn)
		cl.Call("initialize", map[string]any{
			"protocolVersion": mcp.ProtocolVersion,
			"clientInfo":      map[string]string{"name": "asker", "version": "t"},
		}, &mcp.InitializeResult{})
		cl.Call("tools/call", mcp.CallToolParams{
			Name: "systemd.restart", Arguments: map[string]any{"unit": "nginx.service"},
		}, &res)
		done <- &res
	}()
	_ = asker

	// Wait for the pending approval to appear, then approve it.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if pend := env.d.Escalation.List(); len(pend) == 1 {
			if !env.d.Escalation.Resolve(pend[0].ID, true, 0) {
				t.Fatal("resolve failed")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no pending approval appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}

	res := <-done
	if res.IsError {
		t.Fatalf("approved call should succeed: %v", res.Content)
	}

	entries, _ := audit.Query(env.d.AuditPath, audit.QueryFilter{Tool: "systemd.restart"})
	if len(entries) != 1 || entries[0].Decision != "allow_after_ask" {
		t.Fatalf("audit should record allow_after_ask, got %+v", entries)
	}
}

func TestAskUnlistedUnitFallsThroughToDeny(t *testing.T) {
	env := startDaemon(t)
	asker := env.connect(t, "asker", "")
	res := call(t, asker, "systemd.restart", map[string]any{"unit": "sshd.service"})
	if !res.IsError {
		t.Fatal("unit outside allowlist must be denied without asking")
	}
	if pend := env.d.Escalation.List(); len(pend) != 0 {
		t.Fatal("no approval should have been created")
	}
}

func TestFreezeKillSwitch(t *testing.T) {
	env := startDaemon(t)
	reader := env.connect(t, "reader", "")
	env.d.Broker.Freeze("reader")
	res := call(t, reader, "journal.read", map[string]any{})
	if !res.IsError {
		t.Fatal("frozen agent must be denied")
	}
	env.d.Broker.Unfreeze("reader")
	res = call(t, reader, "journal.read", map[string]any{})
	if res.IsError {
		t.Fatalf("unfrozen agent should succeed again: %v", res.Content)
	}
}

func TestRegisteredNameRequiresToken(t *testing.T) {
	env := startDaemon(t)
	token, err := env.d.Agents.Register("reader", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Claiming the registered name without the token is rejected at initialize.
	if _, err := env.tryConnect(t, "reader", ""); err == nil {
		t.Fatal("registered name without token must be rejected")
	}
	if _, err := env.tryConnect(t, "reader", "setu_wrongtoken"); err == nil {
		t.Fatal("bad token must be rejected")
	}
	cl, err := env.tryConnect(t, "reader", token)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if res := call(t, cl, "journal.read", map[string]any{}); res.IsError {
		t.Fatalf("authenticated reader should read journal: %v", res.Content)
	}
}

func TestEveryCallIsAudited(t *testing.T) {
	env := startDaemon(t)
	reader := env.connect(t, "reader", "")
	call(t, reader, "journal.read", map[string]any{})
	call(t, reader, "pkg.install", map[string]any{"package": "htop"}) // denied
	stranger := env.connect(t, "stranger", "")
	call(t, stranger, "journal.read", map[string]any{}) // denied

	n, err := audit.Verify(env.d.AuditPath)
	if err != nil {
		t.Fatalf("audit chain invalid: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 audited calls, got %d", n)
	}
	denies, _ := audit.Query(env.d.AuditPath, audit.QueryFilter{Decision: "deny"})
	if len(denies) != 2 {
		t.Fatalf("expected 2 denies, got %d", len(denies))
	}
}
