package daemon

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kolz001/setu/internal/audit"
)

// Regression tests for scope, allowlist, and audit-integrity bypasses found
// in pre-release review. Each drives a real daemon over its socket.

const plainAllowPolicy = `
[[rule]]
agent  = "writer"
tool   = "fs.*"
scope  = { path_prefix = "%s" }
action = "allow"

[[rule]]
agent  = "reader"
tool   = "journal.read"
units  = ["nginx.service"]
action = "allow"
`

// A dangling symlink inside the scope must not let a write land outside it.
// (Under allow_with_snapshot the snapshot step happened to refuse this;
// plain allow wrote straight through the link.)
func TestDanglingSymlinkCannotEscapeScope(t *testing.T) {
	env := startDaemonWithPolicy(t, plainAllowPolicy)
	writer := env.connect(t, "writer", "")

	outside := filepath.Join(filepath.Dir(env.repoDir), "outside")
	os.MkdirAll(outside, 0o755)
	target := filepath.Join(outside, "pwned")
	link := filepath.Join(env.repoDir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}

	res := call(t, writer, "fs.write", map[string]any{"path": link, "content": "x"})
	if !res.IsError {
		t.Fatalf("write through dangling symlink must fail, got %v", res.Content)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("file must not have been created outside the scope")
	}

	res = call(t, writer, "fs.mkdir", map[string]any{"path": link + "/sub"})
	if !res.IsError {
		t.Fatalf("mkdir through dangling symlink must fail, got %v", res.Content)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("directory must not have been created outside the scope")
	}
}

// Omitting an argument a rule constrains must not satisfy the constraint.
func TestOmittedArgCannotBypassAllowlist(t *testing.T) {
	env := startDaemonWithPolicy(t, plainAllowPolicy)
	reader := env.connect(t, "reader", "")

	if res := call(t, reader, "journal.read", map[string]any{"unit": "nginx.service"}); res.IsError {
		t.Fatalf("allowlisted unit should be readable: %v", res.Content)
	}
	if res := call(t, reader, "journal.read", map[string]any{"unit": "sshd.service"}); !res.IsError {
		t.Fatal("unit outside the allowlist must be denied")
	}
	if res := call(t, reader, "journal.read", map[string]any{}); !res.IsError {
		t.Fatalf("omitting the constrained unit must be denied, got %v", res.Content)
	}
}

// One oversized call from an unauthenticated peer must not produce an audit
// line too long to re-read — that failed daemon restart and broke
// audit query/verify. '<' is chosen because encoding/json escapes it to six
// bytes, maximizing expansion between the wire and the log.
func TestOversizedCallCannotBreakAuditLog(t *testing.T) {
	env := startDaemonWithPolicy(t, plainAllowPolicy)

	conn, err := net.Dial("unix", env.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReaderSize(conn, 64*1024)
	send := func(line string) string {
		t.Helper()
		if _, err := conn.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		resp, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	big := strings.Repeat("<", 1536*1024)
	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"_meta":{"setu":{"agent":"anyone","task":"` + big + `"}}}}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + big + `","arguments":{"x":"` + big + `"}}}`)
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"journal.read","arguments":{"unit":"` + big + `.service"}}}`)

	fi, err := os.Stat(env.d.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 256*1024 {
		t.Fatalf("audit log grew to %d bytes from two calls; fields must be bounded", fi.Size())
	}
	if n, err := audit.Verify(env.d.AuditPath); err != nil || n != 2 {
		t.Fatalf("audit log must stay verifiable: n=%d err=%v", n, err)
	}
	// Reopening is what daemon startup does; it must still succeed.
	l, err := audit.Open(env.d.AuditPath)
	if err != nil {
		t.Fatalf("audit log must reopen after oversized calls: %v", err)
	}
	l.Close()
}
