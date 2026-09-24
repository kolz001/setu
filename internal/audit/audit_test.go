package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kolz001/setu/internal/identity"
)

func testEntry(tool string) Entry {
	return Entry{
		SessionID: "s-test",
		Agent:     identity.Identity{Name: "tester", Peer: identity.PeerCred{UID: 1000}},
		Tool:      tool,
		Decision:  "allow",
		OK:        true,
	}
}

func TestAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"journal.read", "fs.write", "systemd.restart"} {
		if _, err := l.Append(testEntry(tool)); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	n, err := Verify(path)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 valid entries, got %d", n)
	}
}

func TestChainSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(path)
	l.Append(testEntry("a.b"))
	l.Close()

	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.Append(testEntry("c.d"))
	l2.Close()

	n, err := Verify(path)
	if err != nil || n != 2 {
		t.Fatalf("chain broken across reopen: n=%d err=%v", n, err)
	}
}

func TestTamperDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(path)
	l.Append(testEntry("x.y"))
	l.Append(testEntry("y.z"))
	l.Close()

	b, _ := os.ReadFile(path)
	// Flip the recorded decision on the first entry.
	tampered := strings.Replace(string(b), `"decision":"allow"`, `"decision":"deny"`, 1)
	os.WriteFile(path, []byte(tampered), 0o600)

	if _, err := Verify(path); err == nil {
		t.Fatal("tampered entry must fail verification")
	}
}

func TestTruncationDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(path)
	l.Append(testEntry("x.y"))
	l.Append(testEntry("y.z"))
	l.Close()

	b, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(b), "\n")
	// Drop the first entry, keep the second: seq check must catch it.
	os.WriteFile(path, []byte(strings.Join(lines[1:], "")), 0o600)

	if _, err := Verify(path); err == nil {
		t.Fatal("removed leading entry must fail verification")
	}
}

func TestQueryFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(path)
	e := testEntry("journal.read")
	e.Agent.Name = "alpha"
	l.Append(e)
	e2 := testEntry("fs.write")
	e2.Agent.Name = "beta"
	e2.Decision = "deny"
	e2.OK = false
	l.Append(e2)
	l.Close()

	got, err := Query(path, QueryFilter{Agent: "beta"})
	if err != nil || len(got) != 1 || got[0].Tool != "fs.write" {
		t.Fatalf("agent filter: got %v err %v", got, err)
	}
	got, _ = Query(path, QueryFilter{Decision: "deny"})
	if len(got) != 1 || got[0].Agent.Name != "beta" {
		t.Fatalf("decision filter: got %v", got)
	}
	got, _ = Query(path, QueryFilter{Tool: "journal.*"})
	if len(got) != 1 || got[0].Agent.Name != "alpha" {
		t.Fatalf("tool glob filter: got %v", got)
	}
}

func TestAppendBoundsAgentControlledFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("<", 2<<20) // escapes to 6 bytes each in JSON
	e := testEntry(huge)
	e.Agent.Name, e.Agent.Task, e.Reason, e.Result = huge, huge, huge, huge
	e.Args = json.RawMessage(`{"path":"/srv/x","content":"` + strings.Repeat("a", 5000) + `"}`)
	written, err := l.Append(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(testEntry("fs.write")); err != nil {
		t.Fatal(err)
	}
	l.Close()

	if fi, _ := os.Stat(path); fi.Size() > 64*1024 {
		t.Fatalf("oversized fields reached disk: log is %d bytes", fi.Size())
	}
	var args map[string]string
	if err := json.Unmarshal(written.Args, &args); err != nil {
		t.Fatal(err)
	}
	if args["path"] != "/srv/x" {
		t.Errorf("small argument values must be kept verbatim, got %q", args["path"])
	}
	sum := sha256.Sum256([]byte(strings.Repeat("a", 5000)))
	if !strings.Contains(args["content"], hex.EncodeToString(sum[:])) {
		t.Errorf("large values must be replaced by a fingerprint, got %q", args["content"])
	}
	if n, err := Verify(path); err != nil || n != 2 {
		t.Fatalf("verify: n=%d err=%v", n, err)
	}
	if l, err := Open(path); err != nil {
		t.Fatalf("reopen: %v", err)
	} else {
		l.Close()
	}
}

func TestBoundArgsCollapsesManyKeys(t *testing.T) {
	m := map[string]string{}
	for i := 0; i < 2000; i++ {
		m[fmt.Sprintf("k%04d", i)] = "value"
	}
	raw, _ := json.Marshal(m)
	out := boundArgs(raw)
	if len(out) > maxArgs || !strings.Contains(string(out), "_omitted") {
		t.Fatalf("many small keys must collapse to one fingerprint, got %d bytes", len(out))
	}
}
