package policy

import (
	"testing"
	"time"

	"github.com/kolz001/setu/internal/identity"
)

func ident(name string, authed bool) identity.Identity {
	return identity.Identity{Name: name, Authenticated: authed, Peer: identity.PeerCred{UID: 1000}}
}

const testPolicy = `
[[rule]]
agent  = "tvastr-*"
tool   = "journal.read"
action = "allow"

[[rule]]
agent  = "tvastr-fixer"
tool   = "fs.write"
scope  = { path_prefix = "/srv/repos" }
action = "allow_with_snapshot"

[[rule]]
agent  = "*"
tool   = "systemd.restart"
units  = ["nginx.service"]
action = "ask"

[[rule]]
agent  = "*"
tool   = "pkg.install"
action = "deny"

[[rule]]
agent  = "ratey"
tool   = "net.interfaces"
rate   = { calls_per_minute = 2 }
action = "allow"

[[rule]]
agent        = "secure-agent"
tool         = "fs.read"
require_token = true
action       = "allow"
`

func mustParse(t *testing.T, s string) *Engine {
	t.Helper()
	e, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDenyByDefault(t *testing.T) {
	e := mustParse(t, testPolicy)
	d := e.Evaluate(ident("unknown-agent", false), "journal.read", Args{})
	if d.Action != Deny || d.RuleIndex != -1 {
		t.Fatalf("expected default deny, got %+v", d)
	}
}

func TestGlobAgentMatch(t *testing.T) {
	e := mustParse(t, testPolicy)
	if d := e.Evaluate(ident("tvastr-analyzer", false), "journal.read", Args{}); d.Action != Allow {
		t.Fatalf("tvastr-* should allow journal.read, got %+v", d)
	}
	if d := e.Evaluate(ident("other", false), "journal.read", Args{}); d.Action != Deny {
		t.Fatalf("non-matching agent should be denied, got %+v", d)
	}
}

func TestScopeConstraint(t *testing.T) {
	e := mustParse(t, testPolicy)
	fixer := ident("tvastr-fixer", true)
	if d := e.Evaluate(fixer, "fs.write", Args{Path: "/srv/repos/app/main.go"}); d.Action != AllowWithSnapshot {
		t.Fatalf("in-scope write should be allow_with_snapshot, got %+v", d)
	}
	// Out of scope falls through to default deny.
	if d := e.Evaluate(fixer, "fs.write", Args{Path: "/etc/passwd"}); d.Action != Deny {
		t.Fatalf("out-of-scope write should be denied, got %+v", d)
	}
	// Sibling-prefix bypass: /srv/repos-evil must NOT match /srv/repos.
	if d := e.Evaluate(fixer, "fs.write", Args{Path: "/srv/repos-evil/x"}); d.Action != Deny {
		t.Fatalf("prefix must be component-aware, got %+v", d)
	}
}

func TestUnitConstraint(t *testing.T) {
	e := mustParse(t, testPolicy)
	if d := e.Evaluate(ident("any", false), "systemd.restart", Args{Unit: "nginx.service"}); d.Action != Ask {
		t.Fatalf("nginx restart should be ask, got %+v", d)
	}
	if d := e.Evaluate(ident("any", false), "systemd.restart", Args{Unit: "sshd.service"}); d.Action != Deny {
		t.Fatalf("non-allowlisted unit should fall through to deny, got %+v", d)
	}
}

func TestFirstMatchWins(t *testing.T) {
	e := mustParse(t, `
[[rule]]
agent  = "a"
tool   = "fs.read"
action = "deny"

[[rule]]
agent  = "*"
tool   = "fs.read"
action = "allow"
`)
	if d := e.Evaluate(ident("a", false), "fs.read", Args{}); d.Action != Deny || d.RuleIndex != 0 {
		t.Fatalf("first matching rule should win, got %+v", d)
	}
	if d := e.Evaluate(ident("b", false), "fs.read", Args{}); d.Action != Allow || d.RuleIndex != 1 {
		t.Fatalf("second rule should match other agents, got %+v", d)
	}
}

func TestRequireToken(t *testing.T) {
	e := mustParse(t, testPolicy)
	if d := e.Evaluate(ident("secure-agent", false), "fs.read", Args{}); d.Action != Deny {
		t.Fatalf("unauthenticated agent must not match require_token rule, got %+v", d)
	}
	if d := e.Evaluate(ident("secure-agent", true), "fs.read", Args{}); d.Action != Allow {
		t.Fatalf("authenticated agent should be allowed, got %+v", d)
	}
}

func TestRateLimit(t *testing.T) {
	e := mustParse(t, testPolicy)
	now := time.Now()
	e.now = func() time.Time { return now }
	r := ident("ratey", false)
	for i := 0; i < 2; i++ {
		if d := e.Evaluate(r, "net.interfaces", Args{}); d.Action != Allow {
			t.Fatalf("call %d should be allowed, got %+v", i, d)
		}
	}
	if d := e.Evaluate(r, "net.interfaces", Args{}); d.Action != Deny {
		t.Fatalf("third call within a minute should be rate-limited, got %+v", d)
	}
	// Window slides: a minute later the agent can call again.
	now = now.Add(61 * time.Second)
	if d := e.Evaluate(r, "net.interfaces", Args{}); d.Action != Allow {
		t.Fatalf("call after window should be allowed, got %+v", d)
	}
}

func TestVisibility(t *testing.T) {
	e := mustParse(t, testPolicy)
	if !e.ToolVisible(ident("tvastr-analyzer", false), "journal.read") {
		t.Fatal("journal.read should be visible to tvastr-*")
	}
	if e.ToolVisible(ident("tvastr-analyzer", false), "pkg.install") {
		t.Fatal("pkg.install is unconditionally denied; must be invisible")
	}
	if e.ToolVisible(ident("stranger", false), "journal.read") {
		t.Fatal("no rule for stranger; tool must be invisible")
	}
	// Constrained allow (scope) still makes the tool visible.
	if !e.ToolVisible(ident("tvastr-fixer", true), "fs.write") {
		t.Fatal("scoped allow should keep fs.write visible")
	}
	// systemd.restart has an ask rule with a unit constraint → visible.
	if !e.ToolVisible(ident("anyone", false), "systemd.restart") {
		t.Fatal("ask rule should make tool visible")
	}
}

func TestTimeWindow(t *testing.T) {
	e := mustParse(t, `
[[rule]]
agent  = "night-agent"
tool   = "fs.read"
time   = { after = "22:00", before = "06:00" }
action = "allow"
`)
	base := time.Date(2026, 7, 9, 0, 0, 0, 0, time.Local)
	at := func(h int) { e.now = func() time.Time { return base.Add(time.Duration(h) * time.Hour) } }
	at(23)
	if d := e.Evaluate(ident("night-agent", false), "fs.read", Args{}); d.Action != Allow {
		t.Fatalf("23:00 is inside the wrap window, got %+v", d)
	}
	at(3)
	if d := e.Evaluate(ident("night-agent", false), "fs.read", Args{}); d.Action != Allow {
		t.Fatalf("03:00 is inside the wrap window, got %+v", d)
	}
	at(12)
	if d := e.Evaluate(ident("night-agent", false), "fs.read", Args{}); d.Action != Deny {
		t.Fatalf("12:00 is outside the window, got %+v", d)
	}
}

func TestStringOrListPathPrefix(t *testing.T) {
	e := mustParse(t, `
[[rule]]
agent  = "a"
tool   = "fs.read"
scope  = { path_prefix = ["/one", "/two"] }
action = "allow"
`)
	if d := e.Evaluate(ident("a", false), "fs.read", Args{Path: "/two/file"}); d.Action != Allow {
		t.Fatalf("list path_prefix should match, got %+v", d)
	}
}

func TestInvalidPolicyRejected(t *testing.T) {
	for name, src := range map[string]string{
		"bad action":      "[[rule]]\nagent='a'\ntool='b'\naction='maybe'\n",
		"missing tool":    "[[rule]]\nagent='a'\naction='allow'\n",
		"relative prefix": "[[rule]]\nagent='a'\ntool='b'\naction='allow'\nscope={path_prefix='rel'}\n",
		"unknown key":     "[[rule]]\nagent='a'\ntool='b'\naction='allow'\ntypo_key='x'\n",
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected parse error", name)
		}
	}
}

func TestConstraintOnOmittedArgFailsClosed(t *testing.T) {
	e := mustParse(t, `
[[rule]]
agent  = "*"
tool   = "journal.read"
units  = ["nginx.service"]
action = "allow"

[[rule]]
agent  = "*"
tool   = "fs.read"
scope  = { path_prefix = "/srv" }
action = "allow"

[[rule]]
agent    = "*"
tool     = "pkg.info"
packages = ["htop"]
action   = "allow"

[[rule]]
agent  = "*"
tool   = "systemd.list_units"
units  = ["nginx.service"]
action = "allow"
`)
	id := ident("a", false)
	cases := []struct {
		tool string
		args Args
		want Action
	}{
		{"journal.read", Args{TakesUnit: true, Unit: "nginx.service"}, Allow},
		{"journal.read", Args{TakesUnit: true}, Deny}, // omitted unit must not match
		{"fs.read", Args{TakesPath: true}, Deny},
		{"pkg.info", Args{TakesPackage: true}, Deny},
		// A tool with no argument of the constrained kind is still covered.
		{"systemd.list_units", Args{}, Allow},
	}
	for _, c := range cases {
		if d := e.Evaluate(id, c.tool, c.args); d.Action != c.want {
			t.Errorf("%s %+v: got %s want %s", c.tool, c.args, d.Action, c.want)
		}
	}
}

func TestDecisionReportsMatchedScope(t *testing.T) {
	e := mustParse(t, `
[[rule]]
agent  = "*"
tool   = "fs.read"
scope  = { path_prefix = ["/srv", "/srv/repos"] }
action = "allow"
`)
	d := e.Evaluate(ident("a", false), "fs.read", Args{TakesPath: true, Path: "/srv/repos/x"})
	if d.Action != Allow || d.Scope != "/srv/repos" {
		t.Fatalf("want allow with the longest covering prefix, got %+v", d)
	}
}
