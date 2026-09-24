// Command setu is the policy-governed MCP broker daemon: one Unix socket
// where agents discover and invoke system capabilities, with per-agent
// authorization, hash-chained audit, snapshots/rollback, and
// human-in-the-loop escalation. All substance lives in internal/daemon;
// this binary only parses flags, applies environment-sensitive defaults,
// and handles shutdown signals.
//
// Usage (defaults shown for a root install; see --help):
//
//	setu --policy /etc/setu/policy.toml --state-dir /var/lib/setu \
//	     --socket /run/setu/setu.sock --control-socket /run/setu/control.sock
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kolz001/setu/internal/daemon"
)

// defaultRunDir picks the socket directory: /run/setu for root (the
// canonical system-service location), $XDG_RUNTIME_DIR/setu for user
// sessions, and a per-uid temp directory as the last resort. setuctl
// mirrors this logic so the two binaries meet without flags.
func defaultRunDir() string {
	if os.Geteuid() == 0 {
		return "/run/setu"
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return x + "/setu"
	}
	return os.TempDir() + "/setu-" + fmt.Sprint(os.Getuid())
}

// defaultStateDir picks where audit/snapshots/registry live: /var/lib/setu
// for root, ~/.local/state/setu otherwise.
func defaultStateDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/setu"
	}
	home, _ := os.UserHomeDir()
	return home + "/.local/state/setu"
}

func main() {
	runDir := defaultRunDir()
	var (
		socket  = flag.String("socket", runDir+"/setu.sock", "agent-facing MCP socket path")
		control = flag.String("control-socket", runDir+"/control.sock", "admin control socket path")
		policyP = flag.String("policy", "/etc/setu/policy.toml", "policy rules file (TOML)")
		state   = flag.String("state-dir", defaultStateDir(), "state directory (audit log, snapshots, agent registry)")
		backend = flag.String("backend", "auto", "system backends: auto (real where present, mock otherwise) or mock")
		askTO   = flag.Duration("ask-timeout", 120*time.Second, "how long 'ask' calls wait for approval before default-deny")
		version = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Println("setu", daemon.Version)
		return
	}

	opts := daemon.Options{
		SocketPath:  *socket,
		ControlPath: *control,
		PolicyPath:  *policyP,
		StateDir:    *state,
		AskTimeout:  *askTO,
		Backend:     *backend,
	}

	d, err := daemon.New(opts)
	if err != nil {
		log.Fatalf("setu: %v", err)
	}
	if err := d.Start(opts); err != nil {
		log.Fatalf("setu: %v", err)
	}
	log.Printf("setu %s listening on %s (control: %s, policy: %s, backends: %s)",
		daemon.Version, *socket, *control, *policyP, *backend)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("setu: shutting down")
	d.Stop()
}
