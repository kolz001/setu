// Package daemon wires setu's components together — policy engine, agent
// registry, audit log, snapshot and escalation managers, tool registry with
// backend selection, broker, and control plane — and owns the two Unix
// sockets. cmd/setu is a thin flag-parsing shell around this package; the
// end-to-end tests embed it directly, so a Daemon must be fully functional
// without any CLI involvement.
//
// Lifecycle: New builds and validates everything (fail-closed: a bad
// policy, unreadable registry, or corrupt audit log refuses to start),
// Start binds the sockets and serves in background goroutines, Stop closes
// them.
package daemon

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/kolz001/setu/internal/audit"
	"github.com/kolz001/setu/internal/broker"
	"github.com/kolz001/setu/internal/control"
	"github.com/kolz001/setu/internal/escalate"
	"github.com/kolz001/setu/internal/identity"
	"github.com/kolz001/setu/internal/policy"
	"github.com/kolz001/setu/internal/servers"
	"github.com/kolz001/setu/internal/snapshot"
)

// Version is the setu release version, reported by --version, the MCP
// handshake, and the control-plane status method.
const Version = "0.1.0"

// Options configures a daemon instance. SocketPath, ControlPath,
// PolicyPath, and StateDir are required.
type Options struct {
	// SocketPath is the agent-facing MCP socket (mode 0666 — any local uid
	// may connect; policy decides what each identity can do).
	SocketPath string
	// ControlPath is the admin socket (mode 0600 — owner only).
	ControlPath string
	// PolicyPath is the TOML policy file, loaded at startup and re-read by
	// `setuctl policy reload`.
	PolicyPath string
	// StateDir holds the audit log, snapshots, and agent registry; created
	// 0700 if absent.
	StateDir string
	// AskTimeout is how long ask-gated calls wait for approval before
	// default-denying (120s if zero).
	AskTimeout time.Duration
	// Backend selects system backends: "auto" (real where the host has
	// them, mock otherwise) or "mock" (all mock, for dev and tests).
	Backend string
	// Notify, if set, replaces the default log-line notifier for pending
	// approvals (hook for desktop notifications or webhooks).
	Notify escalate.Notifier
}

// Daemon is a fully wired broker + control plane. The exported fields give
// embedders (tests, future in-process integrations) direct access to the
// components; ordinary operation only needs New, Start, and Stop.
type Daemon struct {
	Broker     *broker.Broker
	Control    *control.Server
	Policy     *policy.Engine
	Agents     *identity.Registry
	Escalation *escalate.Manager
	Snapshots  *snapshot.Manager
	AuditLog   *audit.Logger
	AuditPath  string // location of the audit log within StateDir

	mcpListener *net.UnixListener
	ctlListener *net.UnixListener
}

// New builds a daemon from options; call Start to begin serving.
func New(o Options) (*Daemon, error) {
	if o.StateDir == "" {
		return nil, fmt.Errorf("state dir required")
	}
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return nil, err
	}

	eng, err := policy.Load(o.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}
	agents, err := identity.LoadRegistry(filepath.Join(o.StateDir, "agents.json"))
	if err != nil {
		return nil, err
	}
	auditPath := filepath.Join(o.StateDir, "audit.log")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	snaps, err := snapshot.NewManager(filepath.Join(o.StateDir, "snapshots"))
	if err != nil {
		return nil, err
	}
	notify := o.Notify
	if notify == nil {
		notify = func(r escalate.Request) {
			log.Printf("APPROVAL NEEDED: agent %q wants %s (id %s) — resolve with: setuctl approve %s (or deny)",
				r.Agent, r.Tool, r.ID, r.ID)
		}
	}
	esc := escalate.NewManager(o.AskTimeout, notify)

	reg := servers.NewRegistry()
	registerBackends(reg, o.Backend)

	b := broker.New(broker.Config{
		Registry:   reg,
		Policy:     eng,
		Audit:      auditLog,
		Snapshots:  snaps,
		Escalation: esc,
		Agents:     agents,
	})

	ctl := &control.Server{
		Broker:     b,
		Policy:     eng,
		Agents:     agents,
		Escalation: esc,
		Snapshots:  snaps,
		AuditPath:  auditPath,
		PolicyPath: o.PolicyPath,
		Started:    time.Now().UTC(),
		Version:    Version,
	}

	return &Daemon{
		Broker: b, Control: ctl, Policy: eng, Agents: agents,
		Escalation: esc, Snapshots: snaps, AuditLog: auditLog, AuditPath: auditPath,
	}, nil
}

// registerBackends picks real system backends where the host has them,
// mock backends otherwise ("auto"), or all-mock ("mock") for dev/testing.
func registerBackends(reg *servers.Registry, mode string) {
	mock := mode == "mock"

	if !mock && haveJournalctl() {
		reg.Register(servers.JournalTools(servers.JournalctlBackend{})...)
	} else {
		reg.Register(servers.JournalTools(&servers.MockJournal{})...)
	}
	if !mock && haveSystemctl() {
		reg.Register(servers.SystemdTools(servers.SystemctlBackend{})...)
	} else {
		reg.Register(servers.SystemdTools(servers.NewMockSystemd())...)
	}
	reg.Register(servers.FSTools()...) // stdlib; real on every OS
	if mock {
		reg.Register(servers.PkgTools(servers.NewMockPkg())...)
	} else if pb := servers.DetectPkgBackend(); pb != nil {
		reg.Register(servers.PkgTools(pb)...)
	} else {
		reg.Register(servers.PkgTools(servers.NewMockPkg())...)
	}
	if mock {
		reg.Register(servers.NetTools(servers.MockNet{})...)
	} else {
		reg.Register(servers.NetTools(servers.ExecNetBackend{})...)
	}
}

// Start binds both sockets and begins serving in background goroutines; it
// returns immediately (callers wait on signals or test logic). Socket modes
// encode the trust model: the agent socket is world-connectable because
// policy — not filesystem permission — is the authorization layer for
// agents, while the control socket is owner-only because filesystem
// permission IS the authorization layer for admin operations.
func (d *Daemon) Start(o Options) error {
	ml, err := listenUnix(o.SocketPath, 0o666) // agent socket: any local uid may connect; policy decides what they can do
	if err != nil {
		return err
	}
	cl, err := listenUnix(o.ControlPath, 0o600) // admin socket: owner only
	if err != nil {
		ml.Close()
		return err
	}
	d.mcpListener, d.ctlListener = ml, cl

	go func() {
		if err := d.Control.Serve(cl); err != nil {
			log.Printf("control plane exited: %v", err)
		}
	}()
	go func() {
		if err := d.Broker.Serve(ml); err != nil {
			log.Printf("broker exited: %v", err)
		}
	}()
	return nil
}

// Stop closes both listeners (ending Serve loops) and the audit log. Live
// sessions are severed by their connections closing; Stop does not drain
// in-flight calls (v1 accepts losing their results, not their audit
// entries — those are appended before the reply).
func (d *Daemon) Stop() {
	if d.mcpListener != nil {
		d.mcpListener.Close()
	}
	if d.ctlListener != nil {
		d.ctlListener.Close()
	}
	d.AuditLog.Close()
}

// listenUnix binds a Unix listener at path with the given socket file mode,
// creating parent directories and clearing a stale socket left by an
// unclean shutdown (only ever an actual socket — a regular file at the
// path is an error surfaced by the bind, not silently deleted).
func listenUnix(path string, mode os.FileMode) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// Remove a stale socket from an unclean shutdown.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		os.Remove(path)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// haveJournalctl and haveSystemctl gate real-vs-mock backend selection for
// the journal and systemd servers respectively.
func haveJournalctl() bool { return lookPath("journalctl") }
func haveSystemctl() bool  { return lookPath("systemctl") }
