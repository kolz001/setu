// Package escalate implements the human-in-the-loop path behind the `ask`
// policy action.
//
// Flow: a governed call that evaluates to ask blocks inside Manager.Ask
// while the request sits in a pending queue, visible to operators via
// `setuctl approvals` and resolvable via `setuctl approve|deny <id>`.
// Timeouts default to deny — an unattended system fails closed. An approval
// may carry a TTL, creating a temporary grant for the same (agent, tool)
// pair so a burst of identical asks doesn't page the operator repeatedly.
//
// State is in-memory only, deliberately: pending asks are attached to live,
// blocked calls, which do not survive a daemon restart either; and dropping
// grants on restart errs toward requiring a fresh human decision.
//
// Concurrency: all Manager methods are safe for concurrent use.
package escalate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// Request is one pending approval as shown to operators.
type Request struct {
	// ID is the short handle operators pass to `setuctl approve|deny`.
	ID string `json:"id"`
	// Agent and Tool identify what is being asked for.
	Agent string `json:"agent"`
	Tool  string `json:"tool"`
	// Args is the call's canonicalized argument JSON, so the operator can
	// see exactly what would run (unit name, path, package, ...).
	Args json.RawMessage `json:"args,omitempty"`
	// Created and Expires bound the request's lifetime; at Expires the
	// blocked call gives up and is denied.
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

// pending pairs a queued Request with the channel its blocked call waits on.
type pending struct {
	req Request
	ch  chan verdict // buffered(1): Resolve never blocks on a racing timeout
}

// verdict is an operator's answer to one request.
type verdict struct {
	approved bool
	ttl      time.Duration // >0: also grant (agent, tool) for this duration
}

// Grant is a temporary standing approval: while unexpired, asks for the
// same (agent, tool) are approved without prompting.
type Grant struct {
	Agent   string    `json:"agent"`
	Tool    string    `json:"tool"`
	Expires time.Time `json:"expires"`
}

// Notifier is invoked once per new pending request — the hook for desktop
// notifications, webhooks, or log lines. It runs on the asking call's
// goroutine and must not block.
type Notifier func(Request)

// Manager owns the pending-approval queue and active grants.
type Manager struct {
	mu      sync.Mutex
	pending map[string]*pending
	grants  []Grant
	timeout time.Duration
	notify  Notifier
}

// NewManager creates a Manager whose asks wait at most timeout before
// default-denying (120s if timeout <= 0). notify may be nil.
func NewManager(timeout time.Duration, notify Notifier) *Manager {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Manager{pending: map[string]*pending{}, timeout: timeout, notify: notify}
}

// Outcome describes how an ask was resolved.
type Outcome string

// Ask outcomes. Only Approved and ApprovedTTL let the call proceed; the
// broker treats everything else as a deny and audits the distinction.
const (
	Approved    Outcome = "approved"       // operator approved this call
	ApprovedTTL Outcome = "approved_grant" // matched an active TTL grant, no prompt
	Denied      Outcome = "denied"         // operator denied this call
	TimedOut    Outcome = "timed_out"      // no answer in time, or ctx canceled
)

// Ask blocks until the request is approved, denied, times out, or ctx ends
// (context cancellation reports TimedOut — the call did not get approval).
//
// An active grant for (agent, tool) short-circuits to ApprovedTTL without
// queueing or notifying. Otherwise the request is queued, the notifier
// fires, and the calling goroutine — which is the blocked tool call —
// parks until Resolve or timeout. The pending entry is removed on every
// exit path.
func (m *Manager) Ask(ctx context.Context, agent, tool string, args json.RawMessage) Outcome {
	m.mu.Lock()
	// Sweep expired grants and check for a live one in a single pass.
	now := time.Now()
	kept := m.grants[:0]
	granted := false
	for _, g := range m.grants {
		if g.Expires.After(now) {
			kept = append(kept, g)
			if g.Agent == agent && g.Tool == tool {
				granted = true
			}
		}
	}
	m.grants = kept
	if granted {
		m.mu.Unlock()
		return ApprovedTTL
	}

	b := make([]byte, 6)
	rand.Read(b)
	id := hex.EncodeToString(b)
	p := &pending{
		req: Request{ID: id, Agent: agent, Tool: tool, Args: args,
			Created: now, Expires: now.Add(m.timeout)},
		ch: make(chan verdict, 1),
	}
	m.pending[id] = p
	notify := m.notify
	m.mu.Unlock()

	if notify != nil {
		notify(p.req)
	}

	timer := time.NewTimer(m.timeout)
	defer timer.Stop()
	defer func() {
		m.mu.Lock()
		delete(m.pending, id)
		m.mu.Unlock()
	}()

	select {
	case v := <-p.ch:
		if !v.approved {
			return Denied
		}
		if v.ttl > 0 {
			m.mu.Lock()
			m.grants = append(m.grants, Grant{Agent: agent, Tool: tool, Expires: time.Now().Add(v.ttl)})
			m.mu.Unlock()
		}
		return Approved
	case <-timer.C:
		return TimedOut
	case <-ctx.Done():
		return TimedOut
	}
}

// List returns a snapshot of pending requests, in no particular order.
func (m *Manager) List() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Request, 0, len(m.pending))
	for _, p := range m.pending {
		out = append(out, p.req)
	}
	return out
}

// Grants returns the currently active (unexpired) TTL grants.
func (m *Manager) Grants() []Grant {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var out []Grant
	for _, g := range m.grants {
		if g.Expires.After(now) {
			out = append(out, g)
		}
	}
	return out
}

// Resolve delivers an operator's verdict on pending request id, unblocking
// the waiting call. approve with ttl > 0 additionally grants the same
// (agent, tool) for that duration. Returns false if no such request is
// pending (already resolved, timed out, or never existed) — the operator
// gets an error instead of a silent no-op.
func (m *Manager) Resolve(id string, approve bool, ttl time.Duration) bool {
	m.mu.Lock()
	p, ok := m.pending[id]
	if ok {
		delete(m.pending, id)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	p.ch <- verdict{approved: approve, ttl: ttl}
	return true
}
