// Package broker is setu's core: it accepts MCP connections on a Unix
// socket, binds each session to a kernel-verified identity, and pushes every
// tool call through the governed pipeline
//
//	canonicalize → freeze check → policy → escalate/snapshot → execute → audit
//
// (implemented in callTool; canonicalization lives in canonicalize.go).
// The broker is the single choke point between agents and the system: the
// one place to authorize, rate-limit, audit, and kill-switch agent access.
//
// Session model: the first request on a connection must be MCP initialize,
// which fixes the session's Identity for the connection's lifetime (see
// package identity). Everything an agent can discover (tools/list) or do
// (tools/call) is filtered through that identity's policy.
//
// Concurrency: one goroutine per connection; requests within a session are
// handled sequentially in arrival order. Cross-session state (session
// table, freeze list) is mutex-guarded; every other collaborator manages
// its own synchronization.
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/kolz001/setu/internal/audit"
	"github.com/kolz001/setu/internal/escalate"
	"github.com/kolz001/setu/internal/identity"
	"github.com/kolz001/setu/internal/jsonrpc"
	"github.com/kolz001/setu/internal/mcp"
	"github.com/kolz001/setu/internal/policy"
	"github.com/kolz001/setu/internal/servers"
	"github.com/kolz001/setu/internal/snapshot"
)

// serverVersion is reported to clients in the initialize handshake.
const serverVersion = "0.1.0"

// Config wires the broker's collaborators. All fields except CallTimeout
// are required; package daemon is the canonical constructor of a complete
// Config.
type Config struct {
	// Registry is the tool table dispatched through.
	Registry *servers.Registry
	// Policy decides every call and every tool listing.
	Policy *policy.Engine
	// Audit receives one entry per tools/call, including denies.
	Audit *audit.Logger
	// Snapshots captures pre-mutation state for allow_with_snapshot calls.
	Snapshots *snapshot.Manager
	// Escalation blocks ask-gated calls pending operator approval.
	Escalation *escalate.Manager
	// Agents resolves session identity at initialize time.
	Agents *identity.Registry
	// CallTimeout bounds a single tool handler's execution (default 60s).
	// It does not cover ask waits, which have their own timeout in the
	// escalation manager.
	CallTimeout time.Duration
}

// Broker serves MCP sessions over a Unix listener. Construct with New,
// drive with Serve; the admin surface (Sessions, Freeze/Unfreeze/Frozen) is
// consumed by package control.
type Broker struct {
	cfg Config

	mu       sync.Mutex              // guards sessions and frozen
	sessions map[string]*SessionInfo // live sessions by session ID
	frozen   map[string]bool         // agent names currently kill-switched
}

// SessionInfo is the operator-visible view of a live session, as returned
// by `setuctl sessions`.
type SessionInfo struct {
	// ID is the broker-assigned session identifier, also stamped on every
	// audit entry the session produces.
	ID string `json:"id"`
	// Agent is the identity snapshot the session is bound to.
	Agent identity.Identity `json:"agent"`
	// Connected is when the session completed initialize (UTC).
	Connected time.Time `json:"connected"`
	// Calls counts tools/call requests made so far.
	Calls int `json:"calls"`
}

// New builds a Broker from cfg, applying the CallTimeout default.
func New(cfg Config) *Broker {
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 60 * time.Second
	}
	return &Broker{cfg: cfg, sessions: map[string]*SessionInfo{}, frozen: map[string]bool{}}
}

// Serve accepts connections until the listener closes, spawning one
// handler goroutine per connection. It returns nil on clean listener
// shutdown and the accept error otherwise.
func (b *Broker) Serve(l *net.UnixListener) error {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go b.handleConn(conn)
	}
}

// --- admin surface (used by the control plane) ---

// Sessions returns a snapshot of live sessions, in no particular order.
func (b *Broker) Sessions() []SessionInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]SessionInfo, 0, len(b.sessions))
	for _, s := range b.sessions {
		out = append(out, *s)
	}
	return out
}

// Freeze kill-switches an agent name: every subsequent call from any
// session under that identity is denied (and audited) until unfrozen.
// Existing sessions stay connected — they just can't do anything — so the
// operator can still inspect them. Matching is by exact effective name.
func (b *Broker) Freeze(agent string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.frozen[agent] = true
}

// Unfreeze lifts a Freeze. Unknown names are a no-op.
func (b *Broker) Unfreeze(agent string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.frozen, agent)
}

// Frozen returns the currently frozen agent names.
func (b *Broker) Frozen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.frozen))
	for a := range b.frozen {
		out = append(out, a)
	}
	return out
}

// isFrozen reports whether agent is currently kill-switched.
func (b *Broker) isFrozen(agent string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.frozen[agent]
}

// --- session handling ---

// newSessionID mints a short random session identifier ("s-" + 12 hex).
func newSessionID() string {
	buf := make([]byte, 6)
	rand.Read(buf)
	return "s-" + hex.EncodeToString(buf)
}

// handleConn owns one connection for its lifetime: extract peer
// credentials (refusing the connection if unavailable), run the initialize
// handshake to fix the session identity, register the session, then serve
// requests sequentially until the peer disconnects.
func (b *Broker) handleConn(conn *net.UnixConn) {
	defer conn.Close()

	peer, err := identity.FromConn(conn)
	if err != nil {
		log.Printf("broker: rejecting connection: peer credentials unavailable: %v", err)
		return
	}

	rpc := jsonrpc.NewConn(conn)

	// The first request must be initialize; identity is fixed for the session.
	id, sessID, ok := b.awaitInitialize(rpc, peer)
	if !ok {
		return
	}

	info := &SessionInfo{ID: sessID, Agent: id, Connected: time.Now().UTC()}
	b.mu.Lock()
	b.sessions[sessID] = info
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.sessions, sessID)
		b.mu.Unlock()
	}()
	log.Printf("broker: session %s opened by %s", sessID, id)

	for {
		msg, err := rpc.Read()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("broker: session %s read error: %v", sessID, err)
			}
			return
		}
		switch {
		case msg.IsNotification():
			// notifications/initialized etc. — nothing to do
		case msg.Method == "ping":
			rpc.Reply(msg.ID, map[string]any{})
		case msg.Method == "tools/list":
			rpc.Reply(msg.ID, b.listTools(id))
		case msg.Method == "tools/call":
			b.mu.Lock()
			info.Calls++
			b.mu.Unlock()
			result := b.callTool(sessID, id, msg.Params)
			rpc.Reply(msg.ID, result)
		case msg.Method == "initialize":
			rpc.ReplyError(msg.ID, jsonrpc.CodeInvalidRequest, "session already initialized")
		default:
			rpc.ReplyError(msg.ID, jsonrpc.CodeMethodNotFound, "method not supported: "+msg.Method)
		}
	}
}

// awaitInitialize enforces that the connection's first request is MCP
// initialize, resolves the session identity from the declared name, token,
// and peer credentials, and replies with the broker's capabilities. It
// returns ok=false — after sending the appropriate error — if the first
// request is anything else or identity resolution rejects the claims
// (invalid token, registered name without token).
func (b *Broker) awaitInitialize(rpc *jsonrpc.Conn, peer identity.PeerCred) (identity.Identity, string, bool) {
	msg, err := rpc.Read()
	if err != nil {
		return identity.Identity{}, "", false
	}
	if msg.Method != "initialize" || !msg.IsRequest() {
		rpc.ReplyError(msg.ID, jsonrpc.CodeInvalidRequest, "first request must be initialize")
		return identity.Identity{}, "", false
	}
	var params mcp.InitializeParams
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			rpc.ReplyError(msg.ID, jsonrpc.CodeInvalidParams, "bad initialize params: "+err.Error())
			return identity.Identity{}, "", false
		}
	}
	declared := params.Meta.Setu.Agent
	if declared == "" {
		declared = params.ClientInfo.Name
	}
	id, err := b.cfg.Agents.Resolve(declared, params.Meta.Setu.Token, peer)
	if err != nil {
		rpc.ReplyError(msg.ID, jsonrpc.CodeInvalidRequest, "identity rejected: "+err.Error())
		return identity.Identity{}, "", false
	}
	id.Task = params.Meta.Setu.Task

	sessID := newSessionID()
	res := mcp.InitializeResult{
		ProtocolVersion: mcp.ProtocolVersion,
		ServerInfo:      mcp.Implementation{Name: "setu", Version: serverVersion},
		Instructions: "setu brokers access to system capabilities under a deny-by-default " +
			"policy. Only tools your policy permits are listed. Every call is audited. " +
			"Some calls may block pending human approval.",
	}
	res.Capabilities.Tools.ListChanged = false
	if err := rpc.Reply(msg.ID, res); err != nil {
		return identity.Identity{}, "", false
	}
	return id, sessID, true
}

// listTools returns only the tools this identity's policy could ever allow —
// least-privilege visibility, so a prompt-injected "call pkg.install" fails
// at discovery, not just execution.
func (b *Broker) listTools(id identity.Identity) mcp.ListToolsResult {
	res := mcp.ListToolsResult{Tools: []mcp.Tool{}}
	for _, t := range b.cfg.Registry.All() {
		if b.cfg.Policy.ToolVisible(id, t.Name) {
			res.Tools = append(res.Tools, mcp.Tool{
				Name:        t.Name,
				Description: t.Description,
				InputSchema: t.InputSchema,
			})
		}
	}
	return res
}

// callTool runs the full governed pipeline for one tools/call and always
// returns an MCP result (policy denials and failures are tool-level errors,
// never protocol errors, so agents can read and adapt to them).
//
// Every exit path — unknown tools, canonicalization failures, freezes,
// denials, ask timeouts, snapshot failures, handler errors, and success —
// appends exactly one audit entry via the finish closure. The single
// exception is unparseable params, where there is no coherent call to
// attribute.
func (b *Broker) callTool(sessID string, id identity.Identity, rawParams json.RawMessage) *mcp.CallToolResult {
	var params mcp.CallToolParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return mcp.ErrorResult("bad tools/call params: " + err.Error())
	}
	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}

	entry := audit.Entry{SessionID: sessID, Agent: id, Tool: params.Name}
	finish := func(decision, reason string, ok bool, result string) {
		entry.Decision = decision
		entry.Reason = reason
		entry.OK = ok
		entry.Result = result
		if _, err := b.cfg.Audit.Append(entry); err != nil {
			log.Printf("broker: AUDIT WRITE FAILED (session %s, tool %s): %v", sessID, params.Name, err)
		}
	}

	tool, exists := b.cfg.Registry.Get(params.Name)
	// Unknown and policy-hidden tools are indistinguishable to the caller:
	// confirming a tool exists while refusing it would leak the capability
	// surface to agents probing beyond their grant.
	if !exists || !b.cfg.Policy.ToolVisible(id, params.Name) {
		argsJSON, _ := json.Marshal(params.Arguments)
		entry.Args = argsJSON
		entry.RuleIndex = -1
		finish("deny", "tool not available to this agent", false, "")
		return mcp.ErrorResult(fmt.Sprintf("tool %q is not available", params.Name))
	}

	// 1. Canonicalize arguments (before policy, so rules match real targets).
	pargs, err := canonicalize(tool, params.Arguments)
	argsJSON, _ := json.Marshal(params.Arguments) // post-canonicalization view
	entry.Args = argsJSON
	if err != nil {
		entry.RuleIndex = -1
		finish("deny", "invalid arguments: "+err.Error(), false, "")
		return mcp.ErrorResult("invalid arguments: " + err.Error())
	}

	// 2. Kill switch.
	if b.isFrozen(id.Name) {
		entry.RuleIndex = -1
		finish("deny", "agent is frozen", false, "")
		return mcp.ErrorResult("agent is frozen by the operator")
	}

	// 3. Policy.
	dec := b.cfg.Policy.Evaluate(id, params.Name, pargs)
	entry.RuleIndex = dec.RuleIndex
	switch dec.Action {
	case policy.Deny:
		finish("deny", dec.Reason, false, "")
		return mcp.ErrorResult("denied by policy: " + dec.Reason)

	case policy.Ask:
		outcome := b.cfg.Escalation.Ask(context.Background(), id.Name, params.Name, argsJSON)
		switch outcome {
		case escalate.Approved, escalate.ApprovedTTL:
			entry.Reason = dec.Reason + "; ask:" + string(outcome)
		case escalate.Denied:
			finish("deny", dec.Reason+"; ask:denied by operator", false, "")
			return mcp.ErrorResult("denied by operator")
		default: // TimedOut
			finish("deny", dec.Reason+"; ask:timed out (default deny)", false, "")
			return mcp.ErrorResult("approval timed out (default deny)")
		}

	case policy.AllowWithSnapshot:
		if tool.Mutating {
			var targets []string
			for _, argName := range tool.SnapshotArgs {
				if p, ok := params.Arguments[argName].(string); ok && p != "" {
					targets = append(targets, p)
				}
			}
			if len(targets) > 0 {
				snapID, err := b.cfg.Snapshots.Take(id.Name, params.Name, targets)
				if err != nil {
					// Reversibility is the contract of allow_with_snapshot:
					// no snapshot, no mutation.
					finish("deny", "snapshot failed: "+err.Error(), false, "")
					return mcp.ErrorResult("snapshot failed; mutation refused: " + err.Error())
				}
				entry.SnapshotID = snapID
			}
		}
	}

	// 4. Execute.
	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.CallTimeout)
	defer cancel()
	ctx = servers.WithScope(ctx, dec.Scope) // fs handlers stay confined to it
	decision := string(dec.Action)
	if dec.Action == policy.Ask {
		decision = "allow_after_ask"
	}
	out, err := tool.Handler(ctx, params.Arguments)
	if err != nil {
		finish(decision, entry.Reason, false, "error: "+err.Error())
		return mcp.ErrorResult(err.Error())
	}
	finish(decision, firstNonEmpty(entry.Reason, dec.Reason), true, out)

	if entry.SnapshotID != "" {
		out += fmt.Sprintf("\n[setu: snapshot %s taken; operator can roll back this change]", entry.SnapshotID)
	}
	return mcp.TextResult(out)
}

// firstNonEmpty returns a unless it is empty, else b (used to prefer the
// ask-annotated reason over the plain policy reason in audit entries).
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
