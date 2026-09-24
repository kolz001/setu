// Package control implements setu's admin plane: a second Unix socket,
// owner-only (0600), speaking plain JSON-RPC (not MCP). setuctl is its
// client.
//
// Separation rationale: admin operations — approving escalations,
// registering agents, freezing, rolling back, reloading policy — must never
// flow through the agent-facing socket, where a confined agent could reach
// them; authorization is the filesystem permission on the socket itself.
//
// Method catalog (dispatch): status, sessions.list, agents.register/list/
// revoke, freeze, unfreeze, approvals.list, approvals.resolve,
// policy.reload, audit.query, audit.verify, snapshots.list, rollback.
package control

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"time"

	"github.com/kolz001/setu/internal/audit"
	"github.com/kolz001/setu/internal/broker"
	"github.com/kolz001/setu/internal/escalate"
	"github.com/kolz001/setu/internal/identity"
	"github.com/kolz001/setu/internal/jsonrpc"
	"github.com/kolz001/setu/internal/policy"
	"github.com/kolz001/setu/internal/snapshot"
)

// Server exposes admin operations over the control socket. All fields are
// required; package daemon assembles them.
type Server struct {
	// Broker provides the session table and freeze switch.
	Broker *broker.Broker
	// Policy is the live engine; policy.reload swaps its rules in place so
	// the broker sees the change without restarting.
	Policy *policy.Engine
	// Agents is the registered-agent store behind agents.*.
	Agents *identity.Registry
	// Escalation provides pending approvals and grants.
	Escalation *escalate.Manager
	// Snapshots serves snapshots.list and rollback.
	Snapshots *snapshot.Manager
	// AuditPath locates the audit log for audit.query / audit.verify.
	AuditPath string
	// PolicyPath is the policy file re-read by policy.reload.
	PolicyPath string
	// Started and Version feed the status report.
	Started time.Time
	Version string
}

// Serve accepts control connections until the listener closes, one handler
// goroutine per connection. It returns nil on clean shutdown.
func (s *Server) Serve(l *net.UnixListener) error {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// handle serves one control connection: requests are dispatched in order;
// notifications are ignored; dispatch errors become JSON-RPC error
// responses rather than closing the connection.
func (s *Server) handle(conn *net.UnixConn) {
	defer conn.Close()
	rpc := jsonrpc.NewConn(conn)
	for {
		msg, err := rpc.Read()
		if err != nil {
			return
		}
		if !msg.IsRequest() {
			continue
		}
		result, err := s.dispatch(msg.Method, msg.Params)
		if err != nil {
			rpc.ReplyError(msg.ID, jsonrpc.CodeInvalidParams, err.Error())
			continue
		}
		rpc.Reply(msg.ID, result)
	}
}

// registerParams are the parameters of agents.register.
type registerParams struct {
	Name string `json:"name"`
	UID  *int   `json:"uid,omitempty"` // optional uid pin for the token
}

// nameParams carry the single agent-name argument of agents.revoke, freeze,
// and unfreeze.
type nameParams struct {
	Name string `json:"name"`
}

// resolveParams are the parameters of approvals.resolve.
type resolveParams struct {
	ID      string `json:"id"`
	Approve bool   `json:"approve"`
	TTLSecs int    `json:"ttl_seconds,omitempty"` // >0 also grants (agent, tool) for this long
}

// idParams carry the single snapshot-id argument of rollback.
type idParams struct {
	ID string `json:"id"`
}

// dispatch routes one control method to its implementation and returns the
// JSON-marshalable result. Errors are reported to the client verbatim —
// the operator on the other end is trusted (socket permissions enforce
// that) and needs real diagnostics. State-changing operations log for the
// daemon journal.
func (s *Server) dispatch(method string, raw json.RawMessage) (any, error) {
	switch method {
	case "status":
		return map[string]any{
			"version":       s.Version,
			"started":       s.Started,
			"uptime_sec":    int(time.Since(s.Started).Seconds()),
			"sessions":      s.Broker.Sessions(),
			"frozen_agents": s.Broker.Frozen(),
			"rules":         len(s.Policy.Rules()),
			"pending_asks":  s.Escalation.List(),
			"grants":        s.Escalation.Grants(),
		}, nil

	case "sessions.list":
		return s.Broker.Sessions(), nil

	case "agents.register":
		var p registerParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		token, err := s.Agents.Register(p.Name, p.UID)
		if err != nil {
			return nil, err
		}
		log.Printf("control: registered agent %q", p.Name)
		return map[string]string{"name": p.Name, "token": token}, nil

	case "agents.list":
		return s.Agents.List(), nil

	case "agents.revoke":
		var p nameParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		if err := s.Agents.Revoke(p.Name); err != nil {
			return nil, err
		}
		return map[string]string{"revoked": p.Name}, nil

	case "freeze":
		var p nameParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		s.Broker.Freeze(p.Name)
		log.Printf("control: froze agent %q", p.Name)
		return map[string]any{"frozen": s.Broker.Frozen()}, nil

	case "unfreeze":
		var p nameParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		s.Broker.Unfreeze(p.Name)
		return map[string]any{"frozen": s.Broker.Frozen()}, nil

	case "approvals.list":
		return map[string]any{"pending": s.Escalation.List(), "grants": s.Escalation.Grants()}, nil

	case "approvals.resolve":
		var p resolveParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		ok := s.Escalation.Resolve(p.ID, p.Approve, time.Duration(p.TTLSecs)*time.Second)
		if !ok {
			return nil, errors.New("no pending approval with id " + p.ID)
		}
		verdict := "denied"
		if p.Approve {
			verdict = "approved"
		}
		log.Printf("control: approval %s %s", p.ID, verdict)
		return map[string]string{"id": p.ID, "result": verdict}, nil

	case "policy.reload":
		fresh, err := policy.Load(s.PolicyPath)
		if err != nil {
			return nil, errors.New("policy not reloaded (file invalid): " + err.Error())
		}
		s.Policy.Reload(fresh)
		n := len(s.Policy.Rules())
		log.Printf("control: policy reloaded from %s (%d rules)", s.PolicyPath, n)
		return map[string]any{"reloaded": true, "rules": n}, nil

	case "audit.query":
		var f audit.QueryFilter
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
		}
		entries, err := audit.Query(s.AuditPath, f)
		if err != nil {
			return nil, err
		}
		if entries == nil {
			entries = []audit.Entry{}
		}
		return entries, nil

	case "audit.verify":
		n, err := audit.Verify(s.AuditPath)
		if err != nil {
			return map[string]any{"valid_entries": n, "ok": false, "error": err.Error()}, nil
		}
		return map[string]any{"valid_entries": n, "ok": true}, nil

	case "snapshots.list":
		list, err := s.Snapshots.List()
		if err != nil {
			return nil, err
		}
		if list == nil {
			list = []*snapshot.Manifest{}
		}
		return list, nil

	case "rollback":
		var p idParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		if err := s.Snapshots.Rollback(p.ID); err != nil {
			return nil, err
		}
		log.Printf("control: rolled back snapshot %s", p.ID)
		return map[string]string{"rolled_back": p.ID}, nil

	default:
		return nil, errors.New("unknown control method: " + method)
	}
}
