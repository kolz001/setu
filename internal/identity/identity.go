// Package identity resolves who is on the other end of a broker connection.
//
// setu's identity model has two layers:
//
//   - Kernel peer credentials (uid/gid/pid), read from the Unix socket via
//     SO_PEERCRED (Linux) or LOCAL_PEERCRED (macOS). These cannot be forged
//     by an unprivileged peer and are always recorded.
//   - Optional registered-agent tokens, for identities finer than a uid
//     (e.g. "tvastr-fixer" vs "tvastr-reviewer" under the same service uid).
//     Tokens are issued once via `setuctl agent register` and stored only as
//     SHA-256 hashes.
//
// The result of resolution is an Identity: an immutable snapshot bound to a
// session at initialize time. Policy is evaluated against this snapshot for
// the session's lifetime, so a mid-run registry or policy change applies on
// the next connect, never mid-flight.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PeerCred is the kernel-reported identity of a Unix socket peer. UID and
// GID are trustworthy (kernel-asserted); PID is informational — the process
// may exit or the pid may be recycled while the connection lives.
type PeerCred struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
	PID int `json:"pid"`
}

// Identity is the immutable per-session identity snapshot that policy
// evaluates against and audit entries record.
type Identity struct {
	// Name is the effective agent name: the registered name when a valid
	// token was presented, otherwise the self-declared (advisory) name, or
	// "anonymous" when none was declared.
	Name string `json:"name"`
	// Authenticated is true only when a valid registered-agent token was
	// presented. Policy rules can require this via require_token.
	Authenticated bool `json:"authenticated"`
	// Peer holds the kernel credentials captured at connect time.
	Peer PeerCred `json:"peer"`
	// Task is the session's declared task manifest, if any. Recorded in
	// audit; not yet enforced (v2 roadmap: intent-scoped capabilities).
	Task string `json:"task,omitempty"`
}

// String renders the identity for logs, e.g.
// "tvastr-fixer (authenticated, uid=982 pid=4711)".
func (id Identity) String() string {
	auth := "unauthenticated"
	if id.Authenticated {
		auth = "authenticated"
	}
	return fmt.Sprintf("%s (%s, uid=%d pid=%d)", id.Name, auth, id.Peer.UID, id.Peer.PID)
}

// FromConn extracts kernel peer credentials from a connected Unix socket.
// It fails only if the platform getsockopt does, in which case the broker
// refuses the connection — a session must never exist without kernel-backed
// credentials.
func FromConn(conn *net.UnixConn) (PeerCred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return PeerCred{}, err
	}
	var cred PeerCred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = peerCred(fd) // per-platform: peercred_linux.go / peercred_darwin.go
	}); err != nil {
		return PeerCred{}, err
	}
	return cred, credErr
}

// --- Registered agents ---

// registeredAgent is one entry in the on-disk registry. The token itself is
// never stored — only its SHA-256 hex digest.
type registeredAgent struct {
	Name      string    `json:"name"`
	TokenHash string    `json:"token_sha256"`
	UID       *int      `json:"uid,omitempty"` // optional uid pin: token only valid from this uid
	CreatedAt time.Time `json:"created_at"`
}

// registryFile is the JSON document persisted at Registry.path.
type registryFile struct {
	Agents []registeredAgent `json:"agents"`
}

// Registry stores registered agent names with hashed tokens, persisted as a
// JSON file under the daemon's state directory (0600).
//
// Registration is a claim on the name: once a name is registered, a
// connection declaring it without the valid token is rejected outright —
// the name cannot be assumed by declaration alone.
//
// Concurrency: all methods are safe for concurrent use.
type Registry struct {
	mu   sync.Mutex
	path string
	data registryFile
}

// ErrTokenRequired is returned by Resolve when a connection declares a
// registered name without presenting a token.
var ErrTokenRequired = errors.New("agent name is registered: a valid token is required")

// ErrBadToken is returned by Resolve when the presented token matches no
// registered agent.
var ErrBadToken = errors.New("invalid agent token")

// LoadRegistry reads the registry at path, or initializes an empty one if
// the file does not exist yet (first boot). Any other read or parse failure
// is fatal to daemon startup — a half-read registry must not silently drop
// registered agents, because that would reopen their names to squatting.
func LoadRegistry(path string) (*Registry, error) {
	r := &Registry{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &r.data); err != nil {
		return nil, fmt.Errorf("agent registry %s: %w", path, err)
	}
	return r, nil
}

// save persists the registry atomically (write temp file, rename) so a
// crash mid-write cannot corrupt it. Caller must hold r.mu.
func (r *Registry) save() error {
	b, err := json.MarshalIndent(&r.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// hashToken returns the hex SHA-256 digest under which a token is stored
// and compared.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Register creates a registered agent named name and returns the plaintext
// token — the only time it is ever available; store it now. Registering an
// existing name rotates its token (the old token stops working immediately
// for new sessions). A non-nil uid pins the token: sessions presenting it
// from any other uid are rejected.
func (r *Registry) Register(name string, uid *int) (string, error) {
	if name == "" || name == "*" {
		return "", errors.New("invalid agent name")
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := "setu_" + hex.EncodeToString(buf)

	r.mu.Lock()
	defer r.mu.Unlock()
	entry := registeredAgent{Name: name, TokenHash: hashToken(token), UID: uid, CreatedAt: time.Now().UTC()}
	replaced := false
	for i, a := range r.data.Agents {
		if a.Name == name {
			r.data.Agents[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		r.data.Agents = append(r.data.Agents, entry)
	}
	if err := r.save(); err != nil {
		return "", err
	}
	return token, nil
}

// Revoke removes a registered agent. Its token stops working for new
// sessions immediately; live sessions keep their identity snapshot (freeze
// the agent to cut those off). Revoking also releases the name for
// unauthenticated declaration again.
func (r *Registry) Revoke(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, a := range r.data.Agents {
		if a.Name == name {
			r.data.Agents = append(r.data.Agents[:i], r.data.Agents[i+1:]...)
			return r.save()
		}
	}
	return fmt.Errorf("agent %q not registered", name)
}

// List returns each registered agent's name, creation time, and uid pin (if
// set) for operator display. Token hashes are never exposed.
func (r *Registry) List() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]map[string]any, 0, len(r.data.Agents))
	for _, a := range r.data.Agents {
		m := map[string]any{"name": a.Name, "created_at": a.CreatedAt}
		if a.UID != nil {
			m["uid"] = *a.UID
		}
		out = append(out, m)
	}
	return out
}

// Resolve turns a connection's claims (declared name, token) plus its kernel
// peer credentials into a session Identity. The rules:
//
//   - Valid token → identity is the token's registered name, authenticated,
//     regardless of the declared name. If the registration pins a uid, the
//     peer uid must match.
//   - Token presented but invalid → ErrBadToken (connection rejected; never
//     silently downgraded to unauthenticated).
//   - No token, declared name is registered → ErrTokenRequired.
//   - No token, unregistered name → unauthenticated identity under that
//     name, or "anonymous" if none was declared.
//
// Token comparison is constant-time over the stored hash.
func (r *Registry) Resolve(declared, token string, peer PeerCred) (Identity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if token != "" {
		th := hashToken(token)
		for _, a := range r.data.Agents {
			if subtle.ConstantTimeCompare([]byte(a.TokenHash), []byte(th)) == 1 {
				if a.UID != nil && *a.UID != peer.UID {
					return Identity{}, fmt.Errorf("token for %q is pinned to uid %d, peer is uid %d", a.Name, *a.UID, peer.UID)
				}
				return Identity{Name: a.Name, Authenticated: true, Peer: peer}, nil
			}
		}
		return Identity{}, ErrBadToken
	}
	if declared == "" {
		declared = "anonymous"
	}
	for _, a := range r.data.Agents {
		if a.Name == declared {
			return Identity{}, ErrTokenRequired
		}
	}
	return Identity{Name: declared, Authenticated: false, Peer: peer}, nil
}
