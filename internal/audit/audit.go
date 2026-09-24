// Package audit implements setu's append-only, hash-chained audit log.
//
// Every tool call — allowed or denied — produces exactly one JSON-lines
// entry. Each entry's hash covers the previous entry's hash, forming a chain
// anchored at a fixed genesis value, so any in-place edit, removal,
// reordering, or truncation of history is detectable by Verify. (Tamper
// *evidence*, not tamper *prevention*: an attacker with write access to the
// log can still destroy it — they just can't quietly rewrite it. Periodic
// external anchoring of the head hash is the roadmap answer for that.)
//
// The file format is one JSON object per line, written with O_APPEND so
// concurrent daemon restarts cannot interleave partial entries.
//
// Concurrency: Logger methods are safe for concurrent use. Query and Verify
// are standalone functions that read the file independently of any Logger.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kolz001/setu/internal/identity"
)

// Entry is one audit record.
//
// Integrity fields: Hash = SHA-256(PrevHash || canonical JSON of the entry
// with Hash set to empty), hex-encoded. PrevHash of the first entry is the
// genesis constant (all zeroes).
type Entry struct {
	// Seq is the 1-based position in the log; gaps or repeats fail Verify.
	Seq int64 `json:"seq"`
	// Time is when the entry was appended (UTC).
	Time time.Time `json:"time"`
	// SessionID identifies the broker session that made the call.
	SessionID string `json:"session_id"`
	// Agent is the session's full identity snapshot (name, authenticated,
	// peer credentials, task manifest).
	Agent identity.Identity `json:"agent"`
	// Tool is the tool that was called, e.g. "fs.write".
	Tool string `json:"tool"`
	// Args is the canonicalized argument object as JSON — what policy
	// actually evaluated, not the agent's raw strings. Large values are
	// replaced by their size and SHA-256 (see boundArgs), so file contents
	// written via fs.write are fingerprinted rather than copied into the log.
	Args json.RawMessage `json:"args,omitempty"`
	// RuleIndex is the matched policy rule (zero-based), or -1 for the
	// default deny.
	RuleIndex int `json:"rule_index"`
	// Decision is the effective outcome: "allow", "deny",
	// "allow_with_snapshot", or "allow_after_ask".
	Decision string `json:"decision"`
	// Reason explains the decision (which rule, why denied, ask outcome).
	Reason string `json:"reason,omitempty"`
	// OK reports whether the tool executed successfully (always false for
	// denies).
	OK bool `json:"ok"`
	// Result is a summary of the tool output or error, truncated to 400
	// bytes — the audit log records what happened, not full payloads.
	Result string `json:"result,omitempty"`
	// SnapshotID links to the pre-mutation snapshot taken for this call, if
	// any; `setuctl rollback <id>` reverses it.
	SnapshotID string `json:"snapshot_id,omitempty"`
	// PrevHash chains this entry to its predecessor.
	PrevHash string `json:"prev_hash"`
	// Hash authenticates this entry (see type comment for the formula).
	Hash string `json:"hash"`
}

// Field caps, applied by Append before hashing. Agents control most entry
// fields — declared name, task manifest, tool name, arguments, and error
// text derived from them — and may send messages up to 8 MiB, which JSON
// escaping can expand sixfold on the way to disk. Unbounded, one call could
// write a line longer than the log readers accept, and from then on Open
// (so daemon startup), Query, and Verify would all fail.
const (
	maxResult   = 400      // Result: a summary, not the payload
	maxName     = 256      // Tool, agent name
	maxText     = 1024     // Reason, task manifest
	maxArgValue = 1024     // one top-level argument value, as JSON
	maxArgs     = 16 << 10 // the whole argument object, as JSON
)

// clip truncates s to at most n bytes (on a UTF-8 boundary) plus a marker.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…(truncated)"
}

// fingerprint describes omitted data by size and SHA-256, so an operator
// can still match it against a known payload.
func fingerprint(b []byte) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("[omitted by audit: %d bytes, sha256:%s]", len(b), hex.EncodeToString(h[:]))
}

// boundArgs caps the argument object. Each top-level value whose JSON form
// exceeds maxArgValue is replaced by a fingerprint (of the decoded string
// for string values, else of its JSON); if the object is still over maxArgs
// (many keys, or huge keys) it collapses to a single fingerprint. Values
// that fit are kept byte-for-byte.
func boundArgs(raw json.RawMessage) json.RawMessage {
	if len(raw) <= maxArgValue {
		return raw
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		m = nil
	}
	changed := false
	for k, v := range m {
		if len(v) <= maxArgValue {
			continue
		}
		data := []byte(v)
		var str string
		if json.Unmarshal(v, &str) == nil {
			data = []byte(str)
		}
		m[k], _ = json.Marshal(fingerprint(data))
		changed = true
	}
	out := raw
	if m != nil && changed {
		out, _ = json.Marshal(m)
	}
	if m == nil || len(out) > maxArgs {
		out, _ = json.Marshal(map[string]string{"_omitted": fingerprint(raw)})
	}
	return out
}

// genesisHash anchors the chain: the PrevHash of the first entry.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Logger appends entries to a JSONL file opened O_APPEND.
type Logger struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	seq      int64  // seq of the last appended entry
	lastHash string // hash of the last appended entry
}

// Open opens (creating if needed, mode 0600) the audit log at path and
// recovers chain state — last sequence number and hash — by scanning to the
// final entry, so appends continue the existing chain across daemon
// restarts. A log whose final line is unparseable fails Open: appending to
// a corrupt log would bake the corruption into the chain.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Logger{f: f, path: path, lastHash: genesisHash}
	last, err := lastEntry(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	if last != nil {
		l.seq = last.Seq
		l.lastHash = last.Hash
	}
	return l, nil
}

// Close releases the underlying file. The Logger must not be used after.
func (l *Logger) Close() error { return l.f.Close() }

// lastEntry scans the log and returns its final entry, or nil for an empty
// (or absent-content) log. Any unparseable line is an error — see Open.
func lastEntry(path string) (*Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var last *Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			seq := int64(1)
			if last != nil {
				seq = last.Seq + 1
			}
			return nil, fmt.Errorf("audit log corrupt at seq %d: %w", seq, err)
		}
		e2 := e
		last = &e2
	}
	return last, sc.Err()
}

// entryHash computes the chain hash for e as it would appear on disk:
// SHA-256 over prevHash followed by e's canonical JSON with the Hash field
// emptied. Go's encoding/json emits struct fields in declaration order, so
// the byte representation is deterministic for a given Entry value.
func entryHash(prevHash string, e Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// Append assigns the entry's sequence number, chain hashes, and timestamp
// (if unset), bounds every agent-influenced field (see the field caps), and
// writes the entry as one line. It returns the completed entry as written.
//
// On write failure the entry is lost and the error returned; the broker
// logs this loudly. (Fail-closed auditing — refusing the call when the
// audit write fails — is a deliberate roadmap decision, not yet v1.)
func (l *Logger) Append(e Entry) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.Seq = l.seq
	e.PrevHash = l.lastHash
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Tool = clip(e.Tool, maxName)
	e.Agent.Name = clip(e.Agent.Name, maxName)
	e.Agent.Task = clip(e.Agent.Task, maxText)
	e.Reason = clip(e.Reason, maxText)
	e.Result = clip(e.Result, maxResult)
	e.Args = boundArgs(e.Args)
	e.Hash = entryHash(e.PrevHash, e)
	b, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return e, err
	}
	l.lastHash = e.Hash
	return e, nil
}

// QueryFilter selects audit entries; zero-value fields don't filter.
type QueryFilter struct {
	// Agent filters by agent name; glob patterns allowed.
	Agent string `json:"agent,omitempty"`
	// Tool filters by tool name; glob patterns allowed.
	Tool string `json:"tool,omitempty"`
	// Decision filters by exact decision string ("deny", "allow", ...).
	Decision string `json:"decision,omitempty"`
	// Since keeps only entries at or after this time.
	Since time.Time `json:"since,omitempty"`
	// Last, if positive, keeps only the final N matches (applied after the
	// other filters).
	Last int `json:"last,omitempty"`
}

// Query scans the log at path and returns entries matching f, oldest first.
// A missing log yields (nil, nil) — no calls have happened yet. Query does
// not verify hashes; run Verify for integrity.
func Query(path string, f QueryFilter) ([]Entry, error) {
	fh, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []Entry
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		if f.Agent != "" && !globLike(f.Agent, e.Agent.Name) {
			continue
		}
		if f.Tool != "" && !globLike(f.Tool, e.Tool) {
			continue
		}
		if f.Decision != "" && f.Decision != e.Decision {
			continue
		}
		if !f.Since.IsZero() && e.Time.Before(f.Since) {
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if f.Last > 0 && len(out) > f.Last {
		out = out[len(out)-f.Last:]
	}
	return out, nil
}

// globLike matches s against pattern, treating a pattern without glob
// metacharacters as an exact string (so "fs.write" doesn't need escaping
// even though '.' appears in path.Match syntax).
func globLike(pattern, s string) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == s
	}
	ok, err := filepath.Match(pattern, s)
	return err == nil && ok
}

// Verify replays the entire hash chain at path and returns the count of
// valid entries. A missing log verifies trivially (0, nil).
//
// The returned error names the first broken point and what broke:
// unparseable line, sequence gap (entries removed or reordered), prev-hash
// mismatch (chain spliced), or hash mismatch (entry modified in place).
// Truncation from the *end* of the log is the one edit this scheme cannot
// see — countering it requires anchoring the head hash externally (roadmap).
func Verify(path string) (int64, error) {
	fh, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	prev := genesisHash
	var n int64
	var expectSeq int64 = 1
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, fmt.Errorf("entry after seq %d: unparseable: %w", n, err)
		}
		if e.Seq != expectSeq {
			return n, fmt.Errorf("seq %d: expected seq %d (entries removed or reordered)", e.Seq, expectSeq)
		}
		if e.PrevHash != prev {
			return n, fmt.Errorf("seq %d: prev_hash mismatch (chain broken)", e.Seq)
		}
		if entryHash(prev, e) != e.Hash {
			return n, fmt.Errorf("seq %d: hash mismatch (entry modified)", e.Seq)
		}
		prev = e.Hash
		n++
		expectSeq++
	}
	return n, sc.Err()
}
