// Package jsonrpc implements a minimal JSON-RPC 2.0 codec over
// newline-delimited JSON — the framing MCP uses for stdio transports, which
// setu reuses unchanged over Unix domain sockets.
//
// The package provides two layers:
//
//   - Conn: a symmetric message codec (used by the broker and control-plane
//     servers, which multiplex requests themselves).
//   - Client: a blocking call/response convenience on top of Conn (used by
//     setuctl and tests, which issue one request at a time).
//
// Neither layer spawns goroutines; callers own the read loop.
package jsonrpc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Version is the JSON-RPC protocol version string stamped on every outgoing
// message.
const Version = "2.0"

// MaxMessageBytes bounds a single JSON-RPC message (8 MiB). A peer sending
// an oversized line terminates its own connection with a scanner error
// rather than exhausting broker memory.
const MaxMessageBytes = 8 << 20

// Message is the union of the three JSON-RPC 2.0 message shapes. Exactly one
// interpretation applies to a given message:
//
//   - request:      Method set, ID set
//   - notification: Method set, ID absent
//   - response:     ID set, Result or Error set
//
// ID is kept as raw JSON because JSON-RPC permits string, number, or null
// IDs and the broker must echo them byte-for-byte.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// IsRequest reports whether the message is a request (expects a response).
func (m *Message) IsRequest() bool { return m.Method != "" && len(m.ID) > 0 }

// IsNotification reports whether the message is a notification (no response
// expected, and none may be sent).
func (m *Message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }

// Error is a JSON-RPC 2.0 error object. It implements the error interface so
// it can travel through ordinary Go error returns; Client.Call returns it
// directly when the peer responds with an error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

// Standard JSON-RPC 2.0 error codes, used by servers in this codebase when
// rejecting requests.
const (
	CodeParseError     = -32700 // unparseable JSON received
	CodeInvalidRequest = -32600 // message is not a valid request
	CodeMethodNotFound = -32601 // method not supported
	CodeInvalidParams  = -32602 // params failed validation
	CodeInternalError  = -32603 // server-side failure
)

// Conn reads and writes newline-delimited JSON-RPC messages over any
// ReadWriter (in practice a *net.UnixConn).
//
// Concurrency: Write, Reply, and ReplyError are safe to call from multiple
// goroutines (writes are serialized by an internal mutex, and each message
// is a single line so interleaving cannot corrupt framing). Read must be
// driven by a single goroutine.
type Conn struct {
	r  *bufio.Scanner
	w  io.Writer
	mu sync.Mutex // guards w
}

// NewConn wraps rw in a message codec. The read side is buffered up to
// MaxMessageBytes per message.
func NewConn(rw io.ReadWriter) *Conn {
	sc := bufio.NewScanner(rw)
	sc.Buffer(make([]byte, 64*1024), MaxMessageBytes)
	return &Conn{r: sc, w: rw}
}

// Read blocks for the next message, skipping blank lines.
//
// Errors: io.EOF when the peer closes cleanly; an *Error with CodeParseError
// when a line is not valid JSON (the caller should drop the connection — the
// stream cannot be resynchronized); otherwise the underlying transport
// error, including bufio.ErrTooLong for messages over MaxMessageBytes.
func (c *Conn) Read() (*Message, error) {
	for c.r.Scan() {
		line := c.r.Bytes()
		if len(line) == 0 {
			continue
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, &Error{Code: CodeParseError, Message: err.Error()}
		}
		return &m, nil
	}
	if err := c.r.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

// Write marshals m, stamps the protocol version, and sends it as one line.
func (c *Conn) Write(m *Message) error {
	m.JSONRPC = Version
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	_, err = c.w.Write([]byte{'\n'})
	return err
}

// Reply sends a successful response carrying result (which must be
// JSON-marshalable) for the request identified by id.
func (c *Conn) Reply(id json.RawMessage, result any) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return c.Write(&Message{ID: id, Result: b})
}

// ReplyError sends an error response for the request identified by id, using
// one of the Code* constants and a human-readable message.
func (c *Conn) ReplyError(id json.RawMessage, code int, msg string) error {
	return c.Write(&Message{ID: id, Error: &Error{Code: code, Message: msg}})
}

// Client is a blocking request/response layer over a Conn for simple
// sequential clients (setuctl, tests). It assigns integer request IDs and
// matches responses by ID, discarding server notifications along the way.
//
// Concurrency: Call and Notify are mutex-serialized; only one request can be
// in flight at a time. This is a deliberate simplification — the broker's
// admin and test traffic never needs pipelining.
type Client struct {
	conn   *Conn
	nextID int
	mu     sync.Mutex // serializes whole call round-trips
}

// NewClient wraps rw (typically a connected Unix socket) in a Client.
func NewClient(rw io.ReadWriter) *Client { return &Client{conn: NewConn(rw)} }

// Call sends a request and blocks until the matching response arrives.
// params may be nil (omitted from the wire). If result is non-nil the
// response's result field is unmarshaled into it.
//
// Errors: the peer's *Error verbatim if it responded with one; otherwise
// transport or (un)marshaling errors. There is no timeout — callers that
// need one should set a deadline on the underlying connection.
func (c *Client) Call(method string, params any, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	id, _ := json.Marshal(c.nextID)
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	if err := c.conn.Write(&Message{ID: id, Method: method, Params: raw}); err != nil {
		return err
	}
	for {
		m, err := c.conn.Read()
		if err != nil {
			return err
		}
		if m.IsNotification() {
			continue // servers may notify at any time; Call ignores them
		}
		if string(m.ID) != string(id) {
			continue // stale response from an earlier abandoned call
		}
		if m.Error != nil {
			return m.Error
		}
		if result != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, result)
		}
		return nil
	}
}

// Notify sends a notification (a request without an ID; no response will
// arrive). params may be nil.
func (c *Client) Notify(method string, params any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	return c.conn.Write(&Message{Method: method, Params: raw})
}
