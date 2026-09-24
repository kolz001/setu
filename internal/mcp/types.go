// Package mcp defines the subset of Model Context Protocol (MCP) types the
// broker implements: the initialize handshake, tools/list, tools/call, and
// ping. setu deliberately hand-rolls these rather than depending on an SDK —
// the broker needs full control over per-session tool filtering, and the
// wire surface is small enough that the types below are the entire contract.
//
// Wire format: JSON-RPC 2.0, newline-delimited (see package jsonrpc). Field
// names follow the MCP specification revision named by ProtocolVersion.
package mcp

import "encoding/json"

// ProtocolVersion is the MCP specification revision the broker speaks. It is
// echoed to clients in InitializeResult regardless of the version the client
// requests; clients newer than this are expected to downgrade gracefully per
// the MCP version-negotiation rules.
const ProtocolVersion = "2025-06-18"

// Implementation identifies one side of an MCP connection (client or
// server), as exchanged during initialize.
type Implementation struct {
	// Name is the implementation name. For clients connecting to setu this
	// doubles as the default declared agent name when _meta.setu.agent is
	// absent (see InitializeParams.Meta).
	Name string `json:"name"`
	// Version is the implementation's own version string; informational.
	Version string `json:"version"`
}

// SetuMeta is setu-specific session metadata carried inside the initialize
// request's params._meta.setu object. It is the only setu extension to
// standard MCP, and it is optional: a bare MCP client that sends none of it
// still connects, with identity falling back to clientInfo.name
// (unauthenticated) plus kernel peer credentials.
type SetuMeta struct {
	// Agent is the self-declared agent name. It is advisory unless paired
	// with Token; see identity.Registry.Resolve for the binding rules.
	Agent string `json:"agent,omitempty"`
	// Token is a registered-agent token issued by `setuctl agent register`.
	// A valid token makes the session's identity the token's registered
	// name, authenticated. An invalid token rejects the connection.
	Token string `json:"token,omitempty"`
	// Task is an optional task manifest: a free-form statement of what the
	// agent intends to do this session ("remediate lint errors in repo X").
	// v1 records it in every audit entry; v2 will enforce against it
	// (intent-scoped capabilities).
	Task string `json:"task,omitempty"`
}

// InitializeParams are the parameters of the client's initialize request,
// the mandatory first request on every connection.
type InitializeParams struct {
	// ProtocolVersion is the MCP revision the client wants.
	ProtocolVersion string `json:"protocolVersion"`
	// Capabilities is the client capability object. setu currently requires
	// no client capabilities, so it is retained raw and unexamined.
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
	// ClientInfo names the connecting implementation.
	ClientInfo Implementation `json:"clientInfo"`
	// Meta carries the setu identity extension, if any (params._meta.setu).
	Meta struct {
		Setu SetuMeta `json:"setu"`
	} `json:"_meta,omitempty"`
}

// ServerCapabilities advertises what this server supports. setu only
// implements tools (no resources, prompts, or sampling).
type ServerCapabilities struct {
	// Tools signals tool support. ListChanged is false: the tool set visible
	// to a session is fixed at connect time by policy snapshot semantics.
	Tools struct {
		ListChanged bool `json:"listChanged"`
	} `json:"tools"`
}

// InitializeResult is the server's reply to initialize.
type InitializeResult struct {
	// ProtocolVersion is the revision the server will speak (ProtocolVersion
	// constant).
	ProtocolVersion string `json:"protocolVersion"`
	// Capabilities advertises the server's feature set.
	Capabilities ServerCapabilities `json:"capabilities"`
	// ServerInfo identifies the broker ("setu" + version).
	ServerInfo Implementation `json:"serverInfo"`
	// Instructions is human/model-readable guidance injected into the
	// agent's context by conforming clients; setu uses it to state the
	// governance rules (deny-by-default, auditing, possible approval waits).
	Instructions string `json:"instructions,omitempty"`
}

// Tool is one entry in a tools/list result. InputSchema is a JSON Schema
// object describing the tool's arguments.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ListToolsResult is the reply to tools/list. For setu the list is already
// policy-filtered per session identity: tools the agent could never call are
// simply absent (least-privilege discovery).
type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

// CallToolParams are the parameters of a tools/call request.
type CallToolParams struct {
	// Name is the tool to invoke, e.g. "fs.write".
	Name string `json:"name"`
	// Arguments are the tool's arguments per its InputSchema. May be nil.
	Arguments map[string]any `json:"arguments,omitempty"`
}

// Content is one item of tool-result content. setu only produces text
// content in v1.
type Content struct {
	// Type is the content discriminator; always "text" from this broker.
	Type string `json:"type"`
	// Text is the payload when Type == "text".
	Text string `json:"text,omitempty"`
}

// CallToolResult is the reply to tools/call.
//
// Note the two error channels MCP defines: a JSON-RPC error means the
// request itself failed (malformed, unknown method), while IsError on an
// otherwise-successful response means the tool ran (or was refused by
// policy) and failed — the message in Content explains why. Policy denials
// use the second channel so agents can read and adapt to them.
type CallToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// TextResult wraps plain text as a successful CallToolResult.
func TextResult(text string) *CallToolResult {
	return &CallToolResult{Content: []Content{{Type: "text", Text: text}}}
}

// ErrorResult wraps plain text as a failed CallToolResult (tool-level error;
// the JSON-RPC exchange itself still succeeds).
func ErrorResult(text string) *CallToolResult {
	return &CallToolResult{Content: []Content{{Type: "text", Text: text}}, IsError: true}
}
