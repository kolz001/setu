// Command setuctl is the operator CLI for setu. It has two halves:
//
//   - Admin commands (status, sessions, agent, approvals, approve/deny,
//     freeze/unfreeze, audit, snapshots, rollback, policy reload) speak
//     JSON-RPC to the owner-only control socket.
//   - Agent-side commands (tools, call, proxy) act as an MCP client on the
//     agent-facing socket — tools/call for testing policies from the
//     terminal, proxy as a stdio bridge so standard MCP clients (Claude
//     Code, the MCP inspector) can connect to the broker as if it were a
//     stdio server.
//
// Run `setuctl help` for the full command reference; the socket defaults
// mirror cmd/setu's so both binaries meet without flags.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kolz001/setu/internal/audit"
	"github.com/kolz001/setu/internal/jsonrpc"
	"github.com/kolz001/setu/internal/mcp"
)

// defaultRunDir mirrors cmd/setu's socket-directory logic (root → /run/setu,
// user session → $XDG_RUNTIME_DIR/setu, else per-uid temp dir) so setuctl
// finds the daemon without flags.
func defaultRunDir() string {
	if os.Geteuid() == 0 {
		return "/run/setu"
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return x + "/setu"
	}
	return os.TempDir() + "/setu-" + fmt.Sprint(os.Getuid())
}

var usage = `setuctl — operator CLI for the setu broker

Admin (control socket):
  status                            broker status, sessions, pending approvals
  sessions                          list live agent sessions
  agent register <name> [--uid N]   register an agent; prints its token once
  agent list                        list registered agents
  agent revoke <name>               revoke a registered agent
  approvals                         list pending approvals and active grants
  approve <id> [--ttl 30m]          approve a pending ask (TTL adds a grant)
  deny <id>                         deny a pending ask
  freeze <agent>                    kill-switch: deny all calls from an agent
  unfreeze <agent>                  lift a freeze
  audit query [--agent G] [--tool G] [--decision D] [--last N]
  audit verify                      verify the audit log hash chain
  snapshots                         list snapshots
  rollback <snapshot-id>            restore pre-call state
  policy reload                     re-read the policy file into the running broker

Agent-side (MCP socket):
  tools  [--agent N] [--token T]            list tools visible to an identity
  call   <tool> [json-args] [--agent] [--token]   invoke one tool
  proxy  [--agent N] [--token T]            stdio<->socket MCP bridge

Global flags: --socket PATH --control PATH (defaults under ` + defaultRunDir() + `)
Token can also come from $SETU_TOKEN.`

// cli carries the resolved socket paths every subcommand needs.
type cli struct {
	socket  string // agent-facing MCP socket
	control string // admin control socket
}

func main() {
	rd := defaultRunDir()
	fs := flag.NewFlagSet("setuctl", flag.ExitOnError)
	socket := fs.String("socket", rd+"/setu.sock", "MCP socket path")
	control := fs.String("control", rd+"/control.sock", "control socket path")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	fs.Parse(os.Args[1:])
	args := fs.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	c := &cli{socket: *socket, control: *control}
	if err := c.run(args); err != nil {
		fmt.Fprintln(os.Stderr, "setuctl:", err)
		os.Exit(1)
	}
}

// run dispatches the subcommand named by args[0]. Trivial commands are
// handled inline; anything with its own flags or structure gets a method.
func (c *cli) run(args []string) error {
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "status":
		return c.adminJSON("status", nil)
	case "sessions":
		return c.adminJSON("sessions.list", nil)
	case "agent":
		return c.agent(rest)
	case "approvals":
		return c.adminJSON("approvals.list", nil)
	case "approve", "deny":
		return c.resolve(cmd == "approve", rest)
	case "freeze", "unfreeze":
		if len(rest) != 1 {
			return fmt.Errorf("usage: setuctl %s <agent>", cmd)
		}
		return c.adminJSON(cmd, map[string]string{"name": rest[0]})
	case "audit":
		return c.audit(rest)
	case "snapshots":
		return c.adminJSON("snapshots.list", nil)
	case "rollback":
		if len(rest) != 1 {
			return fmt.Errorf("usage: setuctl rollback <snapshot-id>")
		}
		return c.adminJSON("rollback", map[string]string{"id": rest[0]})
	case "policy":
		if len(rest) != 1 || rest[0] != "reload" {
			return fmt.Errorf("usage: setuctl policy reload")
		}
		return c.adminJSON("policy.reload", nil)
	case "tools":
		return c.tools(rest)
	case "call":
		return c.call(rest)
	case "proxy":
		return c.proxy(rest)
	case "help", "-h", "--help":
		fmt.Println(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q (see setuctl help)", cmd)
	}
}

// --- control-plane client ---

// admin performs one JSON-RPC call against the control socket, dialing a
// fresh connection per call (admin commands are one-shot; connection reuse
// isn't worth the state).
func (c *cli) admin(method string, params any, result any) error {
	conn, err := net.Dial("unix", c.control)
	if err != nil {
		return fmt.Errorf("connecting to control socket %s: %w (is setu running?)", c.control, err)
	}
	defer conn.Close()
	return jsonrpc.NewClient(conn).Call(method, params, result)
}

// adminJSON runs an admin call and pretty-prints the raw result — the
// default rendering for admin commands, whose output is consumed by humans
// and scripts alike (the JSON shape is the control API's, unmodified).
func (c *cli) adminJSON(method string, params any) error {
	var result json.RawMessage
	if err := c.admin(method, params, &result); err != nil {
		return err
	}
	return printJSON(result)
}

// printJSON writes v to stdout as indented JSON.
func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// agent handles `setuctl agent register|list|revoke`. Register prints the
// new token to stdout — the only time it is ever available in plaintext.
func (c *cli) agent(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: setuctl agent register|list|revoke")
	}
	switch args[0] {
	case "register":
		fs := flag.NewFlagSet("agent register", flag.ExitOnError)
		uid := fs.Int("uid", -1, "pin the token to a uid")
		parseFlags(fs, args[1:])
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: setuctl agent register <name> [--uid N]")
		}
		params := map[string]any{"name": fs.Arg(0)}
		if *uid >= 0 {
			params["uid"] = *uid
		}
		var res struct{ Name, Token string }
		if err := c.admin("agents.register", params, &res); err != nil {
			return err
		}
		fmt.Printf("agent %q registered.\ntoken (shown once, store it now):\n  %s\n", res.Name, res.Token)
		return nil
	case "list":
		return c.adminJSON("agents.list", nil)
	case "revoke":
		if len(args) != 2 {
			return fmt.Errorf("usage: setuctl agent revoke <name>")
		}
		return c.adminJSON("agents.revoke", map[string]string{"name": args[1]})
	default:
		return fmt.Errorf("unknown agent subcommand %q", args[0])
	}
}

// resolve handles `setuctl approve|deny <id>`; --ttl on approve also
// creates a standing grant for the same (agent, tool).
func (c *cli) resolve(approve bool, args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	ttl := fs.Duration("ttl", 0, "also grant this (agent, tool) for a duration, e.g. 30m")
	parseFlags(fs, args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: setuctl approve|deny <approval-id> [--ttl 30m]")
	}
	return c.adminJSON("approvals.resolve", map[string]any{
		"id": fs.Arg(0), "approve": approve, "ttl_seconds": int(ttl.Seconds()),
	})
}

// audit handles `setuctl audit query|verify`, translating query flags into
// an audit.QueryFilter for the control API.
func (c *cli) audit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: setuctl audit query|verify")
	}
	switch args[0] {
	case "verify":
		return c.adminJSON("audit.verify", nil)
	case "query":
		fs := flag.NewFlagSet("audit query", flag.ExitOnError)
		agent := fs.String("agent", "", "agent name glob")
		tool := fs.String("tool", "", "tool name glob")
		decision := fs.String("decision", "", "allow|deny|ask|allow_with_snapshot|allow_after_ask")
		last := fs.Int("last", 50, "only the last N matches")
		since := fs.String("since", "", "RFC3339 timestamp")
		parseFlags(fs, args[1:])
		f := audit.QueryFilter{Agent: *agent, Tool: *tool, Decision: *decision, Last: *last}
		if *since != "" {
			t, err := time.Parse(time.RFC3339, *since)
			if err != nil {
				return fmt.Errorf("--since: %w", err)
			}
			f.Since = t
		}
		return c.adminJSON("audit.query", f)
	default:
		return fmt.Errorf("unknown audit subcommand %q", args[0])
	}
}

// --- MCP client (agent-side) ---

// parseFlags parses like fs.Parse but accepts flags after positional
// arguments too (Go's flag package stops at the first positional).
func parseFlags(fs *flag.FlagSet, args []string) error {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			// "--flag value" (all flags on these subcommands take values):
			// pull the value along unless it was given as --flag=value.
			if !strings.Contains(name, "=") && fs.Lookup(name) != nil && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	return fs.Parse(append(flags, positional...))
}

// identityFlags registers the --agent/--token flags shared by the
// agent-side commands (tools, call, proxy). The token defaults from
// $SETU_TOKEN so it stays out of shell history and process listings.
func identityFlags(fs *flag.FlagSet) (agent, token *string) {
	agent = fs.String("agent", "setuctl", "agent name to declare")
	token = fs.String("token", os.Getenv("SETU_TOKEN"), "registered agent token ($SETU_TOKEN)")
	return
}

// mcpConnect dials the MCP socket and completes the initialize handshake
// under the given identity, returning a ready client and its close func.
// An identity rejection (bad token, registered name without token) surfaces
// here as the initialize error.
func (c *cli) mcpConnect(agent, token string) (*jsonrpc.Client, func(), error) {
	conn, err := net.Dial("unix", c.socket)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to %s: %w (is setu running?)", c.socket, err)
	}
	cl := jsonrpc.NewClient(conn)
	params := map[string]any{
		"protocolVersion": mcp.ProtocolVersion,
		"clientInfo":      map[string]string{"name": agent, "version": "0.1"},
		"capabilities":    map[string]any{},
		"_meta":           map[string]any{"setu": map[string]string{"agent": agent, "token": token}},
	}
	var res mcp.InitializeResult
	if err := cl.Call("initialize", params, &res); err != nil {
		conn.Close()
		return nil, nil, err
	}
	cl.Notify("notifications/initialized", map[string]any{})
	return cl, func() { conn.Close() }, nil
}

// tools lists the tools visible to an identity — the fastest way to answer
// "what does the policy actually grant this agent?".
func (c *cli) tools(args []string) error {
	fs := flag.NewFlagSet("tools", flag.ExitOnError)
	agent, token := identityFlags(fs)
	parseFlags(fs, args)
	cl, closeFn, err := c.mcpConnect(*agent, *token)
	if err != nil {
		return err
	}
	defer closeFn()
	var res mcp.ListToolsResult
	if err := cl.Call("tools/list", map[string]any{}, &res); err != nil {
		return err
	}
	if len(res.Tools) == 0 {
		fmt.Println("(no tools visible to this identity — check policy)")
		return nil
	}
	for _, t := range res.Tools {
		fmt.Printf("%-22s %s\n", t.Name, t.Description)
	}
	return nil
}

// call invokes one tool as the given identity and prints the text result.
// Tool-level failures (policy denials, handler errors) print their message
// and exit nonzero, so shell scripts can branch on the outcome.
func (c *cli) call(args []string) error {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	agent, token := identityFlags(fs)
	parseFlags(fs, args)
	if fs.NArg() < 1 {
		return fmt.Errorf(`usage: setuctl call <tool> ['{"arg":"value"}'] [--agent N] [--token T]`)
	}
	toolName := fs.Arg(0)
	toolArgs := map[string]any{}
	if fs.NArg() > 1 {
		if err := json.Unmarshal([]byte(fs.Arg(1)), &toolArgs); err != nil {
			return fmt.Errorf("arguments must be a JSON object: %w", err)
		}
	}
	cl, closeFn, err := c.mcpConnect(*agent, *token)
	if err != nil {
		return err
	}
	defer closeFn()
	var res mcp.CallToolResult
	err = cl.Call("tools/call", mcp.CallToolParams{Name: toolName, Arguments: toolArgs}, &res)
	if err != nil {
		return err
	}
	for _, content := range res.Content {
		fmt.Println(content.Text)
	}
	if res.IsError {
		os.Exit(1)
	}
	return nil
}
