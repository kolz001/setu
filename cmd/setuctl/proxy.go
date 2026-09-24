package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/kolz001/setu/internal/jsonrpc"
	"github.com/kolz001/setu/internal/mcp"
)

// proxy bridges stdio to the broker socket so any stdio-transport MCP client
// (Claude Code, inspector, etc.) can use setu directly:
//
//	claude mcp add setu -- setuctl proxy --agent my-agent --token $SETU_TOKEN
//
// The bridge is transparent except for one rewrite: it injects the agent
// name/token into the initialize request's _meta.setu, so identity
// configuration lives with the client config, not inside the agent.
func (c *cli) proxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	agent, token := identityFlags(fs)
	parseFlags(fs, args)

	conn, err := net.Dial("unix", c.socket)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w (is setu running?)", c.socket, err)
	}
	defer conn.Close()

	errc := make(chan error, 2)

	// socket → stdout, verbatim
	go func() {
		sc := bufio.NewScanner(conn)
		sc.Buffer(make([]byte, 64*1024), jsonrpc.MaxMessageBytes)
		for sc.Scan() {
			fmt.Println(sc.Text())
		}
		errc <- sc.Err()
	}()

	// stdin → socket, injecting identity into initialize
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64*1024), jsonrpc.MaxMessageBytes)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			out := injectIdentity(line, *agent, *token)
			if _, err := conn.Write(append(out, '\n')); err != nil {
				errc <- err
				return
			}
		}
		errc <- sc.Err()
	}()

	return <-errc
}

// injectIdentity rewrites an initialize request to carry _meta.setu
// credentials; every other message passes through untouched.
func injectIdentity(line []byte, agent, token string) []byte {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return line
	}
	var method string
	if err := json.Unmarshal(msg["method"], &method); err != nil || method != "initialize" {
		return line
	}
	var params map[string]json.RawMessage
	if len(msg["params"]) > 0 {
		if err := json.Unmarshal(msg["params"], &params); err != nil {
			return line
		}
	}
	if params == nil {
		params = map[string]json.RawMessage{}
	}
	metaRaw, _ := json.Marshal(map[string]mcp.SetuMeta{"setu": {Agent: agent, Token: token}})
	params["_meta"] = metaRaw
	newParams, _ := json.Marshal(params)
	msg["params"] = newParams
	out, err := json.Marshal(msg)
	if err != nil {
		return line
	}
	return out
}
