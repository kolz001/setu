package servers

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
)

// NetBackend answers the read-only network queries that need platform
// tooling: Routes returns the routing table, Sockets the listening sockets.
// v1 has no mutating network tools by design (see the architecture doc's
// v1 server set).
type NetBackend interface {
	Routes(ctx context.Context) (string, error)
	Sockets(ctx context.Context) (string, error)
}

// NetTools returns the net server's tools (all read-only, low risk).
// Interfaces come from the standard library (portable); routes and sockets
// from the platform backend.
func NetTools(b NetBackend) []*Tool {
	return []*Tool{
		{
			Name:        "net.interfaces",
			Description: "List network interfaces and their addresses. Read-only.",
			InputSchema: schema(nil, map[string]any{}),
			Handler: func(_ context.Context, _ map[string]any) (string, error) {
				ifs, err := net.Interfaces()
				if err != nil {
					return "", err
				}
				var sb strings.Builder
				for _, ifc := range ifs {
					addrs, _ := ifc.Addrs()
					var as []string
					for _, a := range addrs {
						as = append(as, a.String())
					}
					fmt.Fprintf(&sb, "%-12s %-6s mtu=%d %s\n", ifc.Name, ifc.Flags, ifc.MTU, strings.Join(as, " "))
				}
				return sb.String(), nil
			},
		},
		{
			Name:        "net.routes",
			Description: "Show the routing table. Read-only.",
			InputSchema: schema(nil, map[string]any{}),
			Handler: func(ctx context.Context, _ map[string]any) (string, error) {
				return b.Routes(ctx)
			},
		},
		{
			Name:        "net.sockets",
			Description: "List listening sockets. Read-only.",
			InputSchema: schema(nil, map[string]any{}),
			Handler: func(ctx context.Context, _ map[string]any) (string, error) {
				return b.Sockets(ctx)
			},
		},
	}
}

// ExecNetBackend implements NetBackend with platform tools: ip/ss on Linux
// when available, netstat as the portable fallback (macOS, minimal
// containers).
type ExecNetBackend struct{}

// Routes returns the routing table.
func (ExecNetBackend) Routes(ctx context.Context) (string, error) {
	if runtime.GOOS == "linux" && haveBinary("ip") {
		return runCmd(ctx, "ip", "route", "show")
	}
	return runCmd(ctx, "netstat", "-rn")
}

// Sockets returns listening sockets (TCP listeners via ss on Linux; all
// sockets via netstat elsewhere).
func (ExecNetBackend) Sockets(ctx context.Context) (string, error) {
	if runtime.GOOS == "linux" && haveBinary("ss") {
		return runCmd(ctx, "ss", "-tlnp")
	}
	return runCmd(ctx, "netstat", "-an")
}

// MockNet implements NetBackend with canned answers for tests and fully
// mock daemon runs.
type MockNet struct{}

// Routes returns a fixed sample routing table.
func (MockNet) Routes(context.Context) (string, error) {
	return "default via 192.168.1.1 dev eth0\n192.168.1.0/24 dev eth0 scope link\n", nil
}

// Sockets returns a fixed sample listener list.
func (MockNet) Sockets(context.Context) (string, error) {
	return "LISTEN 0 128 0.0.0.0:22\nLISTEN 0 511 0.0.0.0:80\n", nil
}
