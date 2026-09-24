package servers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// scopeKey is the context key under which the broker passes the policy
// scope that authorized a call.
type scopeKey struct{}

// WithScope returns ctx carrying scope, the canonical path prefix the
// matching policy rule granted for this call ("" when the rule has no path
// scope). The broker sets it before invoking a handler.
func WithScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, scopeKey{}, scope)
}

// inScope opens the call's authorized scope as an os.Root and returns p
// relative to it. Every fs operation goes through that Root, which refuses
// to follow any symlink or ".." out of the scope. The broker already
// canonicalized p and checked it against the scope; the Root makes that
// check hold at the moment of access, closing the window in which a path
// component could be swapped for a symlink between policy and execution.
// A rule without a path scope confines to "/", i.e. not at all.
func inScope(ctx context.Context, p string) (*os.Root, string, error) {
	scope, _ := ctx.Value(scopeKey{}).(string)
	if scope == "" {
		scope = "/"
	}
	if !filepath.IsAbs(p) {
		return nil, "", fmt.Errorf("path must be absolute")
	}
	rel, err := filepath.Rel(scope, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, "", fmt.Errorf("%s is outside the authorized scope %s", p, scope)
	}
	root, err := os.OpenRoot(scope)
	if err != nil {
		return nil, "", err
	}
	return root, rel, nil
}

// FSTools returns the fs server's tools: scoped read/list/write/mkdir.
//
// Unlike the other servers, fs has no backend interface — the standard
// library is the real backend on every OS, so there is nothing to mock.
//
// Security note: every path reaching these handlers has been canonicalized
// by the broker (absolute, '..' collapsed, symlinks resolved) and passed
// the matching rule's scope.path_prefix constraint. The handlers then do
// every operation through an os.Root anchored at that scope (see inScope),
// so the check cannot be raced: a symlink planted after evaluation still
// cannot lead outside the scope. The write tools declare SnapshotArgs, so
// under allow_with_snapshot their target's prior state is captured before
// they run.
func FSTools() []*Tool {
	pathProp := map[string]any{"type": "string", "description": "absolute path"}
	return []*Tool{
		{
			Name:        "fs.read",
			Description: "Read a file within the policy-granted path scope. Read-only.",
			InputSchema: schema([]string{"path"}, map[string]any{
				"path":      pathProp,
				"max_bytes": map[string]any{"type": "integer", "description": "cap on returned bytes (default 256KiB)"},
			}),
			ArgKinds: map[string]ArgKind{"path": ArgPath},
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				max := intArg(args, "max_bytes", 256*1024)
				if max <= 0 || max > 4*1024*1024 {
					max = 256 * 1024
				}
				root, rel, err := inScope(ctx, strArg(args, "path"))
				if err != nil {
					return "", err
				}
				defer root.Close()
				b, err := root.ReadFile(rel)
				if err != nil {
					return "", err
				}
				if len(b) > max {
					return string(b[:max]) + "\n…(truncated)", nil
				}
				return string(b), nil
			},
		},
		{
			Name:        "fs.list",
			Description: "List a directory within the policy-granted path scope. Read-only.",
			InputSchema: schema([]string{"path"}, map[string]any{"path": pathProp}),
			ArgKinds:    map[string]ArgKind{"path": ArgPath},
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				root, rel, err := inScope(ctx, strArg(args, "path"))
				if err != nil {
					return "", err
				}
				defer root.Close()
				dir, err := root.Open(rel)
				if err != nil {
					return "", err
				}
				defer dir.Close()
				ents, err := dir.ReadDir(-1)
				if err != nil {
					return "", err
				}
				sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
				var b strings.Builder
				for _, e := range ents {
					kind := "f"
					if e.IsDir() {
						kind = "d"
					}
					fmt.Fprintf(&b, "%s %s\n", kind, e.Name())
				}
				if b.Len() == 0 {
					return "(empty)", nil
				}
				return b.String(), nil
			},
		},
		{
			Name:        "fs.write",
			Description: "Write (create or replace) a file within the policy-granted path scope. Mutating; snapshot-eligible.",
			InputSchema: schema([]string{"path", "content"}, map[string]any{
				"path":    pathProp,
				"content": map[string]any{"type": "string"},
			}),
			ArgKinds:     map[string]ArgKind{"path": ArgPath},
			Mutating:     true,
			SnapshotArgs: []string{"path"},
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				p := strArg(args, "path")
				content, ok := args["content"].(string)
				if !ok {
					return "", fmt.Errorf("content must be a string")
				}
				root, rel, err := inScope(ctx, p)
				if err != nil {
					return "", err
				}
				defer root.Close()
				if err := root.WriteFile(rel, []byte(content), 0o644); err != nil {
					return "", err
				}
				return fmt.Sprintf("wrote %d bytes to %s", len(content), p), nil
			},
		},
		{
			Name:         "fs.mkdir",
			Description:  "Create a directory (with parents) within the policy-granted path scope. Mutating; snapshot-eligible.",
			InputSchema:  schema([]string{"path"}, map[string]any{"path": pathProp}),
			ArgKinds:     map[string]ArgKind{"path": ArgPath},
			Mutating:     true,
			SnapshotArgs: []string{"path"},
			Handler: func(ctx context.Context, args map[string]any) (string, error) {
				p := strArg(args, "path")
				root, rel, err := inScope(ctx, p)
				if err != nil {
					return "", err
				}
				defer root.Close()
				if err := root.MkdirAll(rel, 0o755); err != nil {
					return "", err
				}
				return "created " + p, nil
			},
		},
	}
}
