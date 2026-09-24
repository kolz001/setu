package servers

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func fsTool(t *testing.T, name string) *Tool {
	t.Helper()
	for _, tool := range FSTools() {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("no tool %s", name)
	return nil
}

// scopeDirs returns a canonical scope directory and a sibling outside it.
func scopeDirs(t *testing.T) (scope, outside string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scope, outside = filepath.Join(base, "scope"), filepath.Join(base, "outside")
	os.MkdirAll(scope, 0o755)
	os.MkdirAll(outside, 0o755)
	return scope, outside
}

func TestFSWriteWithinScope(t *testing.T) {
	scope, _ := scopeDirs(t)
	ctx := WithScope(context.Background(), scope)
	p := filepath.Join(scope, "a.txt")
	if _, err := fsTool(t, "fs.write").Handler(ctx, map[string]any{"path": p, "content": "hi"}); err != nil {
		t.Fatal(err)
	}
	got, err := fsTool(t, "fs.read").Handler(ctx, map[string]any{"path": p})
	if err != nil || got != "hi" {
		t.Fatalf("read back %q, %v", got, err)
	}
	if _, err := fsTool(t, "fs.mkdir").Handler(ctx, map[string]any{"path": filepath.Join(scope, "d", "e")}); err != nil {
		t.Fatal(err)
	}
	if out, err := fsTool(t, "fs.list").Handler(ctx, map[string]any{"path": scope}); err != nil || out != "f a.txt\nd d\n" {
		t.Fatalf("list = %q, %v", out, err)
	}
}

// Simulates losing the check-then-use race: the broker approved a path
// inside the scope, then a component was replaced by a symlink pointing
// outside before the handler ran. The handler must refuse.
func TestFSHandlersRefuseSymlinkSwappedAfterCheck(t *testing.T) {
	scope, outside := scopeDirs(t)
	if err := os.Symlink(outside, filepath.Join(scope, "sub")); err != nil {
		t.Skip("symlinks unavailable")
	}
	ctx := WithScope(context.Background(), scope)
	p := filepath.Join(scope, "sub", "pwned")

	if _, err := fsTool(t, "fs.write").Handler(ctx, map[string]any{"path": p, "content": "x"}); err == nil {
		t.Error("fs.write followed a symlink out of the scope")
	}
	if _, err := fsTool(t, "fs.mkdir").Handler(ctx, map[string]any{"path": p}); err == nil {
		t.Error("fs.mkdir followed a symlink out of the scope")
	}
	os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o600)
	if _, err := fsTool(t, "fs.read").Handler(ctx, map[string]any{"path": filepath.Join(scope, "sub", "secret")}); err == nil {
		t.Error("fs.read followed a symlink out of the scope")
	}
	if _, err := fsTool(t, "fs.list").Handler(ctx, map[string]any{"path": filepath.Join(scope, "sub")}); err == nil {
		t.Error("fs.list followed a symlink out of the scope")
	}
	if _, err := os.Lstat(filepath.Join(outside, "pwned")); !os.IsNotExist(err) {
		t.Fatal("nothing may be created outside the scope")
	}
}

func TestFSHandlersRejectPathOutsideScope(t *testing.T) {
	scope, outside := scopeDirs(t)
	ctx := WithScope(context.Background(), scope)
	for _, p := range []string{filepath.Join(outside, "x"), "", "relative/x"} {
		if _, err := fsTool(t, "fs.write").Handler(ctx, map[string]any{"path": p, "content": "x"}); err == nil {
			t.Errorf("fs.write(%q) must fail outside scope %s", p, scope)
		}
	}
}
