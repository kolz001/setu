package broker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kolz001/setu/internal/servers"
)

func pathTool() *servers.Tool {
	return &servers.Tool{
		Name:     "fs.read",
		ArgKinds: map[string]servers.ArgKind{"path": servers.ArgPath},
	}
}

func TestCanonicalizeRejectsRelative(t *testing.T) {
	_, err := canonicalize(pathTool(), map[string]any{"path": "etc/passwd"})
	if err == nil {
		t.Fatal("relative path must be rejected")
	}
}

func TestCanonicalizeCollapsesTraversal(t *testing.T) {
	dir := t.TempDir()
	args := map[string]any{"path": dir + "/sub/../../" + filepath.Base(dir) + "/file.txt"}
	got, err := canonicalize(pathTool(), args)
	if err != nil {
		t.Fatal(err)
	}
	resolvedDir, _ := filepath.EvalSymlinks(dir) // TempDir may itself contain symlinks (macOS /var → /private/var)
	want := filepath.Join(resolvedDir, "file.txt")
	if got.Path != want {
		t.Fatalf("traversal not collapsed: got %q want %q", got.Path, want)
	}
	if args["path"] != want {
		t.Fatal("canonical path must be written back so the handler uses it")
	}
}

func TestCanonicalizeResolvesSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	inside := filepath.Join(dir, "inside")
	os.MkdirAll(outside, 0o755)
	os.MkdirAll(inside, 0o755)
	// A symlink planted inside the granted scope pointing outside it.
	link := filepath.Join(inside, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	got, err := canonicalize(pathTool(), map[string]any{"path": link + "/secret.txt"})
	if err != nil {
		t.Fatal(err)
	}
	resolvedOutside, _ := filepath.EvalSymlinks(outside)
	if got.Path != filepath.Join(resolvedOutside, "secret.txt") {
		t.Fatalf("symlink must resolve to real target for policy matching, got %q", got.Path)
	}
}

func TestCanonicalizeUnitAndPackage(t *testing.T) {
	unitTool := &servers.Tool{Name: "systemd.restart", ArgKinds: map[string]servers.ArgKind{"unit": servers.ArgUnit}}
	if _, err := canonicalize(unitTool, map[string]any{"unit": "nginx.service"}); err != nil {
		t.Fatalf("valid unit rejected: %v", err)
	}
	if _, err := canonicalize(unitTool, map[string]any{"unit": "nginx.service; rm -rf /"}); err == nil {
		t.Fatal("shell metacharacters in unit must be rejected")
	}
	pkgTool := &servers.Tool{Name: "pkg.install", ArgKinds: map[string]servers.ArgKind{"package": servers.ArgPackage}}
	if _, err := canonicalize(pkgTool, map[string]any{"package": "-y --allow-downgrades"}); err == nil {
		t.Fatal("flag-like package name must be rejected")
	}
}
