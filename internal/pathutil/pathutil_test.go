package pathutil

import (
	"os"
	"path/filepath"
	"testing"
)

func tempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir()) // macOS /var → /private/var
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCanonicalKeepsNonexistentTail(t *testing.T) {
	d := tempDir(t)
	got, err := Canonical(filepath.Join(d, "new", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(d, "new", "file.txt"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCanonicalResolvesLiveSymlink(t *testing.T) {
	d := tempDir(t)
	os.MkdirAll(filepath.Join(d, "real"), 0o755)
	if err := os.Symlink(filepath.Join(d, "real"), filepath.Join(d, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	got, err := Canonical(filepath.Join(d, "link", "f"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(d, "real", "f"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCanonicalRejectsDanglingSymlink(t *testing.T) {
	d := tempDir(t)
	link := filepath.Join(d, "link")
	if err := os.Symlink(filepath.Join(d, "elsewhere", "target"), link); err != nil {
		t.Skip("symlinks unavailable")
	}
	for _, p := range []string{link, filepath.Join(link, "child")} {
		if got, err := Canonical(p); err == nil {
			t.Errorf("Canonical(%q) = %q; dangling symlink must be rejected", p, got)
		}
	}
}
