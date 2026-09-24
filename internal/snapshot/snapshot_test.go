package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackRestoresModifiedFile(t *testing.T) {
	work := t.TempDir()
	target := filepath.Join(work, "config.txt")
	os.WriteFile(target, []byte("original"), 0o600)

	m, err := NewManager(filepath.Join(work, "snaps"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.Take("tester", "fs.write", []string{target})
	if err != nil {
		t.Fatal(err)
	}

	os.WriteFile(target, []byte("mutated"), 0o644)

	if err := m.Rollback(id); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	if string(b) != "original" {
		t.Fatalf("expected restore to 'original', got %q", b)
	}
	fi, _ := os.Stat(target)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode restore to 0600, got %v", fi.Mode().Perm())
	}
	man, _ := m.Get(id)
	if !man.RolledBack {
		t.Fatal("manifest should record the rollback")
	}
}

func TestRollbackRemovesCreatedFile(t *testing.T) {
	work := t.TempDir()
	target := filepath.Join(work, "new-file.txt")

	m, _ := NewManager(filepath.Join(work, "snaps"))
	id, err := m.Take("tester", "fs.write", []string{target})
	if err != nil {
		t.Fatal(err)
	}

	os.WriteFile(target, []byte("created by agent"), 0o644)

	if err := m.Rollback(id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("file created after snapshot must be removed on rollback")
	}
}

func TestListAndGet(t *testing.T) {
	work := t.TempDir()
	f := filepath.Join(work, "f")
	os.WriteFile(f, []byte("x"), 0o644)
	m, _ := NewManager(filepath.Join(work, "snaps"))
	id, _ := m.Take("a", "fs.write", []string{f})

	list, err := m.List()
	if err != nil || len(list) != 1 || list[0].ID != id {
		t.Fatalf("list: %v err %v", list, err)
	}
	if _, err := m.Get("../escape"); err == nil {
		t.Fatal("path-traversal snapshot id must be rejected")
	}
}
