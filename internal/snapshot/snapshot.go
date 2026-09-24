// Package snapshot implements pre-mutation state capture and rollback — the
// mechanism behind the allow_with_snapshot policy action.
//
// The contract: before a snapshot-gated mutation executes, the prior state
// of every path it will touch is captured; if capture fails, the broker
// refuses the mutation (reversibility is a guarantee, not a best effort).
// Each snapshot's ID lands in the call's audit entry, so
// `setuctl rollback <id>` can restore exactly what one call changed.
//
// v1 captures at file granularity by copying: portable to any filesystem
// and exactly scoped to the paths a call declares. Filesystem-native
// snapshotters (btrfs/ZFS/LVM subvolume snapshots, package-manager
// transaction undo) are roadmap items that slot in behind this same Manager
// API.
//
// On-disk layout, under the daemon's state directory:
//
//	snapshots/<id>/manifest.json   what was captured, per path
//	snapshots/<id>/f0, f1, ...     backup copies of pre-call file contents
//
// Concurrency: Manager methods are safe for concurrent use; a single mutex
// serializes capture and rollback.
package snapshot

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileState records one path's pre-call state within a snapshot manifest.
type FileState struct {
	// Path is the absolute canonical path that was captured.
	Path string `json:"path"`
	// Existed reports whether anything was at Path when the snapshot was
	// taken. False means rollback removes whatever the call created there.
	Existed bool `json:"existed"`
	// Backup is the copy's filename relative to the snapshot directory
	// (empty for directories and non-existent paths).
	Backup string `json:"backup,omitempty"`
	// Mode is the original permission bits, restored on rollback.
	Mode uint32 `json:"mode,omitempty"`
	// IsDir marks paths that were directories (recorded, not deep-copied;
	// see Manager.Take).
	IsDir bool `json:"is_dir,omitempty"`
}

// Manifest describes one snapshot: which call context it belongs to and the
// pre-call state of every path involved.
type Manifest struct {
	// ID is the snapshot's directory name and audit reference.
	ID string `json:"id"`
	// Time is when the snapshot was taken (UTC).
	Time time.Time `json:"time"`
	// Agent and Tool identify the governed call this snapshot protects.
	Agent string `json:"agent"`
	Tool  string `json:"tool"`
	// Files lists the captured per-path states.
	Files []FileState `json:"files"`
	// RolledBack is set once Rollback has restored this snapshot.
	RolledBack bool `json:"rolled_back,omitempty"`
}

// Manager owns the snapshot store rooted at a single directory.
type Manager struct {
	mu  sync.Mutex
	dir string
}

// NewManager creates (mode 0700, parents included) and wraps the snapshot
// directory.
func NewManager(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Manager{dir: dir}, nil
}

// newID mints a snapshot ID: a UTC timestamp prefix for human sortability
// plus random hex for uniqueness. IDs never contain path separators, which
// Get relies on.
func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b)
}

// Take captures the current state of the given paths before a mutation by
// agent/tool and returns the new snapshot's ID.
//
// Per-path behavior: regular files are copied (contents + mode); absent
// paths are recorded as such (rollback will remove whatever gets created);
// directories are recorded but not deep-copied — mutating tools declare the
// specific files they touch, and a directory created by the call rolls back
// by removal.
//
// Take is all-or-nothing: any capture failure removes the partial snapshot
// and returns an error, which the broker converts into refusing the
// mutation.
func (m *Manager) Take(agent, tool string, paths []string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := newID()
	sdir := filepath.Join(m.dir, id)
	if err := os.MkdirAll(sdir, 0o700); err != nil {
		return "", err
	}
	man := Manifest{ID: id, Time: time.Now().UTC(), Agent: agent, Tool: tool}
	for i, p := range paths {
		st, err := os.Lstat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
			man.Files = append(man.Files, FileState{Path: p, Existed: false})
		case err != nil:
			os.RemoveAll(sdir)
			return "", err
		case st.IsDir():
			man.Files = append(man.Files, FileState{Path: p, Existed: true, IsDir: true, Mode: uint32(st.Mode().Perm())})
		default:
			rel := fmt.Sprintf("f%d", i)
			if err := copyFile(p, filepath.Join(sdir, rel), st.Mode().Perm()); err != nil {
				os.RemoveAll(sdir)
				return "", err
			}
			man.Files = append(man.Files, FileState{Path: p, Existed: true, Backup: rel, Mode: uint32(st.Mode().Perm())})
		}
	}
	if err := m.writeManifest(sdir, &man); err != nil {
		os.RemoveAll(sdir)
		return "", err
	}
	return id, nil
}

// writeManifest persists man as sdir/manifest.json (0600).
func (m *Manager) writeManifest(sdir string, man *Manifest) error {
	b, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sdir, "manifest.json"), b, 0o600)
}

// Get loads the manifest for snapshot id. IDs are validated against path
// traversal (an id is always a bare directory name) — operator input from
// `setuctl rollback` flows here.
func (m *Manager) Get(id string) (*Manifest, error) {
	if filepath.Base(id) != id {
		return nil, fmt.Errorf("invalid snapshot id %q", id)
	}
	b, err := os.ReadFile(filepath.Join(m.dir, id, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var man Manifest
	if err := json.Unmarshal(b, &man); err != nil {
		return nil, err
	}
	return &man, nil
}

// List returns all snapshot manifests, oldest first (IDs sort
// chronologically by construction). Damaged snapshot directories are
// skipped rather than failing the listing — an operator hunting for a
// rollback point should see everything that is still usable.
func (m *Manager) List() ([]*Manifest, error) {
	ents, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, err
	}
	var out []*Manifest
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		man, err := m.Get(e.Name())
		if err != nil {
			continue
		}
		out = append(out, man)
	}
	return out, nil
}

// Rollback restores every path in snapshot id to its pre-call state:
// files that existed are restored from backup (contents and mode); paths
// that did not exist are removed along with anything created beneath them;
// directories that pre-existed are left in place (their captured files are
// restored individually).
//
// Rollback attempts every path even after failures and returns the joined
// errors, so one unrestorable path doesn't strand the rest. On full success
// the manifest is re-written with RolledBack set. Rollback is idempotent —
// re-running it re-applies the same restorations.
func (m *Manager) Rollback(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	man, err := m.Get(id)
	if err != nil {
		return err
	}
	sdir := filepath.Join(m.dir, id)
	var errs []error
	for _, f := range man.Files {
		switch {
		case f.Existed && f.Backup != "":
			if err := copyFile(filepath.Join(sdir, f.Backup), f.Path, os.FileMode(f.Mode)); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", f.Path, err))
			}
		case f.Existed && f.IsDir:
			// Directory pre-existed; nothing to restore at this level.
		default:
			// Path did not exist before the call: remove whatever was created.
			// RemoveAll is safe here precisely because Existed is false — it
			// can only delete state the governed call itself produced.
			if err := os.RemoveAll(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("%s: %w", f.Path, err))
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	man.RolledBack = true
	return m.writeManifest(sdir, man)
}

// copyFile copies src to dst with the given mode, creating dst's parents as
// needed and truncating any existing dst. The explicit Chmod covers
// pre-existing destinations, whose mode OpenFile would leave untouched.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Chmod(mode); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
