// Package pathutil provides the canonical path resolution both the broker
// (call arguments) and the policy loader (scope prefixes) rely on, so the
// two sides always compare like with like.
package pathutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// Canonical returns an absolute path with '..' collapsed and symlinks in
// every existing ancestor resolved, so a policy prefix check cannot be
// escaped via traversal or a symlink planted inside a granted scope. Path
// components that don't exist yet are kept verbatim (for writes that create
// new files).
//
// A dangling symlink anywhere in p is an error. Its link path would look
// in-scope while any write through it lands wherever the link points, so
// it cannot be given a canonical form that policy could safely match.
func Canonical(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path must be absolute")
	}
	p = filepath.Clean(p)

	remainder := ""
	base := p
	for {
		resolved, err := filepath.EvalSymlinks(base)
		if err == nil {
			return filepath.Clean(filepath.Join(resolved, remainder)), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		// base failed to resolve yet something is there: it is a symlink
		// whose target (or some link along its chain) does not exist.
		if _, lerr := os.Lstat(base); lerr == nil {
			return "", fmt.Errorf("%s is a dangling symlink", base)
		}
		parent := filepath.Dir(base)
		if parent == base { // reached root without finding an existing dir
			return p, nil
		}
		remainder = filepath.Join(filepath.Base(base), remainder)
		base = parent
	}
}
