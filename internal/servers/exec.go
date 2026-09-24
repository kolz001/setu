package servers

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// runCmd executes a system binary with a hard 30-second timeout (bounded
// further by ctx) and caps captured output at 512 KiB.
//
// Security invariant: arguments are passed as an argv vector — never
// through a shell — so canonicalized values cannot be reinterpreted as
// metacharacters, additional arguments, or redirections. Every exec in this
// package goes through here.
//
// On failure the error carries the binary name and trimmed stderr (or the
// exec error when stderr is empty); any partial stdout is still returned
// for callers that can salvage it (see SystemctlBackend.Status).
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	const maxOut = 512 * 1024
	text := out.String()
	if len(text) > maxOut {
		text = text[:maxOut] + "\n…(output truncated)"
	}
	if err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return text, fmt.Errorf("%s: %s", name, msg)
	}
	return text, nil
}

// haveBinary reports whether name resolves on PATH; used to pick real vs
// mock backends and the native package manager.
func haveBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
