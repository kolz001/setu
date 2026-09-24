package daemon

import "os/exec"

// lookPath reports whether name resolves on PATH; backend auto-detection
// (registerBackends) keys off it.
func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
