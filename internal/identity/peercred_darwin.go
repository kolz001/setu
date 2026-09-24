//go:build darwin

package identity

import "golang.org/x/sys/unix"

// peerCred reads LOCAL_PEERCRED (uid + groups) and LOCAL_PEERPID from the
// socket — macOS's equivalents of Linux's SO_PEERCRED. The uid is the
// security identity; the pid is best-effort (informational only), so its
// lookup failing does not fail credential extraction.
func peerCred(fd uintptr) (PeerCred, error) {
	xu, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return PeerCred{}, err
	}
	pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		pid = 0
	}
	gid := 0
	if xu.Ngroups > 0 {
		gid = int(xu.Groups[0]) // first group is the effective gid
	}
	return PeerCred{UID: int(xu.Uid), GID: gid, PID: pid}, nil
}
