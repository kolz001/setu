//go:build linux

package identity

import "golang.org/x/sys/unix"

// peerCred reads SO_PEERCRED from the socket: the peer's uid, gid, and pid
// as recorded by the kernel at connect(2) time. Unforgeable by unprivileged
// peers.
func peerCred(fd uintptr) (PeerCred, error) {
	uc, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return PeerCred{}, err
	}
	return PeerCred{UID: int(uc.Uid), GID: int(uc.Gid), PID: int(uc.Pid)}, nil
}
