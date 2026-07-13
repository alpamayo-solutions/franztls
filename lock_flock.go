//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package franztls

import (
	"errors"

	"golang.org/x/sys/unix"
)

func tryPlatformIssueLock(fd int) (bool, error) {
	err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return true, nil
	}
	return false, err
}

func unlockPlatformIssueLock(fd int) error {
	return unix.Flock(fd, unix.LOCK_UN)
}
