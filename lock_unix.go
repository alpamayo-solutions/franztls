//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package franztls

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"golang.org/x/sys/unix"
)

const issueLockPollInterval = 50 * time.Millisecond

func acquirePlatformIssueLock(
	ctx context.Context,
	stateRoot string,
	name string,
) (func() error, error) {
	directory, err := openStateDir(stateRoot, true)
	if err != nil {
		return nil, err
	}

	fd, created, err := openUnixIssueLock(directory, name)
	if err != nil {
		return nil, errors.Join(err, directory.close())
	}
	fail := func(cause error) (func() error, error) {
		return nil, errors.Join(cause, unix.Close(fd), directory.close())
	}

	if created {
		// O_EXCL proves this descriptor names the entry we created, so it is
		// safe to correct any permission bits removed by a restrictive umask.
		if err := unix.Fchmod(fd, issueLockMode); err != nil {
			return fail(err)
		}
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fail(err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fail(errNotRegularFile)
	}
	if fs.FileMode(stat.Mode&0o777).Perm() != issueLockMode {
		return fail(errWrongMode)
	}
	if created {
		if err := unix.Fsync(fd); err != nil {
			return fail(err)
		}
		if err := directory.sync(); err != nil {
			return fail(err)
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		blocked, lockErr := tryPlatformIssueLock(fd)
		if lockErr != nil {
			return fail(lockErr)
		}
		if !blocked {
			if err := ctx.Err(); err != nil {
				return fail(errors.Join(err, unlockPlatformIssueLock(fd)))
			}
			break
		}
		timer := time.NewTimer(issueLockPollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return fail(ctx.Err())
		case <-timer.C:
		}
	}

	return func() error {
		return errors.Join(
			unlockPlatformIssueLock(fd),
			unix.Close(fd),
			directory.close(),
		)
	}, nil
}

func openUnixIssueLock(directory *stateDir, name string) (fd int, created bool, err error) {
	flags := unix.O_RDWR |
		unix.O_NONBLOCK |
		unix.O_NOFOLLOW |
		unix.O_CLOEXEC
	fd, err = unix.Openat(
		directory.platform.fd,
		name,
		flags|unix.O_CREAT|unix.O_EXCL,
		issueLockMode,
	)
	if err == nil {
		return fd, true, nil
	}
	if !errors.Is(err, unix.EEXIST) {
		return -1, false, classifyUnixLockPathError(err)
	}
	fd, err = unix.Openat(directory.platform.fd, name, flags, 0)
	if err != nil {
		return -1, false, classifyUnixLockPathError(err)
	}
	return fd, false, nil
}

func classifyUnixLockPathError(err error) error {
	if errors.Is(err, unix.EISDIR) {
		return errors.Join(errNotRegularFile, err)
	}
	return classifyUnixPathError(err)
}
