//go:build windows

package franztls

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

const issueLockPollInterval = 50 * time.Millisecond

func acquirePlatformIssueLock(
	ctx context.Context,
	stateRoot string,
	name string,
	pollInterval time.Duration,
	afterDescriptorValidated func(),
	onContention func(),
) (func() error, error) {
	directory, err := openStateDir(stateRoot, true)
	if err != nil {
		return nil, err
	}
	handle, err := ntOpenPath(
		directory.platform.handle,
		name,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.SYNCHRONIZE,
		windows.FILE_OPEN_IF,
		windows.FILE_NON_DIRECTORY_FILE,
	)
	if err != nil {
		return nil, errors.Join(classifyWindowsLockPathError(err), directory.close())
	}
	fail := func(cause error) (func() error, error) {
		return nil, errors.Join(cause, windows.CloseHandle(handle), directory.close())
	}
	if err := rejectWindowsReparse(handle, false); err != nil {
		return fail(err)
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		return fail(err)
	}
	if err := directory.sync(); err != nil {
		return fail(err)
	}
	if afterDescriptorValidated != nil {
		afterDescriptorValidated()
	}
	if pollInterval <= 0 {
		pollInterval = issueLockPollInterval
	}

	var overlapped windows.Overlapped
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		err := windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			&overlapped,
		)
		if err == nil {
			if err := ctx.Err(); err != nil {
				return fail(errors.Join(
					err,
					windows.UnlockFileEx(handle, 0, 1, 0, &overlapped),
				))
			}
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return fail(err)
		}
		if onContention != nil {
			onContention()
		}
		timer := time.NewTimer(pollInterval)
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
			windows.UnlockFileEx(handle, 0, 1, 0, &overlapped),
			windows.CloseHandle(handle),
			directory.close(),
		)
	}, nil
}

func classifyWindowsLockPathError(err error) error {
	if errors.Is(err, windows.STATUS_FILE_IS_A_DIRECTORY) ||
		errors.Is(err, windows.STATUS_OBJECT_TYPE_MISMATCH) {
		return errors.Join(errNotRegularFile, err)
	}
	return classifyWindowsPathError(err)
}
