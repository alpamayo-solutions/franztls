//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package franztls

import (
	"context"
	"runtime"
)

func acquirePlatformIssueLock(
	context.Context,
	string,
	string,
) (func() error, error) {
	return nil, &UnsupportedSafeOpenError{GOOS: runtime.GOOS}
}
