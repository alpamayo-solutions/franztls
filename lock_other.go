//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package franztls

import (
	"context"
	"runtime"
	"time"
)

func acquirePlatformIssueLock(
	context.Context,
	string,
	string,
	time.Duration,
	func(),
	func(),
) (func() error, error) {
	return nil, &UnsupportedSafeOpenError{GOOS: runtime.GOOS}
}
