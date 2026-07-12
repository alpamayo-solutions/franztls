//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package franztls

import (
	"io/fs"
	"runtime"
)

type platformDir struct{}

func platformOpenDir(string, bool, fs.FileMode) (*platformDir, error) {
	return nil, &UnsupportedSafeOpenError{GOOS: runtime.GOOS}
}

func (d *platformDir) createTemp(string) (atomicFile, string, error) {
	return nil, "", &UnsupportedSafeOpenError{GOOS: runtime.GOOS}
}

func (d *platformDir) remove(string) error {
	return &UnsupportedSafeOpenError{GOOS: runtime.GOOS}
}

func (d *platformDir) rename(string, string) error {
	return &UnsupportedSafeOpenError{GOOS: runtime.GOOS}
}

func (d *platformDir) sync() error {
	return &UnsupportedSafeOpenError{GOOS: runtime.GOOS}
}

func (d *platformDir) close() error {
	return nil
}

func (d *platformDir) readFile(string) ([]byte, fs.FileMode, error) {
	return nil, 0, &UnsupportedSafeOpenError{GOOS: runtime.GOOS}
}
