//go:build aix

package franztls

func tryPlatformIssueLock(int) (bool, error) {
	return false, &UnsupportedSafeOpenError{GOOS: "aix"}
}

func unlockPlatformIssueLock(int) error {
	return nil
}
