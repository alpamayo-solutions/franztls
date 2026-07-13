//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package franztls

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProcessesLockValidatedDescriptorAcrossEntrySwap(t *testing.T) {
	fixture := newProcessFixture(t)
	if err := os.Mkdir(fixture.stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(fixture.stateRoot, issueLockFileName)
	openedPath := filepath.Join(fixture.stateRoot, "opened-lock-inode")
	targetPath := filepath.Join(fixture.coordRoot, "replacement-target")
	targetContents := []byte("replacement-must-not-be-followed")
	readyFile := filepath.Join(fixture.coordRoot, "descriptor-validated")
	startFile := filepath.Join(fixture.coordRoot, "descriptor-continue")
	acquiredFile := filepath.Join(fixture.coordRoot, "descriptor-acquired")
	releaseFile := filepath.Join(fixture.coordRoot, "descriptor-release")

	helper := fixture.helper("descriptor_lock")
	helper.ReadyFile = readyFile
	helper.StartFile = startFile
	helper.AcquiredFile = acquiredFile
	helper.ReleaseFile = releaseFile
	process := startProcessHelper(
		t,
		writeProcessHelperConfig(t, fixture, "descriptor-lock", helper),
	)
	if err := process.waitForFile(readyFile, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(lockPath, openedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, targetContents, 0o600); err != nil {
		t.Fatal(err)
	}
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, lockPath); err != nil {
		t.Fatal(err)
	}
	writeProcessSignalForTest(t, startFile)
	if err := process.waitForFile(acquiredFile, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	blocked, err := processTryLockPath(openedPath)
	if err != nil {
		t.Fatalf("probe opened lock inode: %v", err)
	}
	if !blocked {
		t.Fatal("validated lock inode was not held after the directory entry swap")
	}
	targetBlocked, err := processTryLockPath(targetPath)
	if err != nil {
		t.Fatalf("probe replacement target: %v", err)
	}
	if targetBlocked {
		t.Fatal("replacement target was locked through the swapped symlink")
	}
	assertProcessFileUnchanged(t, targetPath, targetContents, targetInfo)
	assertProcessSymlinkUnchanged(t, lockPath, targetPath)

	writeProcessSignalForTest(t, releaseFile)
	if err := process.wait(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	assertProcessFileUnchanged(t, targetPath, targetContents, targetInfo)
	assertProcessSymlinkUnchanged(t, lockPath, targetPath)
}

func processTryLockPath(path string) (blocked bool, err error) {
	fd, err := unix.Open(
		path,
		unix.O_RDWR|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return false, err
	}
	blocked, lockErr := tryPlatformIssueLock(fd)
	if lockErr != nil || blocked {
		return blocked, errors.Join(lockErr, unix.Close(fd))
	}
	return false, errors.Join(unlockPlatformIssueLock(fd), unix.Close(fd))
}
