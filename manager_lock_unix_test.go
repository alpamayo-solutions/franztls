//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package franztls

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestEnsureFailureRejectsUnsafeUnixLockEntry(t *testing.T) {
	for _, test := range []struct {
		name string
		want error
		make func(string) error
	}{
		{
			name: "wrong mode",
			want: errWrongMode,
			make: func(lockPath string) error {
				return os.WriteFile(lockPath, nil, 0o644)
			},
		},
		{
			name: "FIFO",
			want: errNotRegularFile,
			make: func(lockPath string) error {
				return unix.Mkfifo(lockPath, 0o600)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := newTestMaterial(
				t,
				testKeyRSA,
				testKeyPKCS1,
				true,
				[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			)
			writeManagerIssueCA(t, material)
			lockPath := filepath.Join(filepath.Dir(material.cfg.AccountKeyFile), ".franztls.lock")
			if err := test.make(lockPath); err != nil {
				t.Fatal(err)
			}
			factory := &forbiddenIssuerFactory{}
			manager := newManagerForTest(
				t,
				material.cfg,
				fakeManagerClock{now: material.now},
				factory,
			)
			done := make(chan managerEnsureResult, 1)
			go func() {
				change, err := manager.Ensure(context.Background())
				done <- managerEnsureResult{change: change, err: err}
			}()

			var err error
			select {
			case result := <-done:
				err = result.err
			case <-time.After(500 * time.Millisecond):
				// Unblock an unsafe blocking FIFO open so this regression test
				// cannot hang or leak its Ensure goroutine.
				fd, openErr := unix.Open(lockPath, unix.O_RDWR|unix.O_NONBLOCK, 0)
				if openErr == nil {
					_ = unix.Close(fd)
				}
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				t.Fatalf("Ensure blocked on %s lock", test.name)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("Ensure() error = %T %v, want %v", err, err, test.want)
			}
			if factory.calls.Load() != 0 {
				t.Fatalf("unsafe lock constructed issuer %d times", factory.calls.Load())
			}
			for _, path := range []string{
				material.cfg.AccountKeyFile,
				material.cfg.AccountFile,
				material.cfg.PrivateKeyFile,
				material.cfg.CertificateFile,
			} {
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("unsafe lock failure wrote %s: %v", path, statErr)
				}
			}
			if manager.current.Load() != nil {
				t.Fatal("unsafe lock activated material")
			}
			assertNoManagerEvents(t, manager)
		})
	}
}
