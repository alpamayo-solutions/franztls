package franztls

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
)

type managerEnsureResult struct {
	change CertificateChange
	err    error
}

type managerIssueLockSeam struct {
	acquire func(context.Context) (func() error, error)
}

func (lock *managerIssueLockSeam) Acquire(ctx context.Context) (func() error, error) {
	return lock.acquire(ctx)
}

func TestEnsureConcurrentManagersIssueOneOrder(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	material.cfg.RenewBefore = 24 * time.Hour
	writeManagerIssueCA(t, material)
	registered := testACMEAccount("https://ca.test/acme/account/two-managers")
	enteredOrder := make(chan struct{})
	releaseOrder := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(releaseOrder)
		})
	})

	recorder := managerIssueRecorder(t, material.cfg, registered)
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		enteredOnce.Do(func() {
			close(enteredOrder)
		})
		<-releaseOrder
		return managerIssueChain(t, material, signer, nil), nil
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount,
	) (issuer, error) {
		return recorder, nil
	}}
	first := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	second := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	firstResult := make(chan managerEnsureResult, 1)
	secondResult := make(chan managerEnsureResult, 1)
	start := make(chan struct{})
	go func() {
		<-start
		change, err := first.Ensure(context.Background())
		firstResult <- managerEnsureResult{change: change, err: err}
	}()
	go func() {
		<-start
		change, err := second.Ensure(context.Background())
		secondResult <- managerEnsureResult{change: change, err: err}
	}()
	close(start)
	select {
	case <-enteredOrder:
	case <-time.After(2 * time.Second):
		t.Fatal("neither Manager entered the order")
	}
	select {
	case result := <-firstResult:
		t.Fatalf("first Manager returned while order blocked: %+v, %v", result.change, result.err)
	case result := <-secondResult:
		t.Fatalf("second Manager returned while order blocked: %+v, %v", result.change, result.err)
	case <-time.After(100 * time.Millisecond):
	}
	if factory.callCount() != 1 {
		t.Fatalf("factory calls while first order blocked = %d, want 1", factory.callCount())
	}
	releaseOnce.Do(func() {
		close(releaseOrder)
	})
	gotFirst := <-firstResult
	gotSecond := <-secondResult
	if gotFirst.err != nil || gotSecond.err != nil {
		t.Fatalf("Manager errors = %v / %v", gotFirst.err, gotSecond.err)
	}
	renewed := 0
	if gotFirst.change.Renewed {
		renewed++
	}
	if gotSecond.change.Renewed {
		renewed++
	}
	if renewed != 1 || !gotFirst.change.NotAfter.Equal(gotSecond.change.NotAfter) {
		t.Fatalf("changes = %+v / %+v, want one issuance and one locked re-read", gotFirst.change, gotSecond.change)
	}
	accounts, orders, closes := recorder.counts()
	if factory.callCount() != 1 || accounts != 1 || orders != 1 || closes != 1 {
		t.Fatalf("factory/account/order/close calls = %d/%d/%d/%d, want 1/1/1/1",
			factory.callCount(), accounts, orders, closes)
	}
	events := 0
	for _, manager := range []*Manager{first, second} {
		select {
		case <-manager.Changes():
			events++
		default:
		}
	}
	if events != 1 {
		t.Fatalf("change events = %d, want 1", events)
	}
}

func TestEnsureFailureCanceledManagerWaiterDoesNotOrder(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	material.cfg.RenewBefore = 24 * time.Hour
	writeManagerIssueCA(t, material)
	registered := testACMEAccount("https://ca.test/acme/account/canceled-waiter")
	enteredOrder := make(chan struct{})
	releaseOrder := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(releaseOrder)
		})
	})

	recorder := managerIssueRecorder(t, material.cfg, registered)
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		enteredOnce.Do(func() {
			close(enteredOrder)
		})
		<-releaseOrder
		return managerIssueChain(t, material, signer, nil), nil
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount,
	) (issuer, error) {
		return recorder, nil
	}}
	first := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	second := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	firstResult := make(chan managerEnsureResult, 1)
	go func() {
		change, err := first.Ensure(context.Background())
		firstResult <- managerEnsureResult{change: change, err: err}
	}()
	select {
	case <-enteredOrder:
	case <-time.After(2 * time.Second):
		t.Fatal("first Manager did not enter the order")
	}

	paths := []string{material.cfg.AccountKeyFile, material.cfg.AccountFile, material.cfg.PrivateKeyFile, material.cfg.CertificateFile}
	beforeWaiter := snapshotManagerIssueFiles(t, paths)
	ctx, cancel := context.WithCancel(context.Background())
	secondResult := make(chan managerEnsureResult, 1)
	go func() {
		change, err := second.Ensure(ctx)
		secondResult <- managerEnsureResult{change: change, err: err}
	}()
	select {
	case result := <-secondResult:
		t.Fatalf("second Manager did not wait on OS lock: %+v, %v", result.change, result.err)
	case <-time.After(100 * time.Millisecond):
	}
	if factory.callCount() != 1 {
		t.Fatalf("second waiter reached factory: calls=%d", factory.callCount())
	}
	cancel()
	select {
	case result := <-secondResult:
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("canceled waiter error = %T %v, want context.Canceled", result.err, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled Manager remained blocked on OS lock")
	}
	assertManagerIssueFiles(t, beforeWaiter)
	if second.current.Load() != nil {
		t.Fatal("canceled waiter activated material")
	}
	releaseOnce.Do(func() {
		close(releaseOrder)
	})
	if result := <-firstResult; result.err != nil || !result.change.Renewed {
		t.Fatalf("first Ensure() = (%+v, %v), want issuance", result.change, result.err)
	}
	accounts, orders, closes := recorder.counts()
	if factory.callCount() != 1 || accounts != 1 || orders != 1 || closes != 1 {
		t.Fatalf("factory/account/order/close calls = %d/%d/%d/%d, want 1/1/1/1",
			factory.callCount(), accounts, orders, closes)
	}
	assertNoManagerEvents(t, second)
}

func TestEnsureIssuesHoldsInjectedLockThroughActivation(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeManagerIssueCA(t, material)
	registered := testACMEAccount("https://ca.test/acme/account/lock-held")
	var held atomic.Bool
	var releases atomic.Int32
	recorder := &recordingManagerIssuer{}
	recorder.ensureAccount = func(_ context.Context, _ crypto.Signer, _ *acme.ExtendedAccount) (*acme.ExtendedAccount, error) {
		if !held.Load() {
			t.Fatal("lock was not held during account setup")
		}
		if err := newStateStore(material.cfg).persistAccount(registered); err != nil {
			return nil, err
		}
		return registered, nil
	}
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		if !held.Load() {
			t.Fatal("lock was not held during order")
		}
		return managerIssueChain(t, material, signer, nil), nil
	}
	recorder.close = func(context.Context) error {
		if !held.Load() {
			t.Fatal("lock was released before issuer close")
		}
		return nil
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount,
	) (issuer, error) {
		if !held.Load() {
			t.Fatal("lock was not held during issuer construction")
		}
		return recorder, nil
	}}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	manager.lock = &managerIssueLockSeam{acquire: func(context.Context) (func() error, error) {
		if !held.CompareAndSwap(false, true) {
			t.Fatal("lock acquired twice")
		}
		return func() error {
			defer held.Store(false)
			releases.Add(1)
			if manager.current.Load() == nil {
				t.Fatal("lock released before atomic activation")
			}
			if _, err := os.Stat(material.cfg.CertificateFile); err != nil {
				t.Fatalf("lock released before durable certificate: %v", err)
			}
			return nil
		}, nil
	}}
	change, err := manager.Ensure(context.Background())
	if err != nil || !change.Renewed {
		t.Fatalf("Ensure() = (%+v, %v), want issuance", change, err)
	}
	if held.Load() || releases.Load() != 1 {
		t.Fatalf("lock state after Ensure = held:%v releases:%d", held.Load(), releases.Load())
	}
}

func TestEnsureFailureJoinsLockReleaseErrors(t *testing.T) {
	releaseErr := errors.New("injected lock release failure")
	for _, test := range []struct {
		name    string
		primary bool
	}{
		{name: "success"},
		{name: "primary failure", primary: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			writeManagerIssueCA(t, material)
			registered := testACMEAccount("https://ca.test/acme/account/release-error")
			recorder := managerIssueRecorder(t, material.cfg, registered)
			recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
				if test.primary {
					return nil, safeACMEOperationError("order", context.DeadlineExceeded)
				}
				return managerIssueChain(t, material, signer, nil), nil
			}
			factory := &recordingManagerIssuerFactory{makeIssuer: func(
				context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount,
			) (issuer, error) {
				return recorder, nil
			}}
			manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
			manager.lock = &managerIssueLockSeam{acquire: func(context.Context) (func() error, error) {
				return func() error {
					return releaseErr
				}, nil
			}}
			change, err := manager.Ensure(context.Background())
			if !errors.Is(err, releaseErr) {
				t.Fatalf("Ensure() error = %T %v, want release error", err, err)
			}
			if test.primary {
				if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrNoUsableCertificate) {
					t.Fatalf("primary error classes lost: %v", err)
				}
				assertNoManagerEvents(t, manager)
			} else {
				if !change.Renewed || manager.current.Load() == nil {
					t.Fatalf("successful transaction lost before release error: %+v", change)
				}
				receiveManagerIssueChange(t, manager)
			}
		})
	}
}

func TestEnsureFailureJoinsIssuerCloseError(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeManagerIssueCA(t, material)
	registered := testACMEAccount("https://ca.test/acme/account/close-error")
	closeErr := errors.New("injected issuer close failure")
	recorder := managerIssueRecorder(t, material.cfg, registered)
	recorder.obtain = func(context.Context, crypto.Signer) ([]byte, error) {
		return nil, safeACMEOperationError("order", context.DeadlineExceeded)
	}
	recorder.close = func(context.Context) error {
		return closeErr
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount,
	) (issuer, error) {
		return recorder, nil
	}}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	_, err := manager.Ensure(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, closeErr) ||
		!errors.Is(err, ErrNoUsableCertificate) {
		t.Fatalf("Ensure() error = %T %v, want primary, close, and availability classes", err, err)
	}
}

func TestEnsureIssuesCreatesSecureStateDirectoryAndLock(t *testing.T) {
	base := storageTempDir(t)
	trustRoot := filepath.Join(base, "trust")
	if err := os.Mkdir(trustRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	stateRoot := filepath.Join(base, "generated-state")
	cfg := validConfig(stateRoot)
	cfg.CACertFile = filepath.Join(trustRoot, "prekit-ca.crt")
	material.cfg = cfg
	writeManagerIssueCA(t, material)
	registered := testACMEAccount("https://ca.test/acme/account/secure-state")
	recorder := managerIssueRecorder(t, cfg, registered)
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		return managerIssueChain(t, material, signer, nil), nil
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount,
	) (issuer, error) {
		return recorder, nil
	}}
	manager := newManagerForTest(t, cfg, fakeManagerClock{now: material.now}, factory)
	change, err := manager.Ensure(context.Background())
	if err != nil || !change.Renewed {
		t.Fatalf("Ensure() = (%+v, %v), want issuance", change, err)
	}
	stateInfo, err := os.Stat(stateRoot)
	if err != nil {
		t.Fatalf("stat state directory: %v", err)
	}
	if !stateInfo.IsDir() || stateInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state directory = dir:%v mode:%#o, want directory 0700", stateInfo.IsDir(), stateInfo.Mode().Perm())
	}
	lockInfo, err := os.Lstat(filepath.Join(stateRoot, ".franztls.lock"))
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("lock = mode:%v perm:%#o, want regular 0600", lockInfo.Mode(), lockInfo.Mode().Perm())
	}
}

func TestEnsureFailureRejectsUnsafeLockEntry(t *testing.T) {
	for _, test := range []struct {
		name string
		want error
		make func(*testing.T, string)
	}{
		{name: "symlink", want: errUnsafeStatePath, make: func(t *testing.T, lockPath string) {
			target := lockPath + ".target"
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, lockPath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory", want: errNotRegularFile, make: func(t *testing.T, lockPath string) {
			if err := os.Mkdir(lockPath, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			writeManagerIssueCA(t, material)
			lockPath := filepath.Join(filepath.Dir(material.cfg.AccountKeyFile), ".franztls.lock")
			test.make(t, lockPath)
			factory := &forbiddenIssuerFactory{}
			manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
			_, err := manager.Ensure(context.Background())
			if !errors.Is(err, test.want) {
				t.Fatalf("Ensure() error = %T %v, want %v", err, err, test.want)
			}
			if factory.calls.Load() != 0 {
				t.Fatalf("unsafe lock constructed issuer %d times", factory.calls.Load())
			}
			for _, path := range []string{material.cfg.AccountKeyFile, material.cfg.AccountFile, material.cfg.PrivateKeyFile, material.cfg.CertificateFile} {
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("unsafe lock failure wrote %s: %v", path, statErr)
				}
			}
			if manager.current.Load() != nil {
				t.Fatal("unsafe lock activated material")
			}
		})
	}
}

func TestEnsureFailureInvalidInitialCandidateKeepsDomainKeyInMemory(t *testing.T) {
	tests := []struct {
		name      string
		candidate func(*testing.T, *testMaterial, crypto.Signer) []byte
	}{
		{name: "wrong SAN", candidate: func(t *testing.T, material *testMaterial, signer crypto.Signer) []byte {
			return managerIssueChain(t, material, signer, func(options *testLeafOptions) {
				options.dnsNames = []string{"wrong.internal"}
			})
		}},
		{name: "untrusted", candidate: func(t *testing.T, material *testMaterial, signer crypto.Signer) []byte {
			root := newTestRoot(t, "untrusted initial root", material.now)
			intermediate := newTestIntermediate(t, root, material.now)
			options := cloneTestLeafOptions(material.leafOptions)
			options.notAfter = material.now.Add(72 * time.Hour)
			leafDER, _ := newTestLeaf(t, options, signer, intermediate)
			return encodeTestCertificateChain(t, leafDER, intermediate.der)
		}},
		{name: "mismatched key", candidate: func(t *testing.T, material *testMaterial, _ crypto.Signer) []byte {
			return managerIssueChain(t, material, newTestSigner(t, testKeyRSA), nil)
		}},
		{name: "corrupt", candidate: func(*testing.T, *testMaterial, crypto.Signer) []byte {
			return []byte("corrupt initial candidate")
		}},
		{name: "expired", candidate: func(t *testing.T, material *testMaterial, signer crypto.Signer) []byte {
			return managerIssueChain(t, material, signer, func(options *testLeafOptions) {
				options.notBefore = material.now.Add(-48 * time.Hour)
				options.notAfter = material.now
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			writeManagerIssueCA(t, material)
			registered := testACMEAccount("https://ca.test/acme/account/invalid-initial")
			recorder := managerIssueRecorder(t, material.cfg, registered)
			recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
				return test.candidate(t, material, signer), nil
			}
			factory := &recordingManagerIssuerFactory{makeIssuer: func(
				context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount,
			) (issuer, error) {
				return recorder, nil
			}}
			manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
			_, err := manager.Ensure(context.Background())
			var stateErr *StateError
			if !errors.Is(err, ErrNoUsableCertificate) || !errors.As(err, &stateErr) {
				t.Fatalf("Ensure() error = %T %v, want unavailable StateError", err, err)
			}
			for _, path := range []string{material.cfg.PrivateKeyFile, material.cfg.CertificateFile} {
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("invalid initial candidate persisted domain state %s: %v", path, statErr)
				}
			}
			if manager.current.Load() != nil {
				t.Fatal("invalid initial candidate activated material")
			}
			assertNoManagerEvents(t, manager)
		})
	}
}

func TestEnsureRenewsWithoutRewritingPrivateKeyFile(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	material.cfg.RenewBefore = 24 * time.Hour
	writeTestMaterialFiles(t, material.cfg, material)
	accountKey, _, account := writeManagerIssueAccount(t, material.cfg)
	before, err := os.Stat(material.cfg.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	recorder := managerIssueRecorder(t, material.cfg, account)
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		return managerIssueChain(t, material, signer, nil), nil
	}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now},
		managerIssueFactory(t, accountKey, account, recorder))
	change, err := manager.Ensure(context.Background())
	if err != nil || !change.Renewed {
		t.Fatalf("Ensure() = (%+v, %v), want renewal", change, err)
	}
	after, err := os.Stat(material.cfg.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("renewal replaced the private-key file identity")
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("renewal changed private-key mtime: before=%v after=%v", before.ModTime(), after.ModTime())
	}
}

func TestEnsureIssuesPublishesAfterDurableActivation(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeManagerIssueCA(t, material)
	registered := testACMEAccount("https://ca.test/acme/account/publish-order")
	recorder := managerIssueRecorder(t, material.cfg, registered)
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		return managerIssueChain(t, material, signer, nil), nil
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount,
	) (issuer, error) {
		return recorder, nil
	}}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	observed := make(chan error, 1)
	manager.publishChange = func(change CertificateChange) {
		active := manager.current.Load()
		if active == nil || !active.leaf.NotAfter.Equal(change.NotAfter) {
			observed <- errors.New("publish preceded active material")
			return
		}
		keyPEM, keyErr := os.ReadFile(material.cfg.PrivateKeyFile)
		certificatePEM, certificateErr := os.ReadFile(material.cfg.CertificateFile)
		if keyErr != nil {
			observed <- keyErr
			return
		}
		if certificateErr != nil {
			observed <- certificateErr
			return
		}
		if _, err := parseMaterial(certificatePEM, keyPEM, material.roots, material.cfg, material.now); err != nil {
			observed <- err
			return
		}
		observed <- nil
		select {
		case manager.changes <- change:
		default:
		}
	}
	change, err := manager.Ensure(context.Background())
	if err != nil || !change.Renewed {
		t.Fatalf("Ensure() = (%+v, %v), want issuance", change, err)
	}
	if err := <-observed; err != nil {
		t.Fatalf("publish-order observation failed: %v", err)
	}
	event := receiveManagerIssueChange(t, manager)
	if event != change {
		t.Fatalf("event = %+v, want %+v", event, change)
	}
	assertNoAdditionalManagerIssueChange(t, manager)
}
