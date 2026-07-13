package franztls

import (
	"bytes"
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

type fakeManagerClock struct {
	now time.Time
}

func (clock fakeManagerClock) Now() time.Time { return clock.now }

type forbiddenIssuerFactory struct {
	calls atomic.Int32
}

type recordingManagerIssuerFactory struct {
	mu         sync.Mutex
	calls      int
	makeIssuer func(context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount) (issuer, error)
}

func (factory *recordingManagerIssuerFactory) New(
	ctx context.Context,
	cfg normalizedConfig,
	roots *x509.CertPool,
	accountKey crypto.Signer,
	account *acme.ExtendedAccount,
) (issuer, error) {
	factory.mu.Lock()
	factory.calls++
	makeIssuer := factory.makeIssuer
	factory.mu.Unlock()
	if makeIssuer == nil {
		return nil, errors.New("missing recording issuer")
	}
	return makeIssuer(ctx, cfg, roots, accountKey, account)
}

func (factory *recordingManagerIssuerFactory) callCount() int {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.calls
}

type recordingManagerIssuer struct {
	mu            sync.Mutex
	accountCalls  int
	orderCalls    int
	closeCalls    int
	ensureAccount func(context.Context, crypto.Signer, *acme.ExtendedAccount) (*acme.ExtendedAccount, error)
	obtain        func(context.Context, crypto.Signer) ([]byte, error)
	close         func(context.Context) error
}

func (issuer *recordingManagerIssuer) EnsureAccount(
	ctx context.Context,
	key crypto.Signer,
	account *acme.ExtendedAccount,
) (*acme.ExtendedAccount, error) {
	issuer.mu.Lock()
	issuer.accountCalls++
	operation := issuer.ensureAccount
	issuer.mu.Unlock()
	if operation == nil {
		return account, nil
	}
	return operation(ctx, key, account)
}

func (issuer *recordingManagerIssuer) Obtain(ctx context.Context, key crypto.Signer) ([]byte, error) {
	issuer.mu.Lock()
	issuer.orderCalls++
	operation := issuer.obtain
	issuer.mu.Unlock()
	if operation == nil {
		return nil, errors.New("missing recording order")
	}
	return operation(ctx, key)
}

func (issuer *recordingManagerIssuer) Close(ctx context.Context) error {
	issuer.mu.Lock()
	issuer.closeCalls++
	operation := issuer.close
	issuer.mu.Unlock()
	if operation == nil {
		return nil
	}
	return operation(ctx)
}

func (issuer *recordingManagerIssuer) counts() (account, order, close int) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.accountCalls, issuer.orderCalls, issuer.closeCalls
}

func (factory *forbiddenIssuerFactory) New(
	context.Context,
	normalizedConfig,
	*x509.CertPool,
	crypto.Signer,
	*acme.ExtendedAccount,
) (issuer, error) {
	factory.calls.Add(1)
	return nil, errors.New("issuer factory must not be called")
}

func newManagerForTest(
	t *testing.T,
	cfg Config,
	clock fakeManagerClock,
	factory issuerFactory,
) *Manager {
	t.Helper()
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return newManager(normalized, clock, factory)
}

func TestLoadActivatesValidDiskMaterialWithoutIssuer(t *testing.T) {
	material := newTestMaterial(t, testKeyECDSA, testKeySEC1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeTestMaterialFiles(t, material.cfg, material)
	factory := &forbiddenIssuerFactory{}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)

	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("issuer factory calls = %d, want 0", factory.calls.Load())
	}
	active := manager.current.Load()
	if active == nil || active.leaf == nil {
		t.Fatal("valid material was not activated")
	}
	if active.leaf.SerialNumber.Cmp(material.leaf.SerialNumber) != 0 {
		t.Fatalf("active serial = %s, want %s", active.leaf.SerialNumber, material.leaf.SerialNumber)
	}
	if !active.leaf.NotAfter.Equal(material.leaf.NotAfter) {
		t.Fatalf("active NotAfter = %s, want %s", active.leaf.NotAfter, material.leaf.NotAfter)
	}
	assertNoManagerEvents(t, manager)
}

func TestLoadMissingStateIsTypedBoundedAndReadOnly(t *testing.T) {
	base := storageTempDir(t)
	trustRoot := filepath.Join(base, "trust")
	if err := os.Mkdir(trustRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	stateRoot := filepath.Join(base, "missing-state")
	cfg := validConfig(stateRoot)
	cfg.CACertFile = filepath.Join(trustRoot, "prekit-ca.crt")
	if err := os.WriteFile(cfg.CACertFile, encodeTestCertificateChain(t, material.root.der), 0o644); err != nil {
		t.Fatal(err)
	}
	manager := newManagerForTest(t, cfg, fakeManagerClock{now: material.now}, &forbiddenIssuerFactory{})

	started := time.Now()
	err := manager.Load(context.Background())
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("Load returned after %v", elapsed)
	}
	var stateErr *StateError
	if !errors.As(err, &stateErr) {
		t.Fatalf("Load error = %T %v, want *StateError", err, err)
	}
	if _, statErr := os.Stat(stateRoot); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Load created missing state directory: %v", statErr)
	}
	assertManagerArtifactsAbsent(t, cfg)
	if manager.current.Load() != nil {
		t.Fatal("missing state activated material")
	}
}

func TestLoadCorruptStateIsTypedAndNeverReplaced(t *testing.T) {
	for _, test := range []struct {
		name string
		path func(Config) string
		mode os.FileMode
	}{
		{name: "CA", path: func(cfg Config) string { return cfg.CACertFile }, mode: 0o644},
		{name: "private key", path: func(cfg Config) string { return cfg.PrivateKeyFile }, mode: 0o600},
		{name: "certificate", path: func(cfg Config) string { return cfg.CertificateFile }, mode: 0o644},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			writeTestMaterialFiles(t, material.cfg, material)
			path := test.path(material.cfg)
			corrupt := []byte("corrupt-" + test.name)
			if err := os.WriteFile(path, corrupt, test.mode); err != nil {
				t.Fatal(err)
			}
			manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, &forbiddenIssuerFactory{})

			err := manager.Load(context.Background())
			var stateErr *StateError
			if !errors.As(err, &stateErr) {
				t.Fatalf("Load error = %T %v, want *StateError", err, err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil || string(got) != string(corrupt) {
				t.Fatalf("corrupt input changed: %q, %v", got, readErr)
			}
			assertManagerArtifactsAbsent(t, material.cfg)
			if manager.current.Load() != nil {
				t.Fatal("corrupt state activated material")
			}
		})
	}
}

func TestLoadChecksCancellationBeforeDiskReads(t *testing.T) {
	stateRoot := filepath.Join(storageTempDir(t), "canceled-state")
	cfg := validConfig(stateRoot)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager := newManagerForTest(t, cfg, fakeManagerClock{now: time.Now()}, &forbiddenIssuerFactory{})

	err := manager.Load(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Load error = %T %v, want context.Canceled", err, err)
	}
	if _, statErr := os.Stat(stateRoot); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled Load touched state directory: %v", statErr)
	}
}

func TestLoadNeverWaitsOnAdvisoryLockPath(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeTestMaterialFiles(t, material.cfg, material)
	lockPath := filepath.Join(filepath.Dir(material.cfg.AccountKeyFile), ".franztls.lock")
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, &forbiddenIssuerFactory{})

	started := time.Now()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("Load() error with unusable lock path = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("Load waited on lock path for %v", elapsed)
	}
}

func TestLoadRefreshesAtomicallyReplacedCertificate(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeTestMaterialFiles(t, material.cfg, material)
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, &forbiddenIssuerFactory{})
	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := manager.current.Load()

	options := cloneTestLeafOptions(material.leafOptions)
	options.notAfter = options.notAfter.Add(12 * time.Hour)
	material.reissueLeaf(options)
	if err := newStateStore(material.cfg).writeFile(
		material.cfg.CertificateFile,
		material.certificatePEM,
		0o644,
		"certificate",
	); err != nil {
		t.Fatal(err)
	}
	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := manager.current.Load()
	if second == first || second.leaf.SerialNumber.Cmp(first.leaf.SerialNumber) == 0 {
		t.Fatal("second Load did not activate the replacement certificate")
	}
	if second.fingerprint == first.fingerprint || second.identity.certificate == first.identity.certificate {
		t.Fatal("replacement certificate retained its prior identity")
	}
	if second.identity.privateKey != first.identity.privateKey {
		t.Fatal("certificate-only replacement changed private-key identity")
	}
	assertNoManagerEvents(t, manager)
}

func TestLoadCachesFirstSuccessfulCAPool(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeTestMaterialFiles(t, material.cfg, material)
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, &forbiddenIssuerFactory{})
	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}

	unrelated := newTestRoot(t, "rotated root", material.now)
	if err := os.WriteFile(
		material.cfg.CACertFile,
		encodeTestCertificateChain(t, unrelated.der),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("existing Manager followed live CA rotation: %v", err)
	}

	fresh := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, &forbiddenIssuerFactory{})
	err := fresh.Load(context.Background())
	var stateErr *StateError
	if !errors.As(err, &stateErr) || stateErr.Kind != "chain" {
		t.Fatalf("fresh Manager error = %T %v, want chain StateError", err, err)
	}
}

func TestLoadRetriesCAAfterFailedInitialRead(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeTestMaterialFiles(t, material.cfg, material)
	if err := os.WriteFile(material.cfg.CACertFile, []byte("corrupt-ca"), 0o644); err != nil {
		t.Fatal(err)
	}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, &forbiddenIssuerFactory{})
	if err := manager.Load(context.Background()); err == nil {
		t.Fatal("Load unexpectedly cached a corrupt CA")
	}
	if err := os.WriteFile(
		material.cfg.CACertFile,
		encodeTestCertificateChain(t, material.root.der),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("Load did not retry corrected CA: %v", err)
	}
}

func TestEnsureReusesNonDueMaterialEntirelyOffline(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	material.cfg.RenewBefore = 3 * time.Hour
	material.cfg.DirectoryURL = "https://127.0.0.1:1/unreachable-directory"
	if !material.now.Add(material.cfg.RenewBefore).Before(material.leaf.NotAfter) {
		t.Fatal("test certificate is not strictly outside its renewal window")
	}
	writeTestMaterialFiles(t, material.cfg, material)
	before := managerDirectoryEntries(t, filepath.Dir(material.cfg.AccountKeyFile))
	factory := &forbiddenIssuerFactory{}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)

	change, err := manager.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if change.Renewed || !change.NotAfter.Equal(material.leaf.NotAfter) {
		t.Fatalf("change = %+v, want offline reuse through %v", change, material.leaf.NotAfter)
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("issuer factory calls = %d, want 0", factory.calls.Load())
	}
	after := managerDirectoryEntries(t, filepath.Dir(material.cfg.AccountKeyFile))
	if len(before) != len(after) {
		t.Fatalf("Ensure changed state-directory entries: before=%q after=%q", before, after)
	}
	for index := range before {
		if before[index] != after[index] {
			t.Fatalf("Ensure changed state-directory entries: before=%q after=%q", before, after)
		}
	}
	assertManagerArtifactsAbsent(t, material.cfg)
	if active := manager.current.Load(); active == nil || !active.leaf.NotAfter.Equal(material.leaf.NotAfter) {
		t.Fatal("Ensure did not activate reused material")
	}
	assertNoManagerEvents(t, manager)
}

func TestLoadRejectsOversizedStateBeforeParsing(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeTestMaterialFiles(t, material.cfg, material)
	oversized := bytes.Repeat([]byte("x"), maxStateFileSize+1)
	if err := os.WriteFile(material.cfg.CertificateFile, oversized, 0o644); err != nil {
		t.Fatal(err)
	}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, &forbiddenIssuerFactory{})

	err := manager.Load(context.Background())
	if !errors.Is(err, errStateFileTooLarge) {
		t.Fatalf("Load error = %T %v, want errStateFileTooLarge", err, err)
	}
	if manager.current.Load() != nil {
		t.Fatal("oversized state activated material")
	}
}

func TestManagerLifecycleChannelsAreStable(t *testing.T) {
	material := newTestMaterial(t, testKeyECDSA, testKeySEC1, false, nil)
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, &forbiddenIssuerFactory{})
	if manager.Changes() == nil || manager.Changes() != manager.Changes() {
		t.Fatal("Changes returned a nil or unstable channel")
	}
	if manager.Errors() == nil || manager.Errors() != manager.Errors() {
		t.Fatal("Errors returned a nil or unstable channel")
	}
}

func assertNoManagerEvents(t *testing.T, manager *Manager) {
	t.Helper()
	select {
	case change := <-manager.Changes():
		t.Fatalf("unexpected certificate change: %+v", change)
	default:
	}
	select {
	case err := <-manager.Errors():
		t.Fatalf("unexpected manager error: %v", err)
	default:
	}
}

func assertManagerArtifactsAbsent(t *testing.T, cfg Config) {
	t.Helper()
	for _, path := range []string{
		cfg.AccountKeyFile,
		cfg.AccountFile,
		filepath.Join(filepath.Dir(cfg.AccountKeyFile), ".franztls.lock"),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected lifecycle artifact %s: %v", path, err)
		}
	}
}

func managerDirectoryEntries(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names
}
