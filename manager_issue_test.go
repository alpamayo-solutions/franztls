package franztls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
)

func TestEnsureIssuesInitialMaterial(t *testing.T) {
	material := newTestMaterial(
		t, testKeyRSA, testKeyPKCS1, true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	material.cfg.RenewBefore = 24 * time.Hour
	if err := os.WriteFile(
		material.cfg.CACertFile,
		encodeTestCertificateChain(t, material.root.der),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	registered := testACMEAccount("https://ca.test/acme/account/initial")
	var accountSigner crypto.Signer
	recorder := &recordingManagerIssuer{}
	recorder.ensureAccount = func(
		_ context.Context, signer crypto.Signer, existing *acme.ExtendedAccount,
	) (*acme.ExtendedAccount, error) {
		if existing != nil {
			t.Fatalf("initial account = %+v, want nil", existing)
		}
		key, ok := signer.(*rsa.PrivateKey)
		if !ok || key.N.BitLen() != 2048 {
			t.Fatalf("account signer = %T/%v, want RSA-2048", signer, ok)
		}
		accountSigner = signer
		encoded, err := os.ReadFile(material.cfg.AccountKeyFile)
		if err != nil {
			t.Fatalf("account key was not durable before registration: %v", err)
		}
		persisted, err := parsePrivateKey(encoded)
		if err != nil || !sameSigner(persisted, signer) {
			t.Fatalf("persisted account key does not match registration signer: %v", err)
		}
		if err := newStateStore(material.cfg).persistAccount(registered); err != nil {
			t.Fatalf("simulate issuer account persistence: %v", err)
		}
		return registered, nil
	}
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		key, ok := signer.(*rsa.PrivateKey)
		if !ok || key.N.BitLen() != 2048 || sameSigner(signer, accountSigner) {
			t.Fatalf("domain signer = %T/%v, want distinct RSA-2048", signer, ok)
		}
		assertPersistedAccount(t, material.cfg, registered)
		options := cloneTestLeafOptions(material.leafOptions)
		options.notAfter = material.now.Add(72 * time.Hour)
		leafDER, _ := newTestLeaf(t, options, signer, material.issuer)
		return encodeTestCertificateChain(t, leafDER, material.intermediateDER), nil
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		_ context.Context, _ normalizedConfig, _ *x509.CertPool,
		signer crypto.Signer, existing *acme.ExtendedAccount,
	) (issuer, error) {
		if existing != nil {
			t.Fatalf("factory account = %+v, want nil", existing)
		}
		if _, err := os.Stat(material.cfg.AccountKeyFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("account key existed before factory construction: %v", err)
		}
		return recorder, nil
	}}
	manager := newManagerForTest(
		t, material.cfg, fakeManagerClock{now: material.now}, factory,
	)
	change, err := manager.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if !change.Renewed || !change.NotAfter.Equal(material.now.Add(72*time.Hour)) {
		t.Fatalf("change = %+v, want renewed initial certificate", change)
	}
	keyPEM, err := os.ReadFile(material.cfg.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := os.ReadFile(material.cfg.CertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseMaterial(
		certificatePEM, keyPEM, material.roots, material.cfg, material.now,
	); err != nil {
		t.Fatalf("committed material is invalid: %v", err)
	}
	accountCalls, orderCalls, closeCalls := recorder.counts()
	if factory.callCount() != 1 || accountCalls != 1 || orderCalls != 1 || closeCalls != 1 {
		t.Fatalf("calls = factory:%d account:%d order:%d close:%d, want all 1",
			factory.callCount(), accountCalls, orderCalls, closeCalls)
	}
	event := receiveManagerIssueChange(t, manager)
	if event != change {
		t.Fatalf("event = %+v, want %+v", event, change)
	}
	active := manager.current.Load()
	if active == nil || !active.leaf.NotAfter.Equal(change.NotAfter) {
		t.Fatal("initial event preceded atomic activation")
	}
	for path, mode := range map[string]os.FileMode{
		material.cfg.AccountKeyFile:  0o600,
		material.cfg.AccountFile:     0o600,
		material.cfg.PrivateKeyFile:  0o600,
		material.cfg.CertificateFile: 0o644,
		filepath.Join(filepath.Dir(material.cfg.AccountKeyFile), ".franztls.lock"): 0o600,
	} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("durable event state %s is missing: %v", path, statErr)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("durable event state %s mode = %#o, want %#o", path, info.Mode().Perm(), mode)
		}
	}
	assertNoAdditionalManagerIssueChange(t, manager)
}

func TestEnsureRenewsDueMaterial(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	material.cfg.RenewBefore = 24 * time.Hour
	if !material.now.Add(material.cfg.RenewBefore).Equal(material.leaf.NotAfter) {
		t.Fatal("test certificate is not exactly on the renewal boundary")
	}
	writeTestMaterialFiles(t, material.cfg, material)
	accountKey, accountKeyPEM, account := writeManagerIssueAccount(t, material.cfg)
	oldKey := bytes.Clone(material.privateKeyPEM)
	oldCertificate := bytes.Clone(material.certificatePEM)
	recorder := managerIssueRecorder(t, material.cfg, account)
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		if !sameSigner(signer, material.leafKey) {
			t.Fatal("renewal did not reuse the domain signer")
		}
		return managerIssueChain(t, material, signer, nil), nil
	}
	factory := managerIssueFactory(t, accountKey, account, recorder)
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldActive := manager.current.Load()
	oldFingerprint := oldActive.fingerprint
	oldKeyIdentity := oldActive.identity.privateKey
	change, err := manager.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if !change.Renewed || !change.NotAfter.Equal(material.now.Add(72*time.Hour)) {
		t.Fatalf("change = %+v, want due renewal", change)
	}
	assertFileBytesAndMode(t, material.cfg.PrivateKeyFile, oldKey, 0o600)
	assertFileBytesAndMode(t, material.cfg.AccountKeyFile, accountKeyPEM, 0o600)
	newCertificate, readErr := os.ReadFile(material.cfg.CertificateFile)
	if readErr != nil || bytes.Equal(newCertificate, oldCertificate) {
		t.Fatalf("certificate was not replaced: %v", readErr)
	}
	event := receiveManagerIssueChange(t, manager)
	active := manager.current.Load()
	if event != change || active == nil || active.fingerprint == oldFingerprint ||
		active.identity.privateKey != oldKeyIdentity {
		t.Fatal("renewal event preceded durable certificate-only activation")
	}
	assertNoAdditionalManagerIssueChange(t, manager)
}

func TestEnsureIssuesReplacementWithExistingDomainKey(t *testing.T) {
	for _, certificateState := range []string{"missing", "corrupt"} {
		t.Run(certificateState, func(t *testing.T) {
			material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			material.cfg.RenewBefore = 24 * time.Hour
			writeManagerIssueCA(t, material)
			if err := os.WriteFile(material.cfg.PrivateKeyFile, material.privateKeyPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			if certificateState == "corrupt" {
				if err := os.WriteFile(material.cfg.CertificateFile, []byte("corrupt certificate"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			accountKey, _, account := writeManagerIssueAccount(t, material.cfg)
			recorder := managerIssueRecorder(t, material.cfg, account)
			recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
				if !sameSigner(signer, material.leafKey) {
					t.Fatal("replacement changed existing domain signer")
				}
				return managerIssueChain(t, material, signer, nil), nil
			}
			manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now},
				managerIssueFactory(t, accountKey, account, recorder))
			change, err := manager.Ensure(context.Background())
			if err != nil || !change.Renewed {
				t.Fatalf("Ensure() = (%+v, %v), want replacement", change, err)
			}
			assertFileBytesAndMode(t, material.cfg.PrivateKeyFile, material.privateKeyPEM, 0o600)
			certificatePEM, readErr := os.ReadFile(material.cfg.CertificateFile)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if _, parseErr := parseMaterial(certificatePEM, material.privateKeyPEM, material.roots, material.cfg, material.now); parseErr != nil {
				t.Fatalf("replacement material is invalid: %v", parseErr)
			}
		})
	}
}

func TestEnsureFailureRejectsInvalidReturnedMaterial(t *testing.T) {
	tests := []struct {
		name      string
		candidate func(*testing.T, *testMaterial, crypto.Signer) []byte
	}{
		{name: "wrong SAN", candidate: func(t *testing.T, material *testMaterial, signer crypto.Signer) []byte {
			return managerIssueChain(t, material, signer, func(options *testLeafOptions) {
				options.dnsNames = []string{"other.internal"}
			})
		}},
		{name: "untrusted", candidate: func(t *testing.T, material *testMaterial, signer crypto.Signer) []byte {
			root := newTestRoot(t, "untrusted issue root", material.now)
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
			return []byte("corrupt returned chain")
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
			material.cfg.RenewBefore = 24 * time.Hour
			writeTestMaterialFiles(t, material.cfg, material)
			accountKey, _, account := writeManagerIssueAccount(t, material.cfg)
			oldKey := bytes.Clone(material.privateKeyPEM)
			oldCertificate := bytes.Clone(material.certificatePEM)
			recorder := managerIssueRecorder(t, material.cfg, account)
			recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
				return test.candidate(t, material, signer), nil
			}
			manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now},
				managerIssueFactory(t, accountKey, account, recorder))
			if err := manager.Load(context.Background()); err != nil {
				t.Fatal(err)
			}
			oldFingerprint := manager.current.Load().fingerprint
			change, err := manager.Ensure(context.Background())
			var deferred *DeferredRenewalError
			var stateErr *StateError
			if !errors.As(err, &deferred) || !errors.As(err, &stateErr) ||
				!deferred.NotAfter.Equal(material.leaf.NotAfter) || !change.NotAfter.Equal(material.leaf.NotAfter) {
				t.Fatalf("Ensure() = (%+v, %T %v), want deferred validation failure", change, err, err)
			}
			assertFileBytesAndMode(t, material.cfg.PrivateKeyFile, oldKey, 0o600)
			assertFileBytesAndMode(t, material.cfg.CertificateFile, oldCertificate, 0o644)
			if manager.current.Load().fingerprint != oldFingerprint {
				t.Fatal("invalid returned material displaced active certificate")
			}
			assertNoManagerEvents(t, manager)
		})
	}
}

func TestEnsureFailureKeepsUsableMemoryWhenDiskReplacementIsInvalid(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	material.cfg.RenewBefore = 24 * time.Hour
	writeTestMaterialFiles(t, material.cfg, material)
	accountKey, _, account := writeManagerIssueAccount(t, material.cfg)
	recorder := managerIssueRecorder(t, material.cfg, account)
	recorder.obtain = func(context.Context, crypto.Signer) ([]byte, error) {
		return nil, safeACMEOperationError("order", context.DeadlineExceeded)
	}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now},
		managerIssueFactory(t, accountKey, account, recorder))
	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldActive := manager.current.Load()
	corrupt := []byte("invalid external replacement")
	if err := os.WriteFile(material.cfg.CertificateFile, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	change, err := manager.Ensure(context.Background())
	var deferred *DeferredRenewalError
	if !errors.As(err, &deferred) || !errors.Is(err, context.DeadlineExceeded) ||
		!change.NotAfter.Equal(material.leaf.NotAfter) {
		t.Fatalf("Ensure() = (%+v, %T %v), want deferred deadline failure", change, err, err)
	}
	assertFileBytesAndMode(t, material.cfg.CertificateFile, corrupt, 0o644)
	if manager.current.Load() != oldActive {
		t.Fatal("invalid disk replacement dislodged usable active memory")
	}
	assertNoManagerEvents(t, manager)
}

func TestEnsureAccountStateErrorsDoNotCreateReplacementIdentity(t *testing.T) {
	tests := []struct {
		name, wantKind   string
		active, noUsable bool
		prepare          func(*testing.T, *testMaterial)
	}{
		{name: "corrupt account key", wantKind: "account_key", active: true, prepare: func(t *testing.T, material *testMaterial) {
			if err := os.WriteFile(material.cfg.AccountKeyFile, []byte("corrupt account key"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "corrupt account JSON", wantKind: "account", active: true, prepare: func(t *testing.T, material *testMaterial) {
			key := encodeTestPrivateKey(t, newTestRSAAccountKey(t), testKeyPKCS1)
			if err := os.WriteFile(material.cfg.AccountKeyFile, key, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(material.cfg.AccountFile, []byte("corrupt account JSON"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "account without key", wantKind: "account_state", active: true, prepare: func(t *testing.T, material *testMaterial) {
			if err := newStateStore(material.cfg).persistAccount(testACMEAccount("https://ca.test/account/orphan")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "corrupt domain key", wantKind: "private_key", noUsable: true, prepare: func(t *testing.T, material *testMaterial) {
			writeTestMaterialFiles(t, material.cfg, material)
			if err := os.WriteFile(material.cfg.PrivateKeyFile, []byte("corrupt domain key"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "certificate without key", wantKind: "material_state", noUsable: true, prepare: func(t *testing.T, material *testMaterial) {
			writeManagerIssueCA(t, material)
			if err := os.WriteFile(material.cfg.CertificateFile, material.certificatePEM, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			material.cfg.RenewBefore = 24 * time.Hour
			factory := &recordingManagerIssuerFactory{makeIssuer: func(context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount) (issuer, error) {
				t.Fatal("issuer constructed for inconsistent state")
				return nil, nil
			}}
			manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
			if test.active {
				writeTestMaterialFiles(t, material.cfg, material)
				if err := manager.Load(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			test.prepare(t, material)
			paths := []string{material.cfg.AccountKeyFile, material.cfg.AccountFile, material.cfg.PrivateKeyFile, material.cfg.CertificateFile}
			before := snapshotManagerIssueFiles(t, paths)
			oldActive := manager.current.Load()
			change, err := manager.Ensure(context.Background())
			var stateErr *StateError
			if !errors.As(err, &stateErr) || stateErr.Kind != test.wantKind {
				t.Fatalf("Ensure() error = %T %v, want %s StateError", err, err, test.wantKind)
			}
			if test.active {
				var deferred *DeferredRenewalError
				if !errors.As(err, &deferred) || !change.NotAfter.Equal(material.leaf.NotAfter) {
					t.Fatalf("active failure = (%+v, %v), want deferred", change, err)
				}
				if manager.current.Load() != oldActive {
					t.Fatal("state error displaced active certificate")
				}
			}
			if test.noUsable && !errors.Is(err, ErrNoUsableCertificate) {
				t.Fatalf("error = %v, want ErrNoUsableCertificate", err)
			}
			assertManagerIssueFiles(t, before)
			if factory.callCount() != 0 {
				t.Fatalf("issuer calls = %d, want 0", factory.callCount())
			}
			assertNoManagerEvents(t, manager)
		})
	}
}

func TestEnsureAccountRecoversMissingRecordBeforeOrder(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	material.cfg.RenewBefore = 24 * time.Hour
	writeTestMaterialFiles(t, material.cfg, material)
	accountKey := newTestRSAAccountKey(t)
	accountKeyPEM := encodeTestPrivateKey(t, accountKey, testKeyPKCS1)
	if err := newStateStore(material.cfg).writeFile(material.cfg.AccountKeyFile, accountKeyPEM, 0o600, "account_key"); err != nil {
		t.Fatal(err)
	}
	recovered := testACMEAccount("https://ca.test/acme/account/recovered-manager")
	recorder := &recordingManagerIssuer{}
	recorder.ensureAccount = func(_ context.Context, signer crypto.Signer, existing *acme.ExtendedAccount) (*acme.ExtendedAccount, error) {
		if existing != nil || !sameSigner(signer, accountKey) {
			t.Fatal("recovery did not use existing account key without record")
		}
		if err := newStateStore(material.cfg).persistAccount(recovered); err != nil {
			return nil, err
		}
		return recovered, nil
	}
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		assertPersistedAccount(t, material.cfg, recovered)
		return managerIssueChain(t, material, signer, nil), nil
	}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now},
		managerIssueFactory(t, accountKey, nil, recorder))
	change, err := manager.Ensure(context.Background())
	if err != nil || !change.Renewed {
		t.Fatalf("Ensure() = (%+v, %v), want recovered renewal", change, err)
	}
	assertFileBytesAndMode(t, material.cfg.AccountKeyFile, accountKeyPEM, 0o600)
	assertPersistedAccount(t, material.cfg, recovered)
}

func TestEnsureFailureExternalAccountBindingHasNoUsableCertificate(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeManagerIssueCA(t, material)
	factory := &recordingManagerIssuerFactory{makeIssuer: func(context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount) (issuer, error) {
		return nil, ErrExternalAccountBinding
	}}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	_, err := manager.Ensure(context.Background())
	if !errors.Is(err, ErrExternalAccountBinding) || !errors.Is(err, ErrNoUsableCertificate) {
		t.Fatalf("Ensure() error = %T %v, want EAB plus ErrNoUsableCertificate", err, err)
	}
	for _, path := range []string{material.cfg.AccountKeyFile, material.cfg.AccountFile, material.cfg.PrivateKeyFile, material.cfg.CertificateFile} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("EAB failure wrote %s: %v", path, statErr)
		}
	}
	if manager.current.Load() != nil {
		t.Fatal("EAB failure activated material")
	}
	assertNoManagerEvents(t, manager)
}

func TestEnsureFailureWithoutUsableCertificatePreservesOperationClass(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	writeManagerIssueCA(t, material)
	registered := testACMEAccount("https://ca.test/acme/account/failed-initial")
	recorder := managerIssueRecorder(t, material.cfg, registered)
	recorder.obtain = func(context.Context, crypto.Signer) ([]byte, error) {
		return nil, safeACMEOperationError("order", context.DeadlineExceeded)
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount) (issuer, error) {
		return recorder, nil
	}}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	_, err := manager.Ensure(context.Background())
	if !errors.Is(err, ErrNoUsableCertificate) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ensure() error = %T %v, want availability plus deadline classes", err, err)
	}
	for _, path := range []string{material.cfg.PrivateKeyFile, material.cfg.CertificateFile} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed initial order wrote domain state %s: %v", path, statErr)
		}
	}
	_, orders, closes := recorder.counts()
	if orders != 1 || closes != 1 {
		t.Fatalf("order/close calls = %d/%d, want 1/1", orders, closes)
	}
	assertNoManagerEvents(t, manager)
}

func TestEnsureFailureCancellationStopsIssuerAndPreservesRenewal(t *testing.T) {
	for _, phase := range []string{"account", "challenge", "order"} {
		t.Run(phase, func(t *testing.T) {
			material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			material.cfg.RenewBefore = 24 * time.Hour
			writeTestMaterialFiles(t, material.cfg, material)
			accountKey, _, account := writeManagerIssueAccount(t, material.cfg)
			ctx, cancel := context.WithCancel(context.Background())
			recorder := &recordingManagerIssuer{}
			recorder.ensureAccount = func(_ context.Context, _ crypto.Signer, existing *acme.ExtendedAccount) (*acme.ExtendedAccount, error) {
				if phase == "account" {
					cancel()
					return nil, safeACMEOperationError("account", ctx.Err())
				}
				if err := newStateStore(material.cfg).persistAccount(existing); err != nil {
					return nil, err
				}
				return existing, nil
			}
			recorder.obtain = func(context.Context, crypto.Signer) ([]byte, error) {
				cancel()
				return nil, safeACMEOperationError(phase, ctx.Err())
			}
			manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now},
				managerIssueFactory(t, accountKey, account, recorder))
			if err := manager.Load(context.Background()); err != nil {
				t.Fatal(err)
			}
			oldActive := manager.current.Load()
			paths := []string{material.cfg.AccountKeyFile, material.cfg.AccountFile, material.cfg.PrivateKeyFile, material.cfg.CertificateFile}
			before := snapshotManagerIssueFiles(t, paths)
			change, err := manager.Ensure(ctx)
			var deferred *DeferredRenewalError
			if !errors.As(err, &deferred) || !errors.Is(err, context.Canceled) || !change.NotAfter.Equal(material.leaf.NotAfter) {
				t.Fatalf("Ensure() = (%+v, %T %v), want canceled deferred renewal", change, err, err)
			}
			assertManagerIssueFiles(t, before)
			if manager.current.Load() != oldActive {
				t.Fatal("cancellation replaced active material")
			}
			_, _, closes := recorder.counts()
			if closes != 1 {
				t.Fatalf("issuer close calls = %d, want 1", closes)
			}
			assertNoManagerEvents(t, manager)
		})
	}
}

func TestEnsureConcurrentGoroutinesIssueOneOrder(t *testing.T) {
	material := newTestMaterial(t, testKeyRSA, testKeyPKCS1, true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	material.cfg.RenewBefore = 24 * time.Hour
	writeManagerIssueCA(t, material)
	registered := testACMEAccount("https://ca.test/acme/account/concurrent")
	recorder := managerIssueRecorder(t, material.cfg, registered)
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		return managerIssueChain(t, material, signer, nil), nil
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount) (issuer, error) {
		return recorder, nil
	}}
	manager := newManagerForTest(t, material.cfg, fakeManagerClock{now: material.now}, factory)
	type result struct {
		change CertificateChange
		err    error
	}
	results := make(chan result, 20)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < 20; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			change, err := manager.Ensure(context.Background())
			results <- result{change: change, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	renewed := 0
	for got := range results {
		if got.err != nil {
			t.Fatalf("concurrent Ensure() error = %v", got.err)
		}
		if got.change.Renewed {
			renewed++
		}
	}
	accounts, orders, closes := recorder.counts()
	if renewed != 1 || factory.callCount() != 1 || accounts != 1 || orders != 1 || closes != 1 {
		t.Fatalf("concurrent results = renewed:%d factory:%d account:%d order:%d close:%d, want all 1",
			renewed, factory.callCount(), accounts, orders, closes)
	}
	keyPEM, keyErr := os.ReadFile(material.cfg.PrivateKeyFile)
	certificatePEM, certificateErr := os.ReadFile(material.cfg.CertificateFile)
	if keyErr != nil || certificateErr != nil {
		t.Fatalf("read final keypair: %v / %v", keyErr, certificateErr)
	}
	if _, err := parseMaterial(certificatePEM, keyPEM, material.roots, material.cfg, material.now); err != nil {
		t.Fatalf("final keypair invalid: %v", err)
	}
	receiveManagerIssueChange(t, manager)
	assertNoAdditionalManagerIssueChange(t, manager)
}

func writeManagerIssueCA(t *testing.T, material *testMaterial) {
	t.Helper()
	if err := os.WriteFile(material.cfg.CACertFile, encodeTestCertificateChain(t, material.root.der), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeManagerIssueAccount(t *testing.T, cfg Config) (crypto.Signer, []byte, *acme.ExtendedAccount) {
	t.Helper()
	key := newTestRSAAccountKey(t)
	encoded := encodeTestPrivateKey(t, key, testKeyPKCS1)
	store := newStateStore(cfg)
	if err := store.writeFile(cfg.AccountKeyFile, encoded, 0o600, "account_key"); err != nil {
		t.Fatal(err)
	}
	account := testACMEAccount("https://ca.test/acme/account/existing-manager")
	if err := store.persistAccount(account); err != nil {
		t.Fatal(err)
	}
	return key, encoded, account
}

func managerIssueRecorder(t *testing.T, cfg Config, account *acme.ExtendedAccount) *recordingManagerIssuer {
	t.Helper()
	recorder := &recordingManagerIssuer{}
	recorder.ensureAccount = func(_ context.Context, _ crypto.Signer, existing *acme.ExtendedAccount) (*acme.ExtendedAccount, error) {
		resolved := account
		if existing != nil {
			resolved = existing
		}
		if resolved == nil {
			t.Fatal("recording issuer has no account")
		}
		if err := newStateStore(cfg).persistAccount(resolved); err != nil {
			return nil, err
		}
		return resolved, nil
	}
	return recorder
}

func managerIssueFactory(t *testing.T, accountKey crypto.Signer, account *acme.ExtendedAccount, recorder issuer) *recordingManagerIssuerFactory {
	t.Helper()
	return &recordingManagerIssuerFactory{makeIssuer: func(_ context.Context, _ normalizedConfig, _ *x509.CertPool, signer crypto.Signer, existing *acme.ExtendedAccount) (issuer, error) {
		if !sameSigner(signer, accountKey) {
			t.Fatal("factory did not receive existing account key")
		}
		if (existing == nil) != (account == nil) {
			t.Fatalf("factory account = %+v, want %+v", existing, account)
		}
		return recorder, nil
	}}
}

func managerIssueChain(t *testing.T, material *testMaterial, signer crypto.Signer, mutate func(*testLeafOptions)) []byte {
	t.Helper()
	options := cloneTestLeafOptions(material.leafOptions)
	options.notBefore = material.now.Add(-time.Hour)
	options.notAfter = material.now.Add(72 * time.Hour)
	if mutate != nil {
		mutate(&options)
	}
	leafDER, _ := newTestLeaf(t, options, signer, material.issuer)
	if material.withIntermediate {
		return encodeTestCertificateChain(t, leafDER, material.intermediateDER)
	}
	return encodeTestCertificateChain(t, leafDER)
}

type managerIssueFileSnapshot struct {
	path    string
	data    []byte
	missing bool
}

func snapshotManagerIssueFiles(t *testing.T, paths []string) []managerIssueFileSnapshot {
	t.Helper()
	snapshots := make([]managerIssueFileSnapshot, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			snapshots = append(snapshots, managerIssueFileSnapshot{path: path, missing: true})
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		snapshots = append(snapshots, managerIssueFileSnapshot{path: path, data: data})
	}
	return snapshots
}

func assertManagerIssueFiles(t *testing.T, snapshots []managerIssueFileSnapshot) {
	t.Helper()
	for _, snapshot := range snapshots {
		data, err := os.ReadFile(snapshot.path)
		if snapshot.missing {
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing file %s was created: %v", snapshot.path, err)
			}
			continue
		}
		if err != nil || !bytes.Equal(data, snapshot.data) {
			t.Fatalf("file %s changed: %v", snapshot.path, err)
		}
	}
}

func receiveManagerIssueChange(t *testing.T, manager *Manager) CertificateChange {
	t.Helper()
	select {
	case change := <-manager.Changes():
		return change
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for certificate change")
		return CertificateChange{}
	}
}

func assertNoAdditionalManagerIssueChange(t *testing.T, manager *Manager) {
	t.Helper()
	select {
	case change := <-manager.Changes():
		t.Fatalf("unexpected additional change: %+v", change)
	default:
	}
}
