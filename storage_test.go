package franztls

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAtomicWriteOrdersDurableOperations(t *testing.T) {
	directory := newRecordingAtomicDir([]byte("old"))
	if err := atomicWrite(directory, "account.key", []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"create-temp", "chmod-0600", "write", "file-sync", "close",
		"rename", "directory-sync",
	}
	if !slices.Equal(want, directory.operations) {
		t.Fatalf("atomic write order: want %q, got %q", want, directory.operations)
	}
	if got := string(directory.destination); got != "new" {
		t.Fatalf("destination = %q, want new", got)
	}
	if !directory.tempRemoved {
		t.Fatal("temporary file was not removed after rename")
	}
}

func TestAtomicWritePreservesDestinationBeforeRenameFailure(t *testing.T) {
	steps := []string{"create-temp", "chmod", "write", "file-sync", "close", "rename"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			directory := newRecordingAtomicDir([]byte("old"))
			directory.failAt = step
			err := atomicWrite(directory, "prekit-tls.key", []byte("new"), 0o600)
			if err == nil {
				t.Fatalf("atomicWrite succeeded with %s failure", step)
			}
			if got := string(directory.destination); got != "old" {
				t.Fatalf("destination = %q after %s failure, want old", got, step)
			}
			if !directory.tempRemoved && step != "create-temp" {
				t.Fatalf("temporary file survived %s failure", step)
			}
		})
	}
}

func TestAtomicWriteReportsDurabilityUncertainAfterRename(t *testing.T) {
	cause := errors.New("directory sync failed")
	directory := newRecordingAtomicDir([]byte("old"))
	directory.failAt = "directory-sync"
	directory.failure = cause

	err := atomicWrite(directory, "prekit-tls.pem", []byte("new"), 0o644)
	var uncertain *DurabilityUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("error = %T %v, want *DurabilityUncertainError", err, err)
	}
	if !errors.Is(err, cause) {
		t.Fatal("DurabilityUncertainError does not unwrap directory-sync failure")
	}
	if got := string(directory.destination); got != "new" {
		t.Fatalf("destination = %q, want possibly committed new bytes", got)
	}
	if uncertain.Path != filepath.Join(directory.root, "prekit-tls.pem") {
		t.Fatalf("uncertain path = %q", uncertain.Path)
	}
}

func TestAtomicWritePreservesDestinationOnShortWrite(t *testing.T) {
	directory := newRecordingAtomicDir([]byte("old"))
	directory.shortWrite = true
	err := atomicWrite(directory, "account.json", []byte("replacement"), 0o600)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v, want io.ErrShortWrite", err)
	}
	if got := string(directory.destination); got != "old" {
		t.Fatalf("destination = %q, want old", got)
	}
	if !directory.tempRemoved {
		t.Fatal("short-write temporary file survived")
	}
}

func TestStatePathCreatesDirectoryAndPersistsExactModes(t *testing.T) {
	root := filepath.Join(storageTempDir(t), "state")
	cfg := validConfig(root)
	store := newStateStore(cfg)

	writes := []struct {
		path string
		mode fs.FileMode
		data string
		kind string
	}{
		{cfg.AccountKeyFile, 0o600, "account-key", "account_key"},
		{cfg.AccountFile, 0o600, `{\"status\":\"valid\"}`, "account"},
		{cfg.PrivateKeyFile, 0o600, "domain-key", "private_key"},
		{cfg.CertificateFile, 0o644, "certificate", "certificate"},
	}
	for _, item := range writes {
		if err := store.writeFile(item.path, []byte(item.data), item.mode, item.kind); err != nil {
			t.Fatalf("write %s: %v", item.kind, err)
		}
		info, err := os.Stat(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != item.mode {
			t.Fatalf("%s mode = %#o, want %#o", item.kind, got, item.mode)
		}
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %#o, want 0700", got)
	}

	for _, item := range writes {
		got, err := store.readFile(item.path, item.mode, item.kind)
		if err != nil {
			t.Fatalf("read %s: %v", item.kind, err)
		}
		if string(got) != item.data {
			t.Fatalf("read %s = %q", item.kind, got)
		}
	}
}

func TestStatePathDoesNotCreateMissingAncestors(t *testing.T) {
	base := storageTempDir(t)
	missingParent := filepath.Join(base, "missing")
	stateRoot := filepath.Join(missingParent, "state")
	cfg := validConfig(stateRoot)
	err := newStateStore(cfg).writeFile(cfg.AccountFile, []byte(`{}`), 0o600, "account")
	if err == nil {
		t.Fatal("state write created missing ancestors")
	}
	if _, statErr := os.Stat(missingParent); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing parent was created: %v", statErr)
	}
}

func TestStatePathRejectsSymlinkedDirectoryAndFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on some Windows builders")
	}

	t.Run("state directory", func(t *testing.T) {
		root := storageTempDir(t)
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedDirectory := filepath.Join(root, "linked")
		if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
			t.Fatal(err)
		}
		cfg := validConfig(linkedDirectory)
		err := newStateStore(cfg).writeFile(cfg.AccountFile, []byte(`{}`), 0o600, "account")
		assertStateErrorKind(t, err, "unsafe_path")
	})

	t.Run("every configured file", func(t *testing.T) {
		root := storageTempDir(t)
		state := filepath.Join(root, "state")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		trust := filepath.Join(root, "trust")
		if err := os.Mkdir(trust, 0o700); err != nil {
			t.Fatal(err)
		}
		realFile := filepath.Join(root, "real")
		if err := os.WriteFile(realFile, []byte("secret target"), 0o600); err != nil {
			t.Fatal(err)
		}

		cfg := validConfig(state)
		cfg.CACertFile = filepath.Join(trust, "ca.pem")
		paths := []struct {
			name string
			path string
			mode fs.FileMode
		}{
			{"ca", cfg.CACertFile, 0o600},
			{"account key", cfg.AccountKeyFile, 0o600},
			{"account", cfg.AccountFile, 0o600},
			{"private key", cfg.PrivateKeyFile, 0o600},
			{"certificate", cfg.CertificateFile, 0o600},
		}
		for _, item := range paths {
			t.Run(item.name, func(t *testing.T) {
				if err := os.Symlink(realFile, item.path); err != nil {
					t.Fatal(err)
				}
				_, err := newStateStore(cfg).readFile(item.path, item.mode, item.name)
				assertStateErrorKind(t, err, "unsafe_path")
				if err := os.Remove(item.path); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(realFile)
				if err != nil || string(got) != "secret target" {
					t.Fatalf("symlink target changed: %q, %v", got, err)
				}
			})
		}
	})
}

func TestStatePathRejectsNonRegularAndWrongMode(t *testing.T) {
	root := storageTempDir(t)
	cfg := validConfig(root)
	store := newStateStore(cfg)

	if err := os.Mkdir(cfg.AccountFile, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := store.readFile(cfg.AccountFile, 0o600, "account")
	assertStateErrorKind(t, err, "not_regular")

	if err := os.Remove(cfg.AccountFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.AccountFile, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = store.readFile(cfg.AccountFile, 0o600, "account")
	assertStateErrorKind(t, err, "permissions")
}

func TestStatePathRejectsFIFOWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mkfifo is Unix-only")
	}
	root := storageTempDir(t)
	cfg := validConfig(root)
	if err := exec.Command("mkfifo", cfg.AccountFile).Run(); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := newStateStore(cfg).readFile(cfg.AccountFile, 0o600, "account")
		done <- err
	}()
	select {
	case err := <-done:
		assertStateErrorKind(t, err, "not_regular")
	case <-time.After(250 * time.Millisecond):
		// Unblock the old O_RDONLY behavior so the goroutine cannot leak after
		// this regression assertion fails.
		writer, openErr := os.OpenFile(cfg.AccountFile, os.O_WRONLY, 0)
		if openErr == nil {
			_ = writer.Close()
		}
		<-done
		t.Fatal("FIFO read blocked before file-type validation")
	}
}

func TestStatePathRejectsPermissiveExistingStateDirectory(t *testing.T) {
	root := storageTempDir(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := validConfig(root)
	err := newStateStore(cfg).writeFile(cfg.AccountFile, []byte(`{}`), 0o600, "account")
	assertStateErrorKind(t, err, "permissions")
}

func TestPersistReplacesSymlinkEntryWithoutWritingItsTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on some Windows builders")
	}
	root := storageTempDir(t)
	cfg := validConfig(root)
	target := filepath.Join(storageTempDir(t), "target")
	if err := os.WriteFile(target, []byte("target-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, cfg.AccountFile); err != nil {
		t.Fatal(err)
	}
	if err := newStateStore(cfg).writeFile(cfg.AccountFile, []byte(`{"new":true}`), 0o600, "account"); err != nil {
		t.Fatal(err)
	}
	targetBytes, err := os.ReadFile(target)
	if err != nil || string(targetBytes) != "target-secret" {
		t.Fatalf("symlink target changed: %q, %v", targetBytes, err)
	}
	info, err := os.Lstat(cfg.AccountFile)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("destination mode = %v, want regular file", info.Mode())
	}
}

func TestStateDirectoryDescriptorSurvivesPathSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory rename semantics differ on Windows")
	}
	root := storageTempDir(t)
	statePath := filepath.Join(root, "state")
	directory, err := openStateDir(statePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()

	originalPath := filepath.Join(root, "original")
	if err := os.Rename(statePath, originalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := directory.atomicWrite("account.json", []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(originalPath, "account.json"))
	if err != nil || string(got) != "original" {
		t.Fatalf("descriptor target = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(statePath, "account.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory was written: %v", err)
	}
}

func TestGeneratedRSAKeyIs2048BitPKCS1PEM(t *testing.T) {
	key, encoded, err := generateRSAKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 2048 {
		t.Fatalf("RSA bits = %d, want 2048", key.N.BitLen())
	}
	block, rest := decodeSinglePEMForTest(t, encoded)
	if block.Type != "RSA PRIVATE KEY" || len(rest) != 0 {
		t.Fatalf("PEM type/rest = %q/%q", block.Type, rest)
	}
	parsed, err := parsePrivateKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeysEqual(key.Public(), parsed.Public()) {
		t.Fatal("generated key changed during PKCS#1 round trip")
	}
}

func TestAccountStateGeneratesMissingRSA2048PKCS1KeyWithoutWriting(t *testing.T) {
	cfg := validConfig(storageTempDir(t))
	state, err := newStateStore(cfg).loadAccountState()
	if err != nil {
		t.Fatal(err)
	}
	key, ok := state.accountKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("account key = %T, want *rsa.PrivateKey", state.accountKey)
	}
	if key.N.BitLen() != 2048 {
		t.Fatalf("RSA bits = %d, want 2048", key.N.BitLen())
	}
	block, rest := decodeSinglePEMForTest(t, state.accountKeyPEM)
	if block.Type != "RSA PRIVATE KEY" || len(rest) != 0 {
		t.Fatalf("account key PEM type/rest = %q/%q", block.Type, rest)
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatalf("parse generated PKCS#1 account key: %v", err)
	}
	if state.accountKeyExisted {
		t.Fatal("generated account key marked as existing")
	}
	if state.account != nil {
		t.Fatalf("generated account state unexpectedly loaded account: %+v", state.account)
	}
	if _, err := os.Stat(cfg.AccountKeyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only account preparation wrote key: %v", err)
	}
}

func TestAccountStateReusesExistingRSAKeyByteForByte(t *testing.T) {
	cfg := validConfig(storageTempDir(t))
	key := newTestRSAAccountKey(t)
	encoded := encodeTestPrivateKey(t, key, testKeyPKCS1)
	store := newStateStore(cfg)
	if err := store.writeFile(cfg.AccountKeyFile, encoded, 0o600, "account_key"); err != nil {
		t.Fatal(err)
	}

	state, err := store.loadAccountState()
	if err != nil {
		t.Fatal(err)
	}
	if !state.accountKeyExisted {
		t.Fatal("existing account key marked as generated")
	}
	if !bytes.Equal(state.accountKeyPEM, encoded) {
		t.Fatal("existing account key encoding changed")
	}
	if !publicKeysEqual(state.accountKey.Public(), key.Public()) {
		t.Fatal("existing account key changed while loading")
	}
	assertFileBytesAndMode(t, cfg.AccountKeyFile, encoded, 0o600)
}

func TestAccountStateLoadsExistingAccountAndAllowsKeyRecovery(t *testing.T) {
	for _, test := range []struct {
		name        string
		writeRecord bool
	}{
		{name: "existing account", writeRecord: true},
		{name: "missing account recovered later", writeRecord: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig(storageTempDir(t))
			store := newStateStore(cfg)
			keyPEM := encodeTestPrivateKey(t, newTestRSAAccountKey(t), testKeyPKCS1)
			if err := store.writeFile(cfg.AccountKeyFile, keyPEM, 0o600, "account_key"); err != nil {
				t.Fatal(err)
			}
			account := testACMEAccount("https://ca.test/acme/account/storage")
			if test.writeRecord {
				if err := store.persistAccount(account); err != nil {
					t.Fatal(err)
				}
			}

			state, err := store.loadAccountState()
			if err != nil {
				t.Fatal(err)
			}
			if test.writeRecord {
				if state.account == nil || state.account.Location != account.Location {
					t.Fatalf("loaded account = %+v, want location %q", state.account, account.Location)
				}
				assertPersistedAccount(t, cfg, account)
			} else if state.account != nil {
				t.Fatalf("missing account file loaded account: %+v", state.account)
			}
		})
	}
}

func TestAccountStateCorruptionNeverCreatesReplacementIdentity(t *testing.T) {
	validKey := encodeTestPrivateKey(t, newTestRSAAccountKey(t), testKeyPKCS1)
	validAccount := testACMEAccount("https://ca.test/acme/account/valid")
	tests := []struct {
		name      string
		prepare   func(*testing.T, Config, *stateStore)
		wantKind  string
		unchanged func(*testing.T, Config)
	}{
		{
			name: "corrupt account key",
			prepare: func(t *testing.T, cfg Config, store *stateStore) {
				t.Helper()
				if err := store.writeFile(cfg.AccountKeyFile, []byte("corrupt-private-key"), 0o600, "account_key"); err != nil {
					t.Fatal(err)
				}
			},
			wantKind: "account_key",
			unchanged: func(t *testing.T, cfg Config) {
				assertFileBytesAndMode(t, cfg.AccountKeyFile, []byte("corrupt-private-key"), 0o600)
			},
		},
		{
			name: "corrupt account JSON",
			prepare: func(t *testing.T, cfg Config, store *stateStore) {
				t.Helper()
				if err := store.writeFile(cfg.AccountKeyFile, validKey, 0o600, "account_key"); err != nil {
					t.Fatal(err)
				}
				if err := store.writeFile(cfg.AccountFile, []byte("not-json "+acmeSecretAccount), 0o600, "account"); err != nil {
					t.Fatal(err)
				}
			},
			wantKind: "account",
			unchanged: func(t *testing.T, cfg Config) {
				assertFileBytesAndMode(t, cfg.AccountKeyFile, validKey, 0o600)
				assertFileBytesAndMode(t, cfg.AccountFile, []byte("not-json "+acmeSecretAccount), 0o600)
			},
		},
		{
			name: "account JSON without matching key",
			prepare: func(t *testing.T, _ Config, store *stateStore) {
				t.Helper()
				if err := store.persistAccount(validAccount); err != nil {
					t.Fatal(err)
				}
			},
			wantKind: "account_state",
			unchanged: func(t *testing.T, cfg Config) {
				assertPersistedAccount(t, cfg, validAccount)
				if _, err := os.Stat(cfg.AccountKeyFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("replacement account key was created: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig(storageTempDir(t))
			store := newStateStore(cfg)
			test.prepare(t, cfg, store)
			_, err := store.loadAccountState()
			assertStateErrorKind(t, err, test.wantKind)
			test.unchanged(t, cfg)
		})
	}
}

func TestPersistRejectsInvalidMaterialBeforeAnyWrite(t *testing.T) {
	root := storageTempDir(t)
	cfg := validConfig(root)
	oldKey := []byte("old-private-key")
	oldCertificate := []byte("old-certificate")
	if err := os.WriteFile(cfg.PrivateKeyFile, oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.CertificateFile, oldCertificate, 0o644); err != nil {
		t.Fatal(err)
	}
	material := newTestMaterial(
		t,
		testKeyRSA,
		testKeyPKCS1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	_, err := newStateStore(cfg).persistMaterial(
		[]byte("not certificate PEM"),
		material.leafKey,
		material.roots,
		material.now,
	)
	if err == nil {
		t.Fatal("invalid material was persisted")
	}
	assertFileBytesAndMode(t, cfg.PrivateKeyFile, oldKey, 0o600)
	assertFileBytesAndMode(t, cfg.CertificateFile, oldCertificate, 0o644)
	assertNoStorageTemps(t, root)
}

func TestPersistValidatedMaterialUsesCompatibleKeyEncoding(t *testing.T) {
	root := storageTempDir(t)
	cfg := validConfig(root)
	material := newTestMaterial(
		t,
		testKeyRSA,
		testKeyPKCS1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	persisted, err := newStateStore(cfg).persistMaterial(
		material.certificatePEM,
		material.leafKey,
		material.roots,
		material.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.leaf.NotAfter.Equal(material.leaf.NotAfter) {
		t.Fatalf("persisted NotAfter = %v", persisted.leaf.NotAfter)
	}
	keyPEM, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("persisted key PEM type/rest = %v/%q", block, rest)
	}
	assertFileBytesAndMode(t, cfg.PrivateKeyFile, keyPEM, 0o600)
	assertFileBytesAndMode(t, cfg.CertificateFile, material.certificatePEM, 0o644)
	if _, err := parseMaterial(material.certificatePEM, keyPEM, material.roots, cfg, material.now); err != nil {
		t.Fatalf("persisted material is not reload-compatible: %v", err)
	}
}

func assertStateErrorKind(t *testing.T, err error, kind string) {
	t.Helper()
	var stateErr *StateError
	if !errors.As(err, &stateErr) {
		t.Fatalf("error = %T %v, want *StateError", err, err)
	}
	if stateErr.Kind != kind {
		t.Fatalf("StateError.Kind = %q, want %q", stateErr.Kind, kind)
	}
}

type recordingAtomicDir struct {
	root        string
	destination []byte
	temporary   []byte
	operations  []string
	failAt      string
	failure     error
	tempRemoved bool
	shortWrite  bool
}

func newRecordingAtomicDir(destination []byte) *recordingAtomicDir {
	return &recordingAtomicDir{
		root:        filepath.Join(string(filepath.Separator), "state"),
		destination: bytes.Clone(destination),
		failure:     errors.New("injected failure"),
	}
}

func (d *recordingAtomicDir) createTemp(string) (atomicFile, string, error) {
	d.operations = append(d.operations, "create-temp")
	if d.failAt == "create-temp" {
		return nil, "", d.failure
	}
	return &recordingAtomicFile{directory: d}, ".franztls-test", nil
}

func (d *recordingAtomicDir) remove(string) error {
	d.tempRemoved = true
	return nil
}

func (d *recordingAtomicDir) rename(_, _ string) error {
	d.operations = append(d.operations, "rename")
	if d.failAt == "rename" {
		return d.failure
	}
	d.destination = bytes.Clone(d.temporary)
	return nil
}

func (d *recordingAtomicDir) sync() error {
	d.operations = append(d.operations, "directory-sync")
	if d.failAt == "directory-sync" {
		return d.failure
	}
	return nil
}

func (d *recordingAtomicDir) path(name string) string {
	return filepath.Join(d.root, name)
}

type recordingAtomicFile struct {
	directory *recordingAtomicDir
}

func (f *recordingAtomicFile) Chmod(mode fs.FileMode) error {
	f.directory.operations = append(f.directory.operations, fmt.Sprintf("chmod-%04o", mode.Perm()))
	if f.directory.failAt == "chmod" {
		return f.directory.failure
	}
	return nil
}

func (f *recordingAtomicFile) Write(data []byte) (int, error) {
	f.directory.operations = append(f.directory.operations, "write")
	if f.directory.failAt == "write" {
		return 0, f.directory.failure
	}
	f.directory.temporary = append(f.directory.temporary, data...)
	if f.directory.shortWrite {
		return len(data) - 1, nil
	}
	return len(data), nil
}

func (f *recordingAtomicFile) Sync() error {
	f.directory.operations = append(f.directory.operations, "file-sync")
	if f.directory.failAt == "file-sync" {
		return f.directory.failure
	}
	return nil
}

func (f *recordingAtomicFile) Close() error {
	f.directory.operations = append(f.directory.operations, "close")
	if f.directory.failAt == "close" {
		return f.directory.failure
	}
	return nil
}

func decodeSinglePEMForTest(t *testing.T, encoded []byte) (*pemBlock, []byte) {
	t.Helper()
	block, rest := decodePEM(encoded)
	if block == nil {
		t.Fatal("generated key is not PEM")
	}
	return block, rest
}

// Small aliases keep the RED test focused on storage API symbols rather than
// duplicating encoding/pem plumbing in every assertion.
type pemBlock = pem.Block

func decodePEM(encoded []byte) (*pem.Block, []byte) {
	return pem.Decode(encoded)
}

func publicKeysEqual(left, right any) bool {
	leftBytes, leftErr := x509.MarshalPKIXPublicKey(left)
	rightBytes, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func TestStorageErrorsNeverContainFileContents(t *testing.T) {
	secret := "do-not-leak-private-key-material"
	root := storageTempDir(t)
	cfg := validConfig(root)
	if err := os.WriteFile(cfg.PrivateKeyFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := newStateStore(cfg).readFile(cfg.PrivateKeyFile, 0o644, "private_key")
	if err == nil {
		t.Fatal("wrong-mode read unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error exposed file contents: %v", err)
	}
}

func storageTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	realDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	return realDirectory
}

func assertFileBytesAndMode(t *testing.T, path string, want []byte, mode fs.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s bytes = %q, want %q", path, got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode.Perm() {
		t.Fatalf("%s mode = %#o, want %#o", path, info.Mode().Perm(), mode.Perm())
	}
}

func assertNoStorageTemps(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".franztls-") {
			t.Fatalf("temporary state file survived: %s", entry.Name())
		}
	}
}
