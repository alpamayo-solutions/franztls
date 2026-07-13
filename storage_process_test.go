package franztls

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
)

const (
	storageCrashHelperFlag       = "FRANZTLS_STORAGE_CRASH_HELPER"
	storageCrashHelperConfigPath = "FRANZTLS_STORAGE_CRASH_CONFIG"
	storageCrashReadyPrefix      = "franztls-storage-temp-synced:"
	storageTemporaryPrefix       = ".franztls-"
	storageTemporaryHexLength    = 24
	storageHelperTimeout         = 5 * time.Second
)

type storageCrashConfig struct {
	StateRoot       string `json:"state_root"`
	Destination     string `json:"destination"`
	ReplacementFile string `json:"replacement_file"`
}

// TestStorageCrashProcessHelper is entered only by the subprocess started by
// TestKilledWriterPreservesDestinationAndLockedWriteCleansStaleTemp. The sole
// environment parameter is a path to generated test configuration.
func TestStorageCrashProcessHelper(t *testing.T) {
	if os.Getenv(storageCrashHelperFlag) != "1" {
		return
	}
	if err := runStorageCrashHelper(os.Getenv(storageCrashHelperConfigPath)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "storage crash helper: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestKilledWriterPreservesDestinationAndLockedWriteCleansStaleTemp(t *testing.T) {
	material := newTestMaterial(
		t,
		testKeyRSA,
		testKeyPKCS1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	material.cfg.RenewBefore = 24 * time.Hour
	writeManagerIssueCA(t, material)
	accountKey, accountKeyPEM, priorAccount := writeManagerIssueAccount(t, material.cfg)
	cfg := material.cfg
	root := filepath.Dir(cfg.AccountKeyFile)
	store := newStateStore(cfg)
	priorBytes, err := os.ReadFile(cfg.AccountFile)
	if err != nil {
		t.Fatal(err)
	}
	assertPersistedAccount(t, cfg, priorAccount)

	replacementAccount := testACMEAccount("https://ca.test/acme/account/uncommitted")
	replacementBytes, err := json.Marshal(replacementAccount)
	if err != nil {
		t.Fatal(err)
	}
	inputRoot := t.TempDir()
	replacementPath := filepath.Join(inputRoot, "replacement-account.json")
	if err := os.WriteFile(replacementPath, replacementBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := writeStorageCrashConfig(t, inputRoot, storageCrashConfig{
		StateRoot:       root,
		Destination:     filepath.Base(cfg.AccountFile),
		ReplacementFile: replacementPath,
	})

	process := startStorageCrashHelper(t, configPath)
	waited := false
	defer func() {
		if !waited {
			killAndWaitStorageHelper(t, process)
		}
	}()

	temporaryName := waitForStorageCrashReadiness(t, process, &waited)
	if !isStorageTemporaryName(temporaryName) {
		t.Fatalf("crash helper temporary name = %q, want %s plus %d lowercase hex characters",
			temporaryName, storageTemporaryPrefix, storageTemporaryHexLength)
	}
	temporaryPath := filepath.Join(root, temporaryName)
	if info, err := os.Stat(temporaryPath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("synced temporary file = %v, %v, want regular file", info, err)
	}
	if synced, err := os.ReadFile(temporaryPath); err != nil || !bytes.Equal(synced, replacementBytes) {
		t.Fatalf("synced temporary bytes = %q, %v, want complete replacement", synced, err)
	}
	assertStorageAccountBytes(t, cfg, priorAccount, priorBytes)

	if err := process.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("kill storage crash helper: %v", err)
	}
	waitForKilledStorageHelper(t, process)
	waited = true
	assertStorageAccountBytes(t, cfg, priorAccount, priorBytes)
	if _, err := os.Stat(temporaryPath); err != nil {
		t.Fatalf("killed writer temporary file did not survive: %v", err)
	}

	preserved := map[string][]byte{
		"operator-notes.txt":                             []byte("arbitrary state-directory file"),
		storageTemporaryPrefix + strings.Repeat("0", 23): []byte("short prefix lookalike"),
		storageTemporaryPrefix + strings.Repeat("0", 25): []byte("long prefix lookalike"),
		storageTemporaryPrefix + strings.Repeat("A", 24): []byte("uppercase prefix lookalike"),
		storageTemporaryPrefix + strings.Repeat("g", 24): []byte("nonhex prefix lookalike"),
		".franztls.tmp": []byte("different prefix lookalike"),
	}
	for name, data := range preserved {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A normal state write without the package issue lock must not sweep
	// abandoned files created by a different process.
	if err := store.persistAccount(priorAccount); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temporaryPath); err != nil {
		t.Fatalf("unlocked write removed killed-writer temporary file: %v", err)
	}

	recorder := managerIssueRecorder(t, cfg, priorAccount)
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		return managerIssueChain(t, material, signer, nil), nil
	}
	factory := managerIssueFactory(t, accountKey, priorAccount, recorder)
	manager := newManagerForTest(t, cfg, fakeManagerClock{now: material.now}, factory)
	ctx, cancel := context.WithTimeout(context.Background(), storageHelperTimeout)
	defer cancel()
	change, err := manager.Ensure(ctx)
	if err != nil {
		t.Fatalf("Ensure() through real package issue lock: %v", err)
	}
	if !change.Renewed || !change.NotAfter.Equal(material.now.Add(72*time.Hour)) {
		t.Fatalf("Ensure() change = %+v, want successful initial issuance", change)
	}
	accounts, orders, closes := recorder.counts()
	if factory.callCount() != 1 || accounts != 1 || orders != 1 || closes != 1 {
		t.Fatalf("factory/account/order/close calls = %d/%d/%d/%d, want 1/1/1/1",
			factory.callCount(), accounts, orders, closes)
	}
	privateKeyPEM, keyErr := os.ReadFile(cfg.PrivateKeyFile)
	certificatePEM, certificateErr := os.ReadFile(cfg.CertificateFile)
	if keyErr != nil || certificateErr != nil {
		t.Fatalf("read issued material: %v / %v", keyErr, certificateErr)
	}
	if _, err := parseMaterial(
		certificatePEM,
		privateKeyPEM,
		material.roots,
		cfg,
		material.now,
	); err != nil {
		t.Fatalf("issued material is invalid: %v", err)
	}
	assertFileBytesAndMode(t, cfg.AccountKeyFile, accountKeyPEM, 0o600)
	assertPersistedAccount(t, cfg, priorAccount)
	if event := receiveManagerIssueChange(t, manager); event != change {
		t.Fatalf("issuance event = %+v, want %+v", event, change)
	}
	assertNoAdditionalManagerIssueChange(t, manager)

	for name, want := range preserved {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("preserved file %q: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("preserved file %q bytes = %q, want %q", name, got, want)
		}
	}
	if _, err := os.Stat(temporaryPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale package temporary file survived real locked Ensure: %v", err)
	}
}

type storageCrashDirectory struct {
	*stateDir
}

func (d *storageCrashDirectory) createTemp(prefix string) (atomicFile, string, error) {
	file, name, err := d.stateDir.createTemp(prefix)
	if err != nil {
		return nil, "", err
	}
	return &storageCrashFile{atomicFile: file, temporaryName: name}, name, nil
}

type storageCrashFile struct {
	atomicFile
	temporaryName string
}

func (f *storageCrashFile) Sync() error {
	if err := f.atomicFile.Sync(); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, storageCrashReadyPrefix+f.temporaryName); err != nil {
		return err
	}
	// The parent kills this process after receiving the readiness line. This is
	// exactly after the real file fsync and before atomicWrite can close or
	// rename the temporary file.
	select {}
}

func runStorageCrashHelper(configPath string) error {
	if configPath == "" {
		return errors.New("missing helper config path")
	}
	encoded, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var config storageCrashConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		return err
	}
	if !safeBaseName(config.Destination) {
		return fmt.Errorf("unsafe destination name %q", config.Destination)
	}
	replacement, err := os.ReadFile(config.ReplacementFile)
	if err != nil {
		return err
	}
	directory, err := openStateDir(config.StateRoot, false)
	if err != nil {
		return err
	}
	defer directory.close()
	return atomicWrite(
		&storageCrashDirectory{stateDir: directory},
		config.Destination,
		replacement,
		0o600,
	)
}

type storageHelperProcess struct {
	cmd    *exec.Cmd
	ready  <-chan storageHelperReadiness
	done   <-chan storageHelperExit
	stdout *storageLockedBuffer
	stderr *storageLockedBuffer
}

type storageHelperReadiness struct {
	temporaryName string
	err           error
}

type storageHelperExit struct {
	waitErr   error
	stdoutErr error
}

type storageLockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *storageLockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *storageLockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (process *storageHelperProcess) diagnostics() string {
	return fmt.Sprintf(
		"stdout:\n%s\nstderr:\n%s",
		process.stdout.String(),
		process.stderr.String(),
	)
}

func startStorageCrashHelper(t *testing.T, configPath string) *storageHelperProcess {
	t.Helper()
	cmd := exec.Command(
		os.Args[0],
		"-test.run=^TestStorageCrashProcessHelper$",
		"-test.count=1",
		"-test.timeout=10s",
	)
	cmd.Env = append(os.Environ(),
		storageCrashHelperFlag+"=1",
		storageCrashHelperConfigPath+"="+configPath,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutCapture := &storageLockedBuffer{}
	stderr := &storageLockedBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan storageHelperReadiness, 1)
	stdoutDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		readinessSent := false
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = stdoutCapture.Write([]byte(line + "\n"))
			if !readinessSent && strings.HasPrefix(line, storageCrashReadyPrefix) {
				ready <- storageHelperReadiness{
					temporaryName: strings.TrimPrefix(line, storageCrashReadyPrefix),
				}
				readinessSent = true
			}
		}
		scanErr := scanner.Err()
		if !readinessSent {
			ready <- storageHelperReadiness{
				err: errors.Join(errors.New("readiness marker not received"), scanErr),
			}
		}
		stdoutDone <- scanErr
	}()
	done := make(chan storageHelperExit, 1)
	go func() {
		stdoutErr := <-stdoutDone
		done <- storageHelperExit{waitErr: cmd.Wait(), stdoutErr: stdoutErr}
	}()
	return &storageHelperProcess{
		cmd:    cmd,
		ready:  ready,
		done:   done,
		stdout: stdoutCapture,
		stderr: stderr,
	}
}

func waitForStorageCrashReadiness(
	t *testing.T,
	process *storageHelperProcess,
	waited *bool,
) string {
	t.Helper()
	timer := time.NewTimer(storageHelperTimeout)
	defer timer.Stop()
	select {
	case readiness := <-process.ready:
		if readiness.err != nil || readiness.temporaryName == "" {
			t.Fatalf("storage crash helper readiness failed: %v\n%s",
				readiness.err, process.diagnostics())
		}
		return readiness.temporaryName
	case exit := <-process.done:
		*waited = true
		t.Fatalf("storage crash helper exited before readiness: wait=%v stdout=%v\n%s",
			exit.waitErr, exit.stdoutErr, process.diagnostics())
	case <-timer.C:
		killAndWaitStorageHelper(t, process)
		*waited = true
		t.Fatalf("storage crash helper readiness timed out\n%s", process.diagnostics())
	}
	return ""
}

func waitForKilledStorageHelper(t *testing.T, process *storageHelperProcess) {
	t.Helper()
	timer := time.NewTimer(storageHelperTimeout)
	defer timer.Stop()
	select {
	case exit := <-process.done:
		if exit.waitErr == nil {
			t.Fatalf("killed storage crash helper exited successfully\n%s", process.diagnostics())
		}
		if exit.stdoutErr != nil {
			t.Fatalf("storage crash helper stdout failed: %v\n%s",
				exit.stdoutErr, process.diagnostics())
		}
	case <-timer.C:
		t.Fatalf("storage crash helper did not exit after Kill\n%s", process.diagnostics())
	}
}

func killAndWaitStorageHelper(t *testing.T, process *storageHelperProcess) {
	t.Helper()
	if err := process.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("kill storage crash helper during cleanup: %v", err)
	}
	waitForKilledStorageHelper(t, process)
}

func writeStorageCrashConfig(t *testing.T, root string, config storageCrashConfig) string {
	t.Helper()
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "storage-crash-config.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func isStorageTemporaryName(name string) bool {
	if !strings.HasPrefix(name, storageTemporaryPrefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, storageTemporaryPrefix)
	if len(suffix) != storageTemporaryHexLength || suffix != strings.ToLower(suffix) {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}

func assertStorageAccountBytes(
	t *testing.T,
	cfg Config,
	wantAccount *acme.ExtendedAccount,
	wantBytes []byte,
) {
	t.Helper()
	got, err := os.ReadFile(cfg.AccountFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantBytes) {
		t.Fatalf("prior account bytes changed before rename: got %q, want %q", got, wantBytes)
	}
	if wantAccount == nil || wantAccount.Location == "" {
		t.Fatal("test account has no location")
	}
	// assertPersistedAccount checks the complete package account shape,
	// including the required nonempty Location, status, contact, and terms.
	assertPersistedAccount(t, cfg, wantAccount)
}
