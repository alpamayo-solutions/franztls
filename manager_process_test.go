package franztls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
)

const (
	processHelperEnvironment = "FRANZTLS_PROCESS_HELPER"
	processHelperConfigEnv   = "FRANZTLS_HELPER_CONFIG"
	processHelperOuterLimit  = 15 * time.Second
)

type processHelperConfig struct {
	Mode              string        `json:"mode"`
	Config            Config        `json:"config"`
	RootKeyFile       string        `json:"root_key_file,omitempty"`
	OrderCountFile    string        `json:"order_count_file,omitempty"`
	OrderReadyFile    string        `json:"order_ready_file,omitempty"`
	OrderReleaseFile  string        `json:"order_release_file,omitempty"`
	LockBlockedFile   string        `json:"lock_blocked_file,omitempty"`
	ReadyFile         string        `json:"ready_file,omitempty"`
	StartFile         string        `json:"start_file,omitempty"`
	CancelFile        string        `json:"cancel_file,omitempty"`
	ReleaseFile       string        `json:"release_file,omitempty"`
	AcquiredFile      string        `json:"acquired_file,omitempty"`
	ExpectedStateKind string        `json:"expected_state_kind,omitempty"`
	Goroutines        int           `json:"goroutines,omitempty"`
	OperationTimeout  time.Duration `json:"operation_timeout,omitempty"`
}

type processFixture struct {
	cfg         Config
	stateRoot   string
	coordRoot   string
	rootKeyFile string
	root        *x509.Certificate
	material    *testMaterial
}

type processEnsureResult struct {
	change CertificateChange
	err    error
}

type runningProcessHelper struct {
	command *exec.Cmd
	output  bytes.Buffer
	done    chan struct{}
	waitErr error
	timer   *time.Timer
}

type processIssuerFactory struct {
	cfg              Config
	root             *x509.Certificate
	rootKey          crypto.Signer
	orderCountFile   string
	orderReadyFile   string
	orderReleaseFile string
}

type processIssuer struct {
	cfg              Config
	root             *x509.Certificate
	rootKey          crypto.Signer
	orderCountFile   string
	orderReadyFile   string
	orderReleaseFile string
}

func TestProcessHelper(t *testing.T) {
	if os.Getenv(processHelperEnvironment) != "1" {
		return
	}
	os.Exit(runProcessHelper(os.Getenv(processHelperConfigEnv)))
}

func helperCommand(t *testing.T, configPath string) *exec.Cmd {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	command.Env = processHelperEnvironmentFor(configPath)
	return command
}

func processHelperEnvironmentFor(configPath string) []string {
	environment := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, processHelperEnvironment+"=") ||
			strings.HasPrefix(entry, processHelperConfigEnv+"=") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(
		environment,
		processHelperEnvironment+"=1",
		processHelperConfigEnv+"="+configPath,
	)
}

func startProcessHelper(t *testing.T, configPath string) *runningProcessHelper {
	t.Helper()
	process := &runningProcessHelper{
		command: helperCommand(t, configPath),
		done:    make(chan struct{}),
	}
	process.command.Stdout = &process.output
	process.command.Stderr = &process.output
	if err := process.command.Start(); err != nil {
		t.Fatalf("start process helper: %v", err)
	}
	process.timer = time.AfterFunc(processHelperOuterLimit, func() {
		_ = process.command.Process.Kill()
	})
	go func() {
		process.waitErr = process.command.Wait()
		process.timer.Stop()
		close(process.done)
	}()
	t.Cleanup(process.stop)
	return process
}

func (process *runningProcessHelper) stop() {
	select {
	case <-process.done:
		return
	default:
	}
	_ = process.command.Process.Kill()
	<-process.done
}

func (process *runningProcessHelper) killAndReap() error {
	select {
	case <-process.done:
		return fmt.Errorf("process exited before kill: %v\n%s", process.waitErr, process.output.String())
	default:
	}
	killErr := process.command.Process.Kill()
	<-process.done
	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		return fmt.Errorf("kill process helper: %w", killErr)
	}
	return nil
}

func (process *runningProcessHelper) wait(timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-process.done:
		if process.waitErr != nil {
			return fmt.Errorf("process helper failed: %w\n%s", process.waitErr, process.output.String())
		}
		return nil
	case <-timer.C:
		_ = process.command.Process.Kill()
		<-process.done
		return fmt.Errorf("process helper timed out after %v\n%s", timeout, process.output.String())
	}
}

func (process *runningProcessHelper) waitForFile(path string, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat readiness file %s: %w", path, err)
		}
		select {
		case <-process.done:
			return fmt.Errorf(
				"process helper exited before readiness %s: %v\n%s",
				path,
				process.waitErr,
				process.output.String(),
			)
		case <-timer.C:
			_ = process.command.Process.Kill()
			<-process.done
			return fmt.Errorf(
				"process helper did not create readiness %s within %v\n%s",
				path,
				timeout,
				process.output.String(),
			)
		case <-ticker.C:
		}
	}
}

func waitForProcessHelpersFile(
	processes []*runningProcessHelper,
	path string,
	timeout time.Duration,
) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat process signal %s: %w", path, err)
		}
		for index, process := range processes {
			select {
			case <-process.done:
				return fmt.Errorf(
					"process helper %d exited before signal %s: %v\n%s",
					index,
					path,
					process.waitErr,
					process.output.String(),
				)
			default:
			}
		}
		select {
		case <-timer.C:
			var diagnostics strings.Builder
			for index, process := range processes {
				process.stop()
				_, _ = fmt.Fprintf(
					&diagnostics,
					"\nprocess %d: %v\n%s",
					index,
					process.waitErr,
					process.output.String(),
				)
			}
			return fmt.Errorf(
				"process helpers did not create signal %s within %v%s",
				path,
				timeout,
				diagnostics.String(),
			)
		case <-ticker.C:
		}
	}
}

func assertProcessHelpersRunning(t *testing.T, processes []*runningProcessHelper) {
	t.Helper()
	for index, process := range processes {
		select {
		case <-process.done:
			t.Fatalf(
				"process helper %d exited before overlap proof: %v\n%s",
				index,
				process.waitErr,
				process.output.String(),
			)
		default:
		}
	}
}

func readProcessPIDSignal(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		t.Fatalf("process PID signal %s = %q: %v", path, data, err)
	}
	return pid
}

func assertProcessPIDIsChild(
	t *testing.T,
	processes []*runningProcessHelper,
	pid int,
) {
	t.Helper()
	for _, process := range processes {
		if process.command.Process.Pid == pid {
			return
		}
	}
	t.Fatalf("signal PID %d does not identify a process helper", pid)
}

func runProcessHelper(configPath string) int {
	if configPath == "" {
		return processHelperErrorf("missing helper config path")
	}
	encoded, err := os.ReadFile(configPath)
	if err != nil {
		return processHelperErrorf("read helper config: %v", err)
	}
	var helper processHelperConfig
	if err := json.Unmarshal(encoded, &helper); err != nil {
		return processHelperErrorf("decode helper config: %v", err)
	}
	if helper.OperationTimeout <= 0 {
		helper.OperationTimeout = 10 * time.Second
	}

	switch helper.Mode {
	case "ensure":
		return runProcessEnsure(helper)
	case "cancel_ensure":
		return runProcessCanceledEnsure(helper)
	case "acquire_lock":
		return runProcessAcquireLock(helper)
	case "descriptor_lock":
		return runProcessDescriptorLock(helper)
	default:
		return processHelperErrorf("unknown helper mode %q", helper.Mode)
	}
}

func runProcessEnsure(helper processHelperConfig) int {
	manager, err := newProcessManager(helper)
	if err != nil {
		return processHelperErrorf("construct process manager: %v", err)
	}
	contentionError, err := configureProcessLockContention(
		manager,
		helper.LockBlockedFile,
		nil,
	)
	if err != nil {
		return processHelperErrorf("configure process lock contention: %v", err)
	}
	workers := helper.Goroutines
	if workers < 1 {
		workers = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), helper.OperationTimeout)
	defer cancel()
	start := make(chan struct{})
	results := make(chan processEnsureResult, workers)
	for index := 0; index < workers; index++ {
		go func() {
			<-start
			change, ensureErr := manager.Ensure(ctx)
			results <- processEnsureResult{change: change, err: ensureErr}
		}()
	}
	if err := writeProcessSignal(helper.ReadyFile); err != nil {
		cancel()
		close(start)
		return processHelperErrorf("write ensure readiness: %v", err)
	}
	if err := waitForProcessSignal(helper.StartFile, helper.OperationTimeout); err != nil {
		cancel()
		close(start)
		return processHelperErrorf("wait for ensure start: %v", err)
	}
	close(start)

	renewed := 0
	var notAfter time.Time
	for index := 0; index < workers; index++ {
		result := <-results
		if result.err != nil {
			return processHelperErrorf("Ensure worker %d: %v", index, result.err)
		}
		if result.change.Renewed {
			renewed++
		}
		if result.change.NotAfter.IsZero() {
			return processHelperErrorf("Ensure worker %d returned zero NotAfter", index)
		}
		if notAfter.IsZero() {
			notAfter = result.change.NotAfter
		} else if !notAfter.Equal(result.change.NotAfter) {
			return processHelperErrorf(
				"Ensure worker %d NotAfter %v differs from %v",
				index,
				result.change.NotAfter,
				notAfter,
			)
		}
	}
	if renewed > 1 {
		return processHelperErrorf("process renewed %d times, want at most one", renewed)
	}
	if err := contentionError(); err != nil {
		return processHelperErrorf("publish lock contention: %v", err)
	}
	return 0
}

func runProcessCanceledEnsure(helper processHelperConfig) int {
	manager, err := newProcessManager(helper)
	if err != nil {
		return processHelperErrorf("construct canceled process manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	contentionError, err := configureProcessLockContention(
		manager,
		helper.ReadyFile,
		cancel,
	)
	if err != nil {
		return processHelperErrorf("configure canceled lock contention: %v", err)
	}
	cancelSignal := make(chan error, 1)
	go func() {
		cancelSignal <- waitForProcessSignal(helper.CancelFile, helper.OperationTimeout)
		cancel()
	}()
	_, err = manager.Ensure(ctx)
	if signalErr := <-cancelSignal; signalErr != nil {
		return processHelperErrorf("wait for cancellation signal: %v", signalErr)
	}
	if err := contentionError(); err != nil {
		return processHelperErrorf("publish canceled lock contention: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		return processHelperErrorf("canceled Ensure error = %T %v", err, err)
	}
	return 0
}

func configureProcessLockContention(
	manager *Manager,
	path string,
	onError func(),
) (func() error, error) {
	lock, ok := manager.lock.(*fileIssueLock)
	if !ok {
		return nil, fmt.Errorf("manager lock = %T, want *fileIssueLock", manager.lock)
	}
	var once sync.Once
	var signalErr error
	lock.onContention = func() {
		once.Do(func() {
			signalErr = writeProcessPIDSignal(path)
			if signalErr != nil && onError != nil {
				onError()
			}
		})
	}
	return func() error { return signalErr }, nil
}

func runProcessAcquireLock(helper processHelperConfig) int {
	cfg, err := normalizeConfig(helper.Config)
	if err != nil {
		return processHelperErrorf("normalize lock config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), helper.OperationTimeout)
	defer cancel()
	release, err := newIssueLock(cfg).Acquire(ctx)
	if helper.ExpectedStateKind != "" {
		if err == nil {
			_ = release()
			return processHelperErrorf(
				"lock acquisition succeeded, want StateError kind %q",
				helper.ExpectedStateKind,
			)
		}
		var stateErr *StateError
		if !errors.As(err, &stateErr) || stateErr.Kind != helper.ExpectedStateKind {
			return processHelperErrorf(
				"lock error = %T %v, want StateError kind %q",
				err,
				err,
				helper.ExpectedStateKind,
			)
		}
		return 0
	}
	if err != nil {
		return processHelperErrorf("acquire lock: %v", err)
	}
	if err := writeProcessSignal(helper.ReadyFile); err != nil {
		_ = release()
		return processHelperErrorf("write lock readiness: %v", err)
	}
	if helper.ReleaseFile != "" {
		if err := waitForProcessSignal(helper.ReleaseFile, helper.OperationTimeout); err != nil {
			_ = release()
			return processHelperErrorf("wait for lock release: %v", err)
		}
	}
	if err := release(); err != nil {
		return processHelperErrorf("release lock: %v", err)
	}
	return 0
}

func runProcessDescriptorLock(helper processHelperConfig) int {
	cfg, err := normalizeConfig(helper.Config)
	if err != nil {
		return processHelperErrorf("normalize descriptor-lock config: %v", err)
	}
	issue := newIssueLock(cfg)
	lock, ok := issue.(*fileIssueLock)
	if !ok {
		return processHelperErrorf("descriptor lock = %T, want *fileIssueLock", issue)
	}
	var hookErr error
	lock.afterDescriptorValidated = func() {
		if err := writeProcessSignal(helper.ReadyFile); err != nil {
			hookErr = err
			return
		}
		hookErr = waitForProcessSignal(helper.StartFile, helper.OperationTimeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), helper.OperationTimeout)
	defer cancel()
	release, err := lock.Acquire(ctx)
	if hookErr != nil {
		if release != nil {
			_ = release()
		}
		return processHelperErrorf("descriptor hook: %v", hookErr)
	}
	if err != nil {
		return processHelperErrorf("acquire validated descriptor: %v", err)
	}
	if err := writeProcessSignal(helper.AcquiredFile); err != nil {
		_ = release()
		return processHelperErrorf("write descriptor acquired signal: %v", err)
	}
	if err := waitForProcessSignal(helper.ReleaseFile, helper.OperationTimeout); err != nil {
		_ = release()
		return processHelperErrorf("wait descriptor release: %v", err)
	}
	if err := release(); err != nil {
		return processHelperErrorf("release validated descriptor: %v", err)
	}
	return 0
}

func newProcessManager(helper processHelperConfig) (*Manager, error) {
	cfg, err := normalizeConfig(helper.Config)
	if err != nil {
		return nil, err
	}
	factory, err := newProcessIssuerFactory(
		cfg,
		helper.RootKeyFile,
		helper.OrderCountFile,
		helper.OrderReadyFile,
		helper.OrderReleaseFile,
	)
	if err != nil {
		return nil, err
	}
	return newManager(cfg, wallClock{}, factory), nil
}

func newProcessIssuerFactory(
	cfg Config,
	rootKeyFile string,
	orderCountFile string,
	orderReadyFile string,
	orderReleaseFile string,
) (*processIssuerFactory, error) {
	keyPEM, err := os.ReadFile(rootKeyFile)
	if err != nil {
		return nil, err
	}
	rootKey, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	rootPEM, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, err
	}
	roots, _, err := parseCertificateChain(rootPEM)
	if err != nil || len(roots) != 1 || !roots[0].IsCA {
		return nil, errors.New("invalid process-helper CA")
	}
	if !samePublicKey(rootKey.Public(), roots[0].PublicKey) {
		return nil, errors.New("process-helper CA key mismatch")
	}
	return &processIssuerFactory{
		cfg:              cfg,
		root:             roots[0],
		rootKey:          rootKey,
		orderCountFile:   orderCountFile,
		orderReadyFile:   orderReadyFile,
		orderReleaseFile: orderReleaseFile,
	}, nil
}

func (factory *processIssuerFactory) New(
	_ context.Context,
	cfg normalizedConfig,
	_ *x509.CertPool,
	_ crypto.Signer,
	_ *acme.ExtendedAccount,
) (issuer, error) {
	if cfg.Domain != factory.cfg.Domain {
		return nil, errors.New("process-helper config changed")
	}
	return &processIssuer{
		cfg:              cfg,
		root:             factory.root,
		rootKey:          factory.rootKey,
		orderCountFile:   factory.orderCountFile,
		orderReadyFile:   factory.orderReadyFile,
		orderReleaseFile: factory.orderReleaseFile,
	}, nil
}

func (issuer *processIssuer) EnsureAccount(
	_ context.Context,
	_ crypto.Signer,
	account *acme.ExtendedAccount,
) (*acme.ExtendedAccount, error) {
	if account == nil {
		account = testACMEAccount("https://ca.test/acme/account/process-helper")
	}
	if err := newStateStore(issuer.cfg).persistAccount(account); err != nil {
		return nil, err
	}
	return account, nil
}

func (issuer *processIssuer) Obtain(
	ctx context.Context,
	domainKey crypto.Signer,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := appendProcessOrder(issuer.orderCountFile); err != nil {
		return nil, err
	}
	if err := writeProcessPIDSignal(issuer.orderReadyFile); err != nil {
		return nil, err
	}
	if err := waitForProcessSignal(issuer.orderReleaseFile, 10*time.Second); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{},
		DNSNames:     []string{issuer.cfg.Domain},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(72 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		issuer.root,
		domainKey.Public(),
		issuer.rootKey,
	)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (*processIssuer) Close(context.Context) error {
	return nil
}

func appendProcessOrder(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintf(file, "%d\n", os.Getpid())
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

func processHelperErrorf(format string, arguments ...any) int {
	_, _ = fmt.Fprintf(os.Stderr, "franztls process helper: "+format+"\n", arguments...)
	return 1
}

func writeProcessSignal(path string) error {
	if path == "" {
		return nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}

func writeProcessPIDSignal(path string) error {
	if path == "" {
		return nil
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".franztls-process-signal-*")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	keepTemporary := true
	defer func() {
		if keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	chmodErr := file.Chmod(0o600)
	_, writeErr := fmt.Fprintf(file, "%d\n", os.Getpid())
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(chmodErr, writeErr, syncErr, closeErr); err != nil {
		return err
	}
	// Each PID signal has exactly one protocol-designated writer. Checking the
	// destination before rename preserves the O_EXCL contract while still
	// publishing only a complete, synced PID file.
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("process PID signal already exists: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	keepTemporary = false
	return nil
}

func waitForProcessSignal(path string, timeout time.Duration) error {
	if path == "" {
		return nil
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for %s", path)
		case <-ticker.C:
		}
	}
}

func newProcessFixture(t *testing.T) *processFixture {
	t.Helper()
	base := storageTempDir(t)
	trustRoot := filepath.Join(base, "trust")
	coordRoot := filepath.Join(base, "coord")
	for _, directory := range []string{trustRoot, coordRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stateRoot := filepath.Join(base, "state")
	cfg := validConfig(stateRoot)
	cfg.CACertFile = filepath.Join(trustRoot, "prekit-ca.crt")
	cfg.RenewBefore = 24 * time.Hour

	material := newTestMaterial(
		t,
		testKeyRSA,
		testKeyPKCS1,
		false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	root := newTestRoot(t, "franztls process root", time.Now())
	if err := os.WriteFile(
		cfg.CACertFile,
		encodeTestCertificateChain(t, root.der),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	rootKeyFile := filepath.Join(trustRoot, "process-root.key")
	rootKeyPEM, err := marshalSignerPEM(root.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootKeyFile, rootKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return &processFixture{
		cfg:         cfg,
		stateRoot:   stateRoot,
		coordRoot:   coordRoot,
		rootKeyFile: rootKeyFile,
		root:        root.certificate,
		material:    material,
	}
}

func (fixture *processFixture) helper(mode string) processHelperConfig {
	return processHelperConfig{
		Mode:             mode,
		Config:           fixture.cfg,
		RootKeyFile:      fixture.rootKeyFile,
		OrderCountFile:   filepath.Join(fixture.coordRoot, "orders"),
		OperationTimeout: 10 * time.Second,
	}
}

func writeProcessHelperConfig(
	t *testing.T,
	fixture *processFixture,
	name string,
	helper processHelperConfig,
) string {
	t.Helper()
	encoded, err := json.Marshal(helper)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.coordRoot, name+".json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeProcessSignalForTest(t *testing.T, path string) {
	t.Helper()
	if err := writeProcessSignal(path); err != nil {
		t.Fatal(err)
	}
}

func assertProcessFileUnchanged(
	t *testing.T,
	path string,
	wantContents []byte,
	wantInfo os.FileInfo,
) {
	t.Helper()
	gotContents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotContents, wantContents) {
		t.Fatalf("file %s contents changed: %q", path, gotContents)
	}
	gotInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(wantInfo, gotInfo) {
		t.Fatalf("file %s was replaced", path)
	}
	if gotInfo.Mode() != wantInfo.Mode() ||
		gotInfo.Size() != wantInfo.Size() ||
		!gotInfo.ModTime().Equal(wantInfo.ModTime()) {
		t.Fatalf(
			"file %s metadata changed: mode=%v size=%d mtime=%v; want mode=%v size=%d mtime=%v",
			path,
			gotInfo.Mode(),
			gotInfo.Size(),
			gotInfo.ModTime(),
			wantInfo.Mode(),
			wantInfo.Size(),
			wantInfo.ModTime(),
		)
	}
}

func assertProcessSymlinkUnchanged(t *testing.T, path, wantTarget string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("entry %s mode = %v, want symlink", path, info.Mode())
	}
	gotTarget, err := os.Readlink(path)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget != wantTarget {
		t.Fatalf("entry %s target = %q, want %q", path, gotTarget, wantTarget)
	}
}

func validateProcessFixtureState(t *testing.T, fixture *processFixture) {
	t.Helper()
	keyPEM, err := os.ReadFile(fixture.cfg.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := os.ReadFile(fixture.cfg.CertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(fixture.root)
	if _, err := parseMaterial(
		certificatePEM,
		keyPEM,
		roots,
		fixture.cfg,
		time.Now(),
	); err != nil {
		t.Fatalf("final process material is invalid: %v", err)
	}
	account, err := newStateStore(fixture.cfg).loadAccountState()
	if err != nil {
		t.Fatalf("load final account state: %v", err)
	}
	if account.account == nil || account.account.Location == "" {
		t.Fatalf("final account state is incomplete: %+v", account.account)
	}
}

func assertOneProcessOrder(t *testing.T, fixture *processFixture) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixture.coordRoot, "orders"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(data))
	if len(lines) != 1 {
		t.Fatalf("process order lines = %q, want exactly one", lines)
	}
}

func assertNoProcessOrders(t *testing.T, fixture *processFixture) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixture.coordRoot, "orders"))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("unexpected process orders: %q", data)
	}
}

func writeValidProcessMaterial(t *testing.T, fixture *processFixture) {
	t.Helper()
	if err := os.Mkdir(fixture.stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestMaterialFiles(t, fixture.cfg, fixture.material)
}

func samePublicKey(left, right any) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}

func TestProcessesIssueOnceAcrossProcessesAndGoroutines(t *testing.T) {
	fixture := newProcessFixture(t)
	startFile := filepath.Join(fixture.coordRoot, "start")
	orderReadyFile := filepath.Join(fixture.coordRoot, "order-ready")
	orderReleaseFile := filepath.Join(fixture.coordRoot, "order-release")
	lockBlockedFile := filepath.Join(fixture.coordRoot, "lock-blocked")
	processes := make([]*runningProcessHelper, 0, 2)
	for index := 0; index < 2; index++ {
		helper := fixture.helper("ensure")
		helper.Goroutines = 8
		helper.StartFile = startFile
		helper.OrderReadyFile = orderReadyFile
		helper.OrderReleaseFile = orderReleaseFile
		helper.LockBlockedFile = lockBlockedFile
		helper.ReadyFile = filepath.Join(
			fixture.coordRoot,
			fmt.Sprintf("ready-%d", index),
		)
		configPath := writeProcessHelperConfig(
			t,
			fixture,
			fmt.Sprintf("ensure-%d", index),
			helper,
		)
		process := startProcessHelper(t, configPath)
		processes = append(processes, process)
	}
	for index, process := range processes {
		ready := filepath.Join(fixture.coordRoot, fmt.Sprintf("ready-%d", index))
		if err := process.waitForFile(ready, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	writeProcessSignalForTest(t, startFile)
	if err := waitForProcessHelpersFile(processes, orderReadyFile, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := waitForProcessHelpersFile(processes, lockBlockedFile, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	winnerPID := readProcessPIDSignal(t, orderReadyFile)
	loserPID := readProcessPIDSignal(t, lockBlockedFile)
	assertProcessPIDIsChild(t, processes, winnerPID)
	assertProcessPIDIsChild(t, processes, loserPID)
	if winnerPID == loserPID {
		t.Fatalf("order winner PID %d also reported lock contention", winnerPID)
	}
	assertProcessHelpersRunning(t, processes)
	writeProcessSignalForTest(t, orderReleaseFile)
	for _, process := range processes {
		if err := process.wait(10 * time.Second); err != nil {
			t.Fatal(err)
		}
	}

	assertOneProcessOrder(t, fixture)
	validateProcessFixtureState(t, fixture)
	lockInfo, err := os.Lstat(filepath.Join(fixture.stateRoot, issueLockFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !lockInfo.Mode().IsRegular() {
		t.Fatalf("process lock mode = %v, want regular", lockInfo.Mode())
	}
	if runtime.GOOS != "windows" && lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("process lock permissions = %#o, want 0600", lockInfo.Mode().Perm())
	}
}

func TestLockCancellationAcrossProcesses(t *testing.T) {
	fixture := newProcessFixture(t)
	holderReady := filepath.Join(fixture.coordRoot, "holder-ready")
	holderRelease := filepath.Join(fixture.coordRoot, "holder-release")
	holder := fixture.helper("acquire_lock")
	holder.ReadyFile = holderReady
	holder.ReleaseFile = holderRelease
	holderProcess := startProcessHelper(
		t,
		writeProcessHelperConfig(t, fixture, "holder", holder),
	)
	if err := holderProcess.waitForFile(holderReady, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	waiter := fixture.helper("cancel_ensure")
	waiter.ReadyFile = filepath.Join(fixture.coordRoot, "waiter-ready")
	waiter.CancelFile = filepath.Join(fixture.coordRoot, "cancel-waiter")
	waiterProcess := startProcessHelper(
		t,
		writeProcessHelperConfig(t, fixture, "canceled-waiter", waiter),
	)
	if err := waiterProcess.waitForFile(waiter.ReadyFile, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	writeProcessSignalForTest(t, waiter.CancelFile)
	if err := waiterProcess.wait(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	assertNoProcessOrders(t, fixture)
	writeProcessSignalForTest(t, holderRelease)
	if err := holderProcess.wait(5 * time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestLoadWhileLockedReturnsWithin250Milliseconds(t *testing.T) {
	fixture := newProcessFixture(t)
	writeValidProcessMaterial(t, fixture)
	holderReady := filepath.Join(fixture.coordRoot, "load-holder-ready")
	holderRelease := filepath.Join(fixture.coordRoot, "load-holder-release")
	holder := fixture.helper("acquire_lock")
	holder.ReadyFile = holderReady
	holder.ReleaseFile = holderRelease
	holderProcess := startProcessHelper(
		t,
		writeProcessHelperConfig(t, fixture, "load-holder", holder),
	)
	if err := holderProcess.waitForFile(holderReady, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	manager := newManagerForTest(
		t,
		fixture.cfg,
		fakeManagerClock{now: fixture.material.now},
		&forbiddenIssuerFactory{},
	)
	loadDone := make(chan error, 1)
	started := time.Now()
	go func() {
		loadDone <- manager.Load(context.Background())
	}()
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-loadDone:
		if err != nil {
			t.Fatalf("Load while locked: %v", err)
		}
		if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
			t.Fatalf("Load waited on process lock for %v", elapsed)
		}
	case <-timer.C:
		writeProcessSignalForTest(t, holderRelease)
		completionTimer := time.NewTimer(5 * time.Second)
		defer completionTimer.Stop()
		select {
		case err := <-loadDone:
			t.Fatalf(
				"Load blocked on process advisory lock for at least 250ms; after release error: %v",
				err,
			)
		case <-completionTimer.C:
			t.Fatal("Load remained blocked for 5s after the holder released its lock")
		}
	}
	writeProcessSignalForTest(t, holderRelease)
	if err := holderProcess.wait(5 * time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestProcessesReleaseKilledOwnerLock(t *testing.T) {
	fixture := newProcessFixture(t)
	holderReady := filepath.Join(fixture.coordRoot, "killed-holder-ready")
	holder := fixture.helper("acquire_lock")
	holder.ReadyFile = holderReady
	holder.ReleaseFile = filepath.Join(fixture.coordRoot, "never-release")
	holderProcess := startProcessHelper(
		t,
		writeProcessHelperConfig(t, fixture, "killed-holder", holder),
	)
	if err := holderProcess.waitForFile(holderReady, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := holderProcess.killAndReap(); err != nil {
		t.Fatal(err)
	}

	successor := fixture.helper("acquire_lock")
	successor.OperationTimeout = 2 * time.Second
	successorProcess := startProcessHelper(
		t,
		writeProcessHelperConfig(t, fixture, "lock-successor", successor),
	)
	if err := successorProcess.wait(5 * time.Second); err != nil {
		t.Fatalf("successor did not acquire OS-released lock: %v", err)
	}
}

func TestProcessesValidateLockEntry(t *testing.T) {
	fixture := newProcessFixture(t)
	if err := os.Mkdir(fixture.stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(fixture.stateRoot, issueLockFileName)

	valid := fixture.helper("acquire_lock")
	validProcess := startProcessHelper(
		t,
		writeProcessHelperConfig(t, fixture, "valid-lock", valid),
	)
	if err := validProcess.wait(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("lock mode = %v, want regular", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("lock permissions = %#o, want 0600", info.Mode().Perm())
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(fixture.coordRoot, "lock-target")
	targetBytes := []byte("target-must-not-change")
	if err := os.WriteFile(target, targetBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lockPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create Windows reparse-point fixture: %v", err)
		}
		t.Fatal(err)
	}
	symlink := fixture.helper("acquire_lock")
	symlink.ExpectedStateKind = "unsafe_path"
	symlinkProcess := startProcessHelper(
		t,
		writeProcessHelperConfig(t, fixture, "symlink-lock", symlink),
	)
	if err := symlinkProcess.wait(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	assertProcessFileUnchanged(t, target, targetBytes, targetInfo)
	assertProcessSymlinkUnchanged(t, lockPath, target)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}

	wrongModeContents := []byte("wrong-mode-must-not-change")
	if err := os.WriteFile(lockPath, wrongModeContents, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	wrongModeInfo, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongMode := fixture.helper("acquire_lock")
	wrongMode.ExpectedStateKind = "permissions"
	wrongModeProcess := startProcessHelper(
		t,
		writeProcessHelperConfig(t, fixture, "wrong-mode-lock", wrongMode),
	)
	if err := wrongModeProcess.wait(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	assertProcessFileUnchanged(t, lockPath, wrongModeContents, wrongModeInfo)
}
