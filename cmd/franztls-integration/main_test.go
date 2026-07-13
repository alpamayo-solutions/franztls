package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	franztls "github.com/alpamayo-solutions/franztls"
	legolog "github.com/go-acme/lego/v5/log"
)

const testSecret = "task12-private-key-token-secret"

type fakeManager struct {
	loadErr       error
	ensureChange  franztls.CertificateChange
	ensureErr     error
	loadCalls     int
	ensureCalls   int
	tlsConfig     *tls.Config
	tlsConfigErr  error
	tlsConfigName string
}

func (manager *fakeManager) Load(context.Context) error {
	manager.loadCalls++
	return manager.loadErr
}

func (manager *fakeManager) Ensure(context.Context) (franztls.CertificateChange, error) {
	manager.ensureCalls++
	return manager.ensureChange, manager.ensureErr
}

func (manager *fakeManager) ClientTLSConfig(serverName string) (*tls.Config, error) {
	manager.tlsConfigName = serverName
	return manager.tlsConfig, manager.tlsConfigErr
}

func testDependencies(manager *fakeManager) commandDependencies {
	return commandDependencies{
		newManager: func(franztls.Config) (managerAPI, error) {
			return manager, nil
		},
		activeCertificate: func(managerAPI) (certificateRecord, error) {
			return certificateRecord{
				Serial: "123456789",
				Expiry: "2030-01-02T03:04:05Z",
			}, nil
		},
		checkStorage: func(storageOptions) (storageRecord, error) {
			return storageRecord{
				UID:           65532,
				GID:           65532,
				StateMode:     "0700",
				StateWritable: true,
				CAReadable:    true,
				CAWriteError:  "EROFS",
			}, nil
		},
		serveMTLS: func(context.Context, serveOptions) error { return nil },
		handshake: func(context.Context, managerAPI, handshakeOptions) (peerRecord, error) {
			return peerRecord{Serial: "123456789"}, nil
		},
	}
}

func TestPackageConfigUsesTheSharedNonRootPaths(t *testing.T) {
	flags := commonFlags{
		directory:   "https://ca.test/acme/directory",
		renewBefore: 47 * time.Hour,
	}

	got := packageConfig(flags)
	want := franztls.Config{
		Domain:          "franztls-client",
		Email:           "admin@localhost",
		AcceptTerms:     true,
		DirectoryURL:    "https://ca.test/acme/directory",
		CACertFile:      "/etc/certs/prekit-ca.crt",
		AccountKeyFile:  "/etc/certs/account.key",
		AccountFile:     "/etc/certs/account.json",
		PrivateKeyFile:  "/etc/certs/prekit-tls.key",
		CertificateFile: "/etc/certs/prekit-tls.pem",
		RenewBefore:     47 * time.Hour,
		HTTP01Address:   ":80",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packageConfig() = %#v, want %#v", got, want)
	}
}

func TestCertificateCommandsEmitOnlyLeafSerialAndExpiryJSON(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		change      franztls.CertificateChange
		wantLoads   int
		wantEnsures int
		wantRenew   time.Duration
	}{
		{
			name:        "issue",
			args:        []string{"issue"},
			change:      franztls.CertificateChange{Renewed: true},
			wantEnsures: 1,
			wantRenew:   24 * time.Hour,
		},
		{
			name:      "load",
			args:      []string{"load"},
			wantLoads: 1,
			wantRenew: 24 * time.Hour,
		},
		{
			name:        "ensure",
			args:        []string{"ensure", "--renew-before=1m"},
			wantEnsures: 1,
			wantRenew:   time.Minute,
		},
		{
			name:        "renew",
			args:        []string{"renew", "--renew-before=48h"},
			change:      franztls.CertificateChange{Renewed: true},
			wantEnsures: 1,
			wantRenew:   48 * time.Hour,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &fakeManager{ensureChange: test.change}
			dependencies := testDependencies(manager)
			var capturedConfig franztls.Config
			dependencies.newManager = func(config franztls.Config) (managerAPI, error) {
				capturedConfig = config
				return manager, nil
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := runCommand(context.Background(), test.args, &stdout, &stderr, dependencies)
			if code != 0 {
				t.Fatalf("runCommand() code = %d, stderr = %q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			if manager.loadCalls != test.wantLoads || manager.ensureCalls != test.wantEnsures {
				t.Fatalf("calls = load %d ensure %d, want load %d ensure %d", manager.loadCalls, manager.ensureCalls, test.wantLoads, test.wantEnsures)
			}
			if capturedConfig.RenewBefore != test.wantRenew {
				t.Fatalf("RenewBefore = %s, want %s", capturedConfig.RenewBefore, test.wantRenew)
			}

			var output map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
				t.Fatalf("stdout is not JSON: %v; output = %q", err, stdout.String())
			}
			want := map[string]any{
				"expiry": "2030-01-02T03:04:05Z",
				"serial": "123456789",
			}
			if !reflect.DeepEqual(output, want) {
				t.Fatalf("output = %#v, want %#v", output, want)
			}
			if !bytes.HasSuffix(stdout.Bytes(), []byte("\n")) || bytes.Count(stdout.Bytes(), []byte("\n")) != 1 {
				t.Fatalf("stdout = %q, want exactly one JSON line", stdout.String())
			}
		})
	}
}

func TestCertificateCommandSuppressesDependencyLogsFromStdout(t *testing.T) {
	originalLogger := legolog.Default()
	defer legolog.SetDefault(originalLogger)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	legolog.SetDefault(slog.New(slog.NewTextHandler(&stdout, nil)))
	manager := &fakeManager{
		ensureChange: franztls.CertificateChange{Renewed: true},
	}
	dependencies := testDependencies(manager)
	dependencies.newManager = func(franztls.Config) (managerAPI, error) {
		legolog.Info("task12 dependency log must stay out of machine output")
		return manager, nil
	}

	code := runCommand(context.Background(), []string{"issue"}, &stdout, &stderr, dependencies)

	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	want := "{\"serial\":\"123456789\",\"expiry\":\"2030-01-02T03:04:05Z\"}\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want exactly %q", stdout.String(), want)
	}
}

func TestIssueAndRenewRequireANewCertificate(t *testing.T) {
	for _, command := range []string{"issue", "renew"} {
		t.Run(command, func(t *testing.T) {
			dependencies := testDependencies(&fakeManager{})
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := runCommand(context.Background(), []string{command}, &stdout, &stderr, dependencies)
			if code != 1 {
				t.Fatalf("code = %d, want 1", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

func TestStorageCheckEmitsMachineReadableAssertions(t *testing.T) {
	dependencies := testDependencies(&fakeManager{})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runCommand(context.Background(), []string{"storage-check"}, &stdout, &stderr, dependencies); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}

	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	want := map[string]any{
		"ca_readable":    true,
		"ca_write_error": "EROFS",
		"gid":            float64(65532),
		"state_mode":     "0700",
		"state_writable": true,
		"uid":            float64(65532),
	}
	if !reflect.DeepEqual(output, want) {
		t.Fatalf("output = %#v, want %#v", output, want)
	}
}

func TestHandshakeLoadsStateAndPrintsTheServerObservedSerial(t *testing.T) {
	manager := &fakeManager{}
	dependencies := testDependencies(manager)
	var capturedOptions handshakeOptions
	dependencies.handshake = func(_ context.Context, gotManager managerAPI, options handshakeOptions) (peerRecord, error) {
		if gotManager != manager {
			t.Fatal("handshake received a different manager")
		}
		capturedOptions = options
		return peerRecord{Serial: "123456789"}, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCommand(context.Background(), []string{"handshake"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if manager.loadCalls != 1 {
		t.Fatalf("Load calls = %d, want 1", manager.loadCalls)
	}
	if capturedOptions.address != "mtls-server:8443" || capturedOptions.serverName != "mtls-server" {
		t.Fatalf("handshake options = %#v, want default internal endpoint", capturedOptions)
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if want := map[string]any{"serial": "123456789"}; !reflect.DeepEqual(output, want) {
		t.Fatalf("output = %#v, want %#v", output, want)
	}
}

func TestHandshakeUsesTheManagersVerifiedClientTLSConfig(t *testing.T) {
	wantErr := errors.New("TLS config sentinel")
	manager := &fakeManager{tlsConfigErr: wantErr}

	_, err := performHandshake(
		context.Background(),
		manager,
		handshakeOptions{address: "mtls-server:8443", serverName: "mtls-server"},
	)

	if !errors.Is(err, wantErr) {
		t.Fatalf("performHandshake() error = %v, want %v", err, wantErr)
	}
	if manager.tlsConfigName != "mtls-server" {
		t.Fatalf("ClientTLSConfig name = %q, want mtls-server", manager.tlsConfigName)
	}
}

func TestServeMTLSDispatchesWithoutWritingSecrets(t *testing.T) {
	dependencies := testDependencies(&fakeManager{})
	called := false
	var capturedOptions serveOptions
	dependencies.serveMTLS = func(_ context.Context, options serveOptions) error {
		called = true
		capturedOptions = options
		return nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runCommand(context.Background(), []string{"serve-mtls"}, &stdout, &stderr, dependencies); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !called {
		t.Fatal("serve-mtls dependency was not called")
	}
	if capturedOptions.listen != ":8443" ||
		capturedOptions.certificateFile != "/runtime/server.pem" ||
		capturedOptions.privateKeyFile != "/runtime/server.key" ||
		capturedOptions.caFile != "/etc/certs/prekit-ca.crt" {
		t.Fatalf("serve options = %#v, want non-secret container defaults", capturedOptions)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout = %q stderr = %q, want both empty", stdout.String(), stderr.String())
	}
}

func TestArgumentErrorsExitTwo(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing command"},
		{name: "unknown command", args: []string{"unknown"}},
		{name: "extra argument", args: []string{"load", "unexpected"}},
		{name: "bad duration", args: []string{"ensure", "--renew-before=tomorrow"}},
		{name: "secret unknown flag", args: []string{"load", "--unknown=" + testSecret}},
		{name: "empty directory", args: []string{"issue", "--directory="}},
		{name: "empty listen", args: []string{"serve-mtls", "--listen="}},
		{name: "empty address", args: []string{"handshake", "--address="}},
		{name: "empty server name", args: []string{"handshake", "--server-name="}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := runCommand(context.Background(), test.args, &stdout, &stderr, testDependencies(&fakeManager{}))
			if code != 2 {
				t.Fatalf("code = %d, want 2; stderr = %q", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Fatal("stderr is empty")
			}
			if strings.Contains(stderr.String(), testSecret) {
				t.Fatalf("stderr leaked secret: %q", stderr.String())
			}
		})
	}
}

func TestLifecycleErrorsAreNonZeroAndSecretFreeForEverySubcommand(t *testing.T) {
	tests := []struct {
		command string
		prepare func(*fakeManager, *commandDependencies)
	}{
		{command: "issue", prepare: func(manager *fakeManager, _ *commandDependencies) { manager.ensureErr = errors.New(testSecret) }},
		{command: "load", prepare: func(manager *fakeManager, _ *commandDependencies) { manager.loadErr = errors.New(testSecret) }},
		{command: "ensure", prepare: func(manager *fakeManager, _ *commandDependencies) { manager.ensureErr = errors.New(testSecret) }},
		{command: "renew", prepare: func(manager *fakeManager, _ *commandDependencies) { manager.ensureErr = errors.New(testSecret) }},
		{command: "storage-check", prepare: func(_ *fakeManager, dependencies *commandDependencies) {
			dependencies.checkStorage = func(storageOptions) (storageRecord, error) {
				return storageRecord{}, errors.New(testSecret)
			}
		}},
		{command: "serve-mtls", prepare: func(_ *fakeManager, dependencies *commandDependencies) {
			dependencies.serveMTLS = func(context.Context, serveOptions) error { return errors.New(testSecret) }
		}},
		{command: "handshake", prepare: func(_ *fakeManager, dependencies *commandDependencies) {
			dependencies.handshake = func(context.Context, managerAPI, handshakeOptions) (peerRecord, error) {
				return peerRecord{}, errors.New(testSecret)
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			manager := &fakeManager{ensureChange: franztls.CertificateChange{Renewed: true}}
			dependencies := testDependencies(manager)
			test.prepare(manager, &dependencies)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := runCommand(context.Background(), []string{test.command}, &stdout, &stderr, dependencies)
			if code != 1 {
				t.Fatalf("code = %d, want 1", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if strings.Contains(stderr.String(), testSecret) {
				t.Fatalf("stderr leaked secret: %q", stderr.String())
			}
			if !strings.Contains(stderr.String(), test.command) {
				t.Fatalf("stderr = %q, want command name", stderr.String())
			}
		})
	}
}

func TestMTLSHandlerReturnsOnlyThePeerLeafSerial(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://mtls-server/", nil)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(424242)}},
		VerifiedChains:   [][]*x509.Certificate{{{SerialNumber: big.NewInt(424242)}}},
	}
	recorder := httptest.NewRecorder()

	mtlsHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var output map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &output); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if want := map[string]any{"serial": "424242"}; !reflect.DeepEqual(output, want) {
		t.Fatalf("output = %#v, want %#v", output, want)
	}
}

func TestMTLSHandlerRejectsRequestsWithoutAVerifiedPeer(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://mtls-server/", nil)
	recorder := httptest.NewRecorder()

	mtlsHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if strings.Contains(recorder.Body.String(), testSecret) {
		t.Fatalf("body leaked secret: %q", recorder.Body.String())
	}
}

func TestMTLSHandlerRejectsAnUnverifiedPeerCertificate(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://mtls-server/", nil)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(424242)}},
	}
	recorder := httptest.NewRecorder()

	mtlsHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}
