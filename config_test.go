package franztls

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validConfig(root string) Config {
	return Config{
		Domain:          "historian.internal",
		Email:           "admin@localhost",
		AcceptTerms:     true,
		DirectoryURL:    "https://ca:9000/acme/acme/directory",
		CACertFile:      filepath.Join(root, "prekit-ca.crt"),
		AccountKeyFile:  filepath.Join(root, "account.key"),
		AccountFile:     filepath.Join(root, "account.json"),
		PrivateKeyFile:  filepath.Join(root, "prekit-tls.key"),
		CertificateFile: filepath.Join(root, "prekit-tls.pem"),
		HTTP01Address:   "127.0.0.1:0",
	}
}

func TestConfigValidation(t *testing.T) {
	longName := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 62),
	}, ".")

	tests := []struct {
		name      string
		mutate    func(*Config)
		wantField string
	}{
		{
			name: "empty domain",
			mutate: func(cfg *Config) {
				cfg.Domain = ""
			},
			wantField: "Domain",
		},
		{
			name: "wildcard domain",
			mutate: func(cfg *Config) {
				cfg.Domain = "*.internal"
			},
			wantField: "Domain",
		},
		{
			name: "IP domain",
			mutate: func(cfg *Config) {
				cfg.Domain = "127.0.0.1"
			},
			wantField: "Domain",
		},
		{
			name: "path-like domain",
			mutate: func(cfg *Config) {
				cfg.Domain = "historian.internal/path"
			},
			wantField: "Domain",
		},
		{
			name: "underscore in domain",
			mutate: func(cfg *Config) {
				cfg.Domain = "historian_service.internal"
			},
			wantField: "Domain",
		},
		{
			name: "empty DNS label",
			mutate: func(cfg *Config) {
				cfg.Domain = "historian..internal"
			},
			wantField: "Domain",
		},
		{
			name: "DNS label longer than 63 bytes",
			mutate: func(cfg *Config) {
				cfg.Domain = strings.Repeat("a", 64) + ".internal"
			},
			wantField: "Domain",
		},
		{
			name: "DNS name longer than 253 bytes",
			mutate: func(cfg *Config) {
				cfg.Domain = longName
			},
			wantField: "Domain",
		},
		{
			name: "missing email",
			mutate: func(cfg *Config) {
				cfg.Email = ""
			},
			wantField: "Email",
		},
		{
			name: "malformed email",
			mutate: func(cfg *Config) {
				cfg.Email = "not-an-email"
			},
			wantField: "Email",
		},
		{
			name: "terms not accepted",
			mutate: func(cfg *Config) {
				cfg.AcceptTerms = false
			},
			wantField: "AcceptTerms",
		},
		{
			name: "missing directory URL",
			mutate: func(cfg *Config) {
				cfg.DirectoryURL = ""
			},
			wantField: "DirectoryURL",
		},
		{
			name: "HTTP directory URL",
			mutate: func(cfg *Config) {
				cfg.DirectoryURL = "http://ca:9000/acme/acme/directory"
			},
			wantField: "DirectoryURL",
		},
		{
			name: "directory URL with credentials",
			mutate: func(cfg *Config) {
				cfg.DirectoryURL = "https://user:password@ca:9000/acme/acme/directory"
			},
			wantField: "DirectoryURL",
		},
		{
			name: "missing CA certificate path",
			mutate: func(cfg *Config) {
				cfg.CACertFile = ""
			},
			wantField: "CACertFile",
		},
		{
			name: "missing account key path",
			mutate: func(cfg *Config) {
				cfg.AccountKeyFile = ""
			},
			wantField: "AccountKeyFile",
		},
		{
			name: "missing account path",
			mutate: func(cfg *Config) {
				cfg.AccountFile = ""
			},
			wantField: "AccountFile",
		},
		{
			name: "missing private key path",
			mutate: func(cfg *Config) {
				cfg.PrivateKeyFile = ""
			},
			wantField: "PrivateKeyFile",
		},
		{
			name: "missing certificate path",
			mutate: func(cfg *Config) {
				cfg.CertificateFile = ""
			},
			wantField: "CertificateFile",
		},
		{
			name: "relative CA certificate path",
			mutate: func(cfg *Config) {
				cfg.CACertFile = "prekit-ca.crt"
			},
			wantField: "CACertFile",
		},
		{
			name: "relative writable path",
			mutate: func(cfg *Config) {
				cfg.AccountKeyFile = "account.key"
			},
			wantField: "AccountKeyFile",
		},
		{
			name: "split writable state directories",
			mutate: func(cfg *Config) {
				cfg.CertificateFile = filepath.Join(filepath.Dir(cfg.CertificateFile), "other", "prekit-tls.pem")
			},
			wantField: "CertificateFile",
		},
		{
			name: "negative renewal duration",
			mutate: func(cfg *Config) {
				cfg.RenewBefore = -time.Second
			},
			wantField: "RenewBefore",
		},
		{
			name: "malformed HTTP listen address",
			mutate: func(cfg *Config) {
				cfg.HTTP01Address = "127.0.0.1"
			},
			wantField: "HTTP01Address",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig(t.TempDir())
			test.mutate(&cfg)

			manager, err := New(cfg)
			if err == nil {
				t.Fatalf("New() = (%v, nil), want a configuration error", manager)
			}
			if manager != nil {
				t.Fatalf("New() manager = %v, want nil", manager)
			}

			var configErr *ConfigError
			if !errors.As(err, &configErr) {
				t.Fatalf("New() error = %T %v, want *ConfigError", err, err)
			}
			if configErr.Field != test.wantField {
				t.Fatalf("ConfigError.Field = %q, want %q", configErr.Field, test.wantField)
			}
			if configErr.Reason == "" {
				t.Fatal("ConfigError.Reason is empty")
			}
		})
	}
}

func TestConfigNormalization(t *testing.T) {
	root := t.TempDir()
	cfg := validConfig(root)
	cfg.Domain = "HISTORIAN.INTERNAL"
	cfg.CACertFile = filepath.Join(root, "ca", "..", "prekit-ca.crt")
	cfg.AccountKeyFile = filepath.Join(root, "state", "..", "account.key")
	cfg.AccountFile = filepath.Join(root, "state", "..", "account.json")
	cfg.PrivateKeyFile = filepath.Join(root, "state", "..", "prekit-tls.key")
	cfg.CertificateFile = filepath.Join(root, "state", "..", "prekit-tls.pem")
	cfg.HTTP01Address = ""

	manager, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got, want := manager.cfg.Domain, "historian.internal"; got != want {
		t.Fatalf("normalized domain = %q, want %q", got, want)
	}
	if got, want := manager.cfg.RenewBefore, 24*time.Hour; got != want {
		t.Fatalf("RenewBefore = %v, want %v", got, want)
	}
	if got, want := manager.cfg.HTTP01Address, ":80"; got != want {
		t.Fatalf("HTTP01Address = %q, want %q", got, want)
	}
	if got, want := manager.cfg.CACertFile, filepath.Join(root, "prekit-ca.crt"); got != want {
		t.Fatalf("CACertFile = %q, want %q", got, want)
	}
	if got, want := manager.cfg.AccountKeyFile, filepath.Join(root, "account.key"); got != want {
		t.Fatalf("AccountKeyFile = %q, want %q", got, want)
	}
}

func TestConfigAllowsCACertificateInDifferentParent(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	caRoot := filepath.Join(root, "trust")
	cfg := validConfig(stateRoot)
	cfg.CACertFile = filepath.Join(caRoot, "prekit-ca.crt")

	if filepath.Dir(cfg.CACertFile) == filepath.Dir(cfg.AccountKeyFile) {
		t.Fatal("test setup placed CA and writable state in the same parent")
	}

	manager, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := manager.cfg.CACertFile; got != cfg.CACertFile {
		t.Fatalf("CACertFile = %q, want %q", got, cfg.CACertFile)
	}
}

func TestNewPerformsNoIO(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	manager, err := New(validConfig(root))
	if err != nil || manager == nil {
		t.Fatalf("New() = (%v, %v)", manager, err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("New created state: %v", err)
	}
}

func TestNewInitializesEventChannels(t *testing.T) {
	manager, err := New(validConfig(t.TempDir()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if manager.Changes() == nil {
		t.Fatal("Changes() returned nil")
	}
	if manager.Errors() == nil {
		t.Fatal("Errors() returned nil")
	}
}

func TestTypedErrorsAreInspectableAndSafe(t *testing.T) {
	configErr := &ConfigError{Field: "Domain", Reason: "must be a DNS name"}
	if got, want := configErr.Error(), "franztls: invalid Domain: must be a DNS name"; got != want {
		t.Fatalf("ConfigError.Error() = %q, want %q", got, want)
	}
	if configErr.Unwrap() != nil {
		t.Fatal("ConfigError.Unwrap() returned a non-nil error")
	}

	sensitiveErr := errors.New("ACME response contained secret-token")
	stateErr := &StateError{Path: "/etc/certs/account.json", Kind: "account", Err: sensitiveErr}
	if !errors.Is(stateErr, sensitiveErr) {
		t.Fatal("StateError does not unwrap its cause")
	}
	if strings.Contains(stateErr.Error(), "secret-token") {
		t.Fatalf("StateError.Error() exposed its cause: %q", stateErr.Error())
	}

	notAfter := time.Date(2026, time.July, 13, 14, 15, 16, 0, time.UTC)
	deferredErr := &DeferredRenewalError{NotAfter: notAfter, Err: sensitiveErr}
	if !errors.Is(deferredErr, sensitiveErr) {
		t.Fatal("DeferredRenewalError does not unwrap its cause")
	}
	if !strings.Contains(deferredErr.Error(), notAfter.Format(time.RFC3339)) {
		t.Fatalf("DeferredRenewalError.Error() = %q, want expiry", deferredErr.Error())
	}
	if !strings.Contains(deferredErr.Error(), "ACME operation") {
		t.Fatalf("DeferredRenewalError.Error() = %q, want sanitized operation class", deferredErr.Error())
	}
	if strings.Contains(deferredErr.Error(), "secret-token") {
		t.Fatalf("DeferredRenewalError.Error() exposed its cause: %q", deferredErr.Error())
	}
}
