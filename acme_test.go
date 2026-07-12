package franztls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/registration"
)

const (
	acmeSecretToken   = "secret-acme-token"
	acmeSecretKeyAuth = "secret-key-authorization"
	acmeSecretAccount = `{"status":"valid","contact":["mailto:secret@example.test"]}`
)

func TestLegoIssuerImplementsManagerSeam(t *testing.T) {
	var _ issuer = (*legoIssuer)(nil)
	var _ issuerFactory = legoIssuerFactory{}
}

func TestLegoDirectoryUsesOnlyConfiguredRoots(t *testing.T) {
	server, requests := newTestACMEDirectoryServer(t, false)
	accountKey := newTestRSAAccountKey(t)

	t.Run("configured CA", func(t *testing.T) {
		cfg := validConfig(storageTempDir(t))
		cfg.DirectoryURL = server.URL + "/directory"
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())

		adapter, err := newLegoIssuer(context.Background(), cfg, roots, accountKey, nil)
		if err != nil {
			t.Fatalf("newLegoIssuer() error = %v", err)
		}
		if err := adapter.Close(context.Background()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	t.Run("system roots", func(t *testing.T) {
		cfg := validConfig(storageTempDir(t))
		cfg.DirectoryURL = server.URL + "/directory"
		_, err := newLegoIssuer(context.Background(), cfg, nil, accountKey, nil)
		if err == nil {
			t.Fatal("self-signed directory unexpectedly trusted system roots")
		}
		assertSafeACMEError(t, err, "directory", server.URL, acmeSecretToken, acmeSecretKeyAuth)
	})

	t.Run("unrelated configured CA", func(t *testing.T) {
		cfg := validConfig(storageTempDir(t))
		cfg.DirectoryURL = server.URL + "/directory"
		unrelated := newTestRoot(t, "unrelated directory root", time.Now().UTC())
		roots := x509.NewCertPool()
		roots.AddCert(unrelated.certificate)
		_, err := newLegoIssuer(context.Background(), cfg, roots, accountKey, nil)
		if err == nil {
			t.Fatal("directory unexpectedly trusted unrelated configured CA")
		}
		assertSafeACMEError(t, err, "directory", server.URL, acmeSecretToken, acmeSecretKeyAuth)
	})

	if requests.directory != 1 {
		t.Fatalf("trusted directory requests = %d, want 1", requests.directory)
	}
	if requests.accounts != 0 || requests.orders != 0 {
		t.Fatalf("directory construction reached accounts/orders: %+v", requests)
	}
}

func TestLegoHTTPClientIsVerifiedAndBounded(t *testing.T) {
	roots := x509.NewCertPool()
	client := newLegoHTTPClient(roots)
	if client.Timeout != 30*time.Second {
		t.Fatalf("HTTP timeout = %v, want 30s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatalf("HTTP transport = %T, want TLS transport", client.Transport)
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("ACME HTTP client disables certificate verification")
	}
	if transport.TLSClientConfig.RootCAs != roots {
		t.Fatal("ACME HTTP client did not use the exclusive configured root pool")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %x, want TLS 1.2", transport.TLSClientConfig.MinVersion)
	}
}

func TestLegoRejectsExternalAccountBindingBeforeAccountOrOrder(t *testing.T) {
	server, requests := newTestACMEDirectoryServer(t, true)
	cfg := validConfig(storageTempDir(t))
	cfg.DirectoryURL = server.URL + "/directory"
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	_, err := newLegoIssuer(context.Background(), cfg, roots, newTestRSAAccountKey(t), nil)
	if !errors.Is(err, ErrExternalAccountBinding) {
		t.Fatalf("error = %T %v, want ErrExternalAccountBinding", err, err)
	}
	if requests.directory != 1 || requests.accounts != 0 || requests.orders != 0 {
		t.Fatalf("EAB requests = %+v, want only one directory request", requests)
	}
}

func TestAccountExistingRecordIsQueried(t *testing.T) {
	cfg := validConfig(storageTempDir(t))
	key := newTestRSAAccountKey(t)
	account := testACMEAccount("https://ca.test/acme/account/existing")
	operations := &recordingLegoOperations{queryAccount: account}
	provider := &recordingManagedHTTP01Provider{}
	adapter := newInjectedLegoIssuer(t, cfg, key, account, false, operations, provider)

	got, err := adapter.EnsureAccount(context.Background(), key, account)
	if err != nil {
		t.Fatalf("EnsureAccount() error = %v", err)
	}
	if got.Location != account.Location {
		t.Fatalf("account location = %q, want %q", got.Location, account.Location)
	}
	if operations.queryCalls != 1 || operations.resolveCalls != 0 || operations.registerCalls != 0 {
		t.Fatalf("account calls = query:%d resolve:%d register:%d", operations.queryCalls, operations.resolveCalls, operations.registerCalls)
	}
	assertPersistedAccount(t, cfg, account)
}

func TestAccountMissingRecordRecoversByExistingKeyAndPersists(t *testing.T) {
	cfg := validConfig(storageTempDir(t))
	key := newTestRSAAccountKey(t)
	keyPEM := encodeTestPrivateKey(t, key, testKeyPKCS1)
	if err := newStateStore(cfg).writeFile(cfg.AccountKeyFile, keyPEM, 0o600, "account_key"); err != nil {
		t.Fatal(err)
	}
	recovered := testACMEAccount("https://ca.test/acme/account/recovered")
	operations := &recordingLegoOperations{resolvedAccount: recovered}
	adapter := newInjectedLegoIssuer(
		t, cfg, key, nil, true, operations, &recordingManagedHTTP01Provider{},
	)

	got, err := adapter.EnsureAccount(context.Background(), key, nil)
	if err != nil {
		t.Fatalf("EnsureAccount() error = %v", err)
	}
	if got.Location != recovered.Location {
		t.Fatalf("recovered location = %q, want %q", got.Location, recovered.Location)
	}
	if operations.resolveCalls != 1 || operations.queryCalls != 0 || operations.registerCalls != 0 {
		t.Fatalf("account calls = query:%d resolve:%d register:%d", operations.queryCalls, operations.resolveCalls, operations.registerCalls)
	}
	assertPersistedAccount(t, cfg, recovered)
	assertFileBytesAndMode(t, cfg.AccountKeyFile, keyPEM, 0o600)
}

func TestAccountMissingIdentityRegistersConfiguredEmailAndTerms(t *testing.T) {
	cfg := validConfig(storageTempDir(t))
	registered := testACMEAccount("https://ca.test/acme/account/new")
	operations := &recordingLegoOperations{registeredAccount: registered}
	key := newTestRSAAccountKey(t)
	adapter := newInjectedLegoIssuer(
		t, cfg, key, nil, false, operations, &recordingManagedHTTP01Provider{},
	)

	got, err := adapter.EnsureAccount(context.Background(), key, nil)
	if err != nil {
		t.Fatalf("EnsureAccount() error = %v", err)
	}
	if got.Location != registered.Location {
		t.Fatalf("registered location = %q, want %q", got.Location, registered.Location)
	}
	if operations.registerCalls != 1 || operations.resolveCalls != 0 || operations.queryCalls != 0 {
		t.Fatalf("account calls = query:%d resolve:%d register:%d", operations.queryCalls, operations.resolveCalls, operations.registerCalls)
	}
	if len(operations.registerOptions) != 1 || !operations.registerOptions[0].TermsOfServiceAgreed {
		t.Fatalf("register options = %+v, want TermsOfServiceAgreed", operations.registerOptions)
	}
	if adapter.user.GetEmail() != cfg.Email {
		t.Fatalf("registration email = %q, want %q", adapter.user.GetEmail(), cfg.Email)
	}
	assertPersistedAccount(t, cfg, registered)
}

func TestCSRUsesExistingSignerOneDNSNameBundleAndFullChain(t *testing.T) {
	material := newTestMaterial(
		t,
		testKeyRSA,
		testKeyPKCS1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	cfg := material.cfg
	operations := &recordingLegoOperations{
		obtainResource: &certificate.Resource{Certificate: bytes.Clone(material.certificatePEM)},
	}
	provider := &recordingManagedHTTP01Provider{}
	adapter := newInjectedLegoIssuer(
		t, cfg, newTestRSAAccountKey(t), testACMEAccount("https://ca.test/account/1"), false, operations, provider,
	)

	chain, err := adapter.Obtain(context.Background(), material.leafKey)
	if err != nil {
		t.Fatalf("Obtain() error = %v", err)
	}
	if len(operations.obtainRequests) != 1 {
		t.Fatalf("obtain calls = %d, want 1", len(operations.obtainRequests))
	}
	request := operations.obtainRequests[0]
	if request.CSR == nil || request.CSR.CheckSignature() != nil {
		t.Fatal("CSR is missing or has an invalid signature")
	}
	if len(request.CSR.DNSNames) != 1 || request.CSR.DNSNames[0] != cfg.Domain {
		t.Fatalf("CSR DNS names = %q, want [%q]", request.CSR.DNSNames, cfg.Domain)
	}
	if request.CSR.Subject.CommonName != "" {
		t.Fatalf("CSR common name = %q, want empty", request.CSR.Subject.CommonName)
	}
	if !publicKeysEqual(request.CSR.PublicKey, material.leafKey.Public()) {
		t.Fatal("CSR did not use the existing domain signer")
	}
	if request.PrivateKey != material.leafKey || !request.Bundle {
		t.Fatalf("obtain request signer/bundle = %T/%v", request.PrivateKey, request.Bundle)
	}
	certificates, _, parseErr := parseCertificateChain(chain)
	if parseErr != nil || len(certificates) != 2 || certificates[0].IsCA || !certificates[1].IsCA {
		t.Fatalf("returned chain is not leaf-first and complete: certificates=%d error=%v", len(certificates), parseErr)
	}
	if !bytes.Equal(chain, material.certificatePEM) {
		t.Fatal("Obtain changed the full chain returned by lego")
	}
	if provider.closeCalls != 1 {
		t.Fatalf("provider close calls = %d, want 1", provider.closeCalls)
	}
}

func TestCSRAlwaysClosesChallengeProvider(t *testing.T) {
	successMaterial := newTestMaterial(
		t,
		testKeyRSA,
		testKeyPKCS1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	for _, test := range []struct {
		name       string
		operation  func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error)
		closeError error
		cancel     bool
		wantClass  string
	}{
		{
			name: "order error",
			operation: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
				return nil, errors.New("order exposed " + acmeSecretToken + " " + acmeSecretKeyAuth)
			},
			wantClass: "order",
		},
		{
			name: "cancellation",
			operation: func(ctx context.Context, _ certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
				return nil, ctx.Err()
			},
			cancel:    true,
			wantClass: "order",
		},
		{
			name: "close error",
			operation: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
				return &certificate.Resource{Certificate: successMaterial.certificatePEM}, nil
			},
			closeError: errors.New("challenge exposed " + acmeSecretToken + " " + acmeSecretKeyAuth),
			wantClass:  "challenge",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig(storageTempDir(t))
			operations := &recordingLegoOperations{obtain: test.operation}
			provider := &recordingManagedHTTP01Provider{closeError: test.closeError}
			adapter := newInjectedLegoIssuer(
				t, cfg, newTestRSAAccountKey(t), testACMEAccount("https://ca.test/account/1"), false, operations, provider,
			)
			ctx := context.Background()
			if test.cancel {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			_, err := adapter.Obtain(ctx, newTestSigner(t, testKeyRSA))
			if err == nil {
				t.Fatal("Obtain() unexpectedly succeeded")
			}
			assertSafeACMEError(t, err, test.wantClass, acmeSecretToken, acmeSecretKeyAuth)
			if provider.closeCalls != 1 {
				t.Fatalf("provider close calls = %d, want 1", provider.closeCalls)
			}
		})
	}
}

func TestLegoAdapterErrorsRedactAccountAndPrivateMaterial(t *testing.T) {
	cfg := validConfig(storageTempDir(t))
	key := newTestRSAAccountKey(t)
	privateKeyPEM := encodeTestPrivateKey(t, key, testKeyPKCS1)
	secretError := errors.New(strings.Join([]string{
		acmeSecretToken,
		acmeSecretKeyAuth,
		acmeSecretAccount,
		string(privateKeyPEM),
	}, " | "))

	t.Run("account", func(t *testing.T) {
		operations := &recordingLegoOperations{registerError: secretError}
		adapter := newInjectedLegoIssuer(
			t, cfg, key, nil, false, operations, &recordingManagedHTTP01Provider{},
		)
		_, err := adapter.EnsureAccount(context.Background(), key, nil)
		assertSafeACMEError(
			t, err, "account", acmeSecretToken, acmeSecretKeyAuth, acmeSecretAccount, string(privateKeyPEM),
		)
	})

	t.Run("challenge setup", func(t *testing.T) {
		operations := &recordingLegoOperations{setProviderError: secretError}
		_, err := newLegoIssuerWithOperations(
			cfg,
			key,
			nil,
			false,
			operations,
			&recordingManagedHTTP01Provider{},
		)
		assertSafeACMEError(
			t, err, "challenge", acmeSecretToken, acmeSecretKeyAuth, acmeSecretAccount, string(privateKeyPEM),
		)
	})
}

func newInjectedLegoIssuer(
	t *testing.T,
	cfg Config,
	accountKey crypto.Signer,
	account *acme.ExtendedAccount,
	recoverAccount bool,
	operations *recordingLegoOperations,
	provider *recordingManagedHTTP01Provider,
) *legoIssuer {
	t.Helper()
	adapter, err := newLegoIssuerWithOperations(
		cfg,
		accountKey,
		account,
		recoverAccount,
		operations,
		provider,
	)
	if err != nil {
		t.Fatalf("newLegoIssuerWithOperations() error = %v", err)
	}
	return adapter
}

type recordingLegoOperations struct {
	setProviderError error

	queryAccount      *acme.ExtendedAccount
	queryError        error
	queryCalls        int
	resolvedAccount   *acme.ExtendedAccount
	resolveError      error
	resolveCalls      int
	registeredAccount *acme.ExtendedAccount
	registerError     error
	registerCalls     int
	registerOptions   []registration.RegisterOptions

	obtain         func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error)
	obtainResource *certificate.Resource
	obtainError    error
	obtainRequests []certificate.ObtainForCSRRequest
	provider       challenge.Provider
}

func (operations *recordingLegoOperations) SetHTTP01Provider(provider challenge.Provider) error {
	operations.provider = provider
	return operations.setProviderError
}

func (operations *recordingLegoOperations) QueryRegistration(context.Context) (*acme.ExtendedAccount, error) {
	operations.queryCalls++
	return operations.queryAccount, operations.queryError
}

func (operations *recordingLegoOperations) ResolveAccountByKey(context.Context) (*acme.ExtendedAccount, error) {
	operations.resolveCalls++
	return operations.resolvedAccount, operations.resolveError
}

func (operations *recordingLegoOperations) Register(
	_ context.Context,
	options registration.RegisterOptions,
) (*acme.ExtendedAccount, error) {
	operations.registerCalls++
	operations.registerOptions = append(operations.registerOptions, options)
	return operations.registeredAccount, operations.registerError
}

func (operations *recordingLegoOperations) ObtainForCSR(
	ctx context.Context,
	request certificate.ObtainForCSRRequest,
) (*certificate.Resource, error) {
	operations.obtainRequests = append(operations.obtainRequests, request)
	if operations.obtain != nil {
		return operations.obtain(ctx, request)
	}
	return operations.obtainResource, operations.obtainError
}

type recordingManagedHTTP01Provider struct {
	closeCalls int
	closeError error
}

func (provider *recordingManagedHTTP01Provider) Present(context.Context, string, string, string) error {
	return nil
}

func (provider *recordingManagedHTTP01Provider) CleanUp(context.Context, string, string, string) error {
	return nil
}

func (provider *recordingManagedHTTP01Provider) close(context.Context) error {
	provider.closeCalls++
	return provider.closeError
}

type testACMERequests struct {
	directory int
	accounts  int
	orders    int
}

func newTestACMEDirectoryServer(t *testing.T, externalAccountRequired bool) (*httptest.Server, *testACMERequests) {
	t.Helper()
	requests := &testACMERequests{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/directory":
			requests.directory++
			baseURL := "https://" + request.Host
			response.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(response).Encode(acme.Directory{
				NewNonceURL:   baseURL + "/nonce",
				NewAccountURL: baseURL + "/new-account",
				NewOrderURL:   baseURL + "/new-order",
				Meta: acme.Meta{
					ExternalAccountRequired: externalAccountRequired,
				},
			}); err != nil {
				t.Errorf("encode directory: %v", err)
			}
		case "/new-account":
			requests.accounts++
			http.Error(response, "unexpected account request "+acmeSecretAccount, http.StatusInternalServerError)
		case "/new-order":
			requests.orders++
			http.Error(response, "unexpected order request "+acmeSecretToken, http.StatusInternalServerError)
		default:
			http.NotFound(response, request)
		}
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(server.Close)
	return server, requests
}

func newTestRSAAccountKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testACMEAccount(location string) *acme.ExtendedAccount {
	return &acme.ExtendedAccount{
		Account: acme.Account{
			Status:               acme.StatusValid,
			Contact:              []string{"mailto:admin@localhost"},
			TermsOfServiceAgreed: true,
			Orders:               "https://ca.test/acme/orders/1",
		},
		Location: location,
	}
}

func assertPersistedAccount(t *testing.T, cfg Config, want *acme.ExtendedAccount) {
	t.Helper()
	data, err := os.ReadFile(cfg.AccountFile)
	if err != nil {
		t.Fatal(err)
	}
	var got acme.ExtendedAccount
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode persisted account: %v", err)
	}
	if got.Location != want.Location || got.Status != want.Status ||
		got.TermsOfServiceAgreed != want.TermsOfServiceAgreed ||
		fmt.Sprint(got.Contact) != fmt.Sprint(want.Contact) {
		t.Fatalf("persisted account = %+v, want %+v", got, want)
	}
	assertFileBytesAndMode(t, cfg.AccountFile, data, 0o600)
}

func assertSafeACMEError(t *testing.T, err error, operation string, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s operation unexpectedly succeeded", operation)
	}
	message := err.Error()
	if !strings.Contains(message, operation) {
		t.Fatalf("error %q does not identify %s operation", message, operation)
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(message, value) {
			t.Fatalf("error exposed forbidden value: %q", message)
		}
	}
}
