package franztls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

type normalizedConfig = Config

type issuer interface {
	EnsureAccount(context.Context, crypto.Signer, *acme.ExtendedAccount) (*acme.ExtendedAccount, error)
	Obtain(context.Context, crypto.Signer) ([]byte, error)
	Close(context.Context) error
}

type issuerFactory interface {
	New(context.Context, normalizedConfig, *x509.CertPool, crypto.Signer, *acme.ExtendedAccount) (issuer, error)
}

type legoIssuerFactory struct{}

func (legoIssuerFactory) New(
	ctx context.Context,
	cfg normalizedConfig,
	roots *x509.CertPool,
	accountKey crypto.Signer,
	account *acme.ExtendedAccount,
) (issuer, error) {
	return newLegoIssuer(ctx, cfg, roots, accountKey, account)
}

type legoOperations interface {
	SetHTTP01Provider(challenge.Provider) error
	QueryRegistration(context.Context) (*acme.ExtendedAccount, error)
	ResolveAccountByKey(context.Context) (*acme.ExtendedAccount, error)
	Register(context.Context, registration.RegisterOptions) (*acme.ExtendedAccount, error)
	ObtainForCSR(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error)
}

type managedHTTP01Provider interface {
	challenge.Provider
	close(context.Context) error
}

type legoUser struct {
	mu      sync.RWMutex
	email   string
	key     crypto.Signer
	account *acme.ExtendedAccount
}

func (u *legoUser) GetEmail() string {
	return u.email
}

func (u *legoUser) GetRegistration() *acme.ExtendedAccount {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.account
}

func (u *legoUser) GetPrivateKey() crypto.Signer {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.key
}

func (u *legoUser) setRegistration(account *acme.ExtendedAccount) {
	u.mu.Lock()
	u.account = account
	u.mu.Unlock()
}

type legoIssuer struct {
	cfg            normalizedConfig
	store          *stateStore
	user           *legoUser
	operations     legoOperations
	provider       managedHTTP01Provider
	recoverAccount bool
}

func newLegoIssuer(
	ctx context.Context,
	cfg normalizedConfig,
	roots *x509.CertPool,
	accountKey crypto.Signer,
	account *acme.ExtendedAccount,
) (*legoIssuer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, safeACMEOperationError("directory", err)
	}
	if accountKey == nil {
		return nil, safeACMEOperationError("account", errors.New("missing account key"))
	}

	store := newStateStore(cfg)
	recoverAccount, err := existingAccountKeyNeedsRecovery(store, account)
	if err != nil {
		return nil, err
	}
	user := &legoUser{email: cfg.Email, key: accountKey, account: account}
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = cfg.DirectoryURL
	legoConfig.HTTPClient = newLegoHTTPClient(roots)
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, safeACMEOperationError("directory", err)
	}
	if client.GetServerMetadata().ExternalAccountRequired {
		return nil, ErrExternalAccountBinding
	}

	provider := newHTTP01Provider(cfg.Domain, cfg.HTTP01Address)
	return buildLegoIssuer(
		cfg,
		store,
		user,
		recoverAccount,
		&legoClientOperations{client: client},
		provider,
	)
}

func newLegoIssuerWithOperations(
	cfg normalizedConfig,
	accountKey crypto.Signer,
	account *acme.ExtendedAccount,
	recoverAccount bool,
	operations legoOperations,
	provider managedHTTP01Provider,
) (*legoIssuer, error) {
	user := &legoUser{email: cfg.Email, key: accountKey, account: account}
	return buildLegoIssuer(
		cfg,
		newStateStore(cfg),
		user,
		recoverAccount,
		operations,
		provider,
	)
}

func buildLegoIssuer(
	cfg normalizedConfig,
	store *stateStore,
	user *legoUser,
	recoverAccount bool,
	operations legoOperations,
	provider managedHTTP01Provider,
) (*legoIssuer, error) {
	if operations == nil || provider == nil {
		return nil, safeACMEOperationError("challenge", errors.New("missing challenge dependency"))
	}
	if err := operations.SetHTTP01Provider(provider); err != nil {
		return nil, safeACMEOperationError("challenge", err)
	}
	return &legoIssuer{
		cfg:            cfg,
		store:          store,
		user:           user,
		operations:     operations,
		provider:       provider,
		recoverAccount: recoverAccount,
	}, nil
}

func newLegoHTTPClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		}},
		Timeout: 30 * time.Second,
	}
}

func existingAccountKeyNeedsRecovery(store *stateStore, account *acme.ExtendedAccount) (bool, error) {
	if account != nil {
		return false, nil
	}
	_, err := store.readFile(store.cfg.AccountKeyFile, 0o600, "account_key")
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

type legoClientOperations struct {
	client *lego.Client
}

func (operations *legoClientOperations) SetHTTP01Provider(provider challenge.Provider) error {
	return operations.client.Challenge.SetHTTP01Provider(provider)
}

func (operations *legoClientOperations) QueryRegistration(ctx context.Context) (*acme.ExtendedAccount, error) {
	return operations.client.Registration.QueryRegistration(ctx)
}

func (operations *legoClientOperations) ResolveAccountByKey(ctx context.Context) (*acme.ExtendedAccount, error) {
	return operations.client.Registration.ResolveAccountByKey(ctx)
}

func (operations *legoClientOperations) Register(
	ctx context.Context,
	options registration.RegisterOptions,
) (*acme.ExtendedAccount, error) {
	return operations.client.Registration.Register(ctx, options)
}

func (operations *legoClientOperations) ObtainForCSR(
	ctx context.Context,
	request certificate.ObtainForCSRRequest,
) (*certificate.Resource, error) {
	return operations.client.Certificate.ObtainForCSR(ctx, request)
}

func (i *legoIssuer) EnsureAccount(
	ctx context.Context,
	accountKey crypto.Signer,
	account *acme.ExtendedAccount,
) (*acme.ExtendedAccount, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, safeACMEOperationError("account", err)
	}
	if !sameSigner(i.user.GetPrivateKey(), accountKey) {
		return nil, safeACMEOperationError("account", errors.New("account key changed"))
	}
	i.user.setRegistration(account)

	var (
		resolved *acme.ExtendedAccount
		err      error
	)
	switch {
	case account != nil:
		resolved, err = i.operations.QueryRegistration(ctx)
	case i.recoverAccount:
		resolved, err = i.operations.ResolveAccountByKey(ctx)
	default:
		resolved, err = i.operations.Register(ctx, registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
	}
	if err != nil || resolved == nil || resolved.Location == "" {
		return nil, safeACMEOperationError("account", err)
	}
	if err := i.store.persistAccount(resolved); err != nil {
		return nil, err
	}
	i.user.setRegistration(resolved)
	return resolved, nil
}

func (i *legoIssuer) Obtain(ctx context.Context, domainKey crypto.Signer) (chain []byte, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if closeErr := i.Close(ctx); closeErr != nil && err == nil {
			err = closeErr
			chain = nil
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, safeACMEOperationError("order", err)
	}
	if domainKey == nil {
		return nil, safeACMEOperationError("order", errors.New("missing domain key"))
	}

	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{i.cfg.Domain},
	}, domainKey)
	if err != nil {
		return nil, safeACMEOperationError("order", err)
	}
	csr, err := x509.ParseCertificateRequest(requestDER)
	if err != nil || csr.CheckSignature() != nil {
		return nil, safeACMEOperationError("order", err)
	}
	resource, err := i.operations.ObtainForCSR(ctx, certificate.ObtainForCSRRequest{
		CSR:        csr,
		PrivateKey: domainKey,
		Bundle:     true,
	})
	if err != nil || resource == nil {
		return nil, safeACMEOperationError("order", err)
	}
	certificates, _, err := parseCertificateChain(resource.Certificate)
	if err != nil || len(certificates) < 2 {
		return nil, safeACMEOperationError("order", err)
	}
	if _, err := validateSuppliedChainOrder(certificates); err != nil {
		return nil, safeACMEOperationError("order", err)
	}
	return bytes.Clone(resource.Certificate), nil
}

func (i *legoIssuer) Close(ctx context.Context) error {
	if i == nil || i.provider == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := i.provider.close(ctx); err != nil {
		return safeACMEOperationError("challenge", err)
	}
	return nil
}

func sameSigner(left, right crypto.Signer) bool {
	if left == nil || right == nil {
		return false
	}
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left.Public())
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right.Public())
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}

type acmeOperationError struct {
	operation string
	canceled  bool
	deadline  bool
}

func (e *acmeOperationError) Error() string {
	return "franztls: ACME " + e.operation + " operation failed"
}

func (e *acmeOperationError) Is(target error) bool {
	return (e.canceled && target == context.Canceled) ||
		(e.deadline && target == context.DeadlineExceeded)
}

func safeACMEOperationError(operation string, cause error) error {
	return &acmeOperationError{
		operation: operation,
		canceled:  errors.Is(cause, context.Canceled),
		deadline:  errors.Is(cause, context.DeadlineExceeded),
	}
}

func (p *http01Provider) close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	if !p.started || p.completed {
		p.mu.Unlock()
		return nil
	}
	generation := p.generation
	done := p.doneCh
	shutdown := p.deadlines.shutdown
	p.mu.Unlock()

	p.initiateShutdown(generation)
	timer := time.NewTimer(shutdown)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errors.New("HTTP-01 shutdown canceled")
	case <-timer.C:
		return errors.New("HTTP-01 shutdown timed out")
	}
}
