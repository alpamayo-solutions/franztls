package franztls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type managerClock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

var (
	errCACertificate              = errors.New("franztls: invalid CA certificate")
	errCertificateRenewalRequired = errors.New("franztls: certificate renewal required")
)

type committedFileIdentity struct {
	certificate [sha256.Size]byte
	privateKey  [sha256.Size]byte
}

type activeMaterial struct {
	certificate tls.Certificate
	leaf        *x509.Certificate
	roots       *x509.CertPool
	fingerprint [sha256.Size]byte
	identity    committedFileIdentity
}

// Manager owns normalized configuration and lifecycle event channels.
type Manager struct {
	cfg           normalizedConfig
	store         *stateStore
	clock         managerClock
	issuerFactory issuerFactory

	mu          sync.Mutex
	current     atomic.Pointer[activeMaterial]
	cachedRoots *x509.CertPool

	changes chan CertificateChange
	errors  chan error
}

// New validates config without performing filesystem or network I/O.
func New(config Config) (*Manager, error) {
	cfg, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return newManager(cfg, wallClock{}, legoIssuerFactory{}), nil
}

func newManager(cfg normalizedConfig, clock managerClock, factory issuerFactory) *Manager {
	return &Manager{
		cfg:           cfg,
		store:         newStateStore(cfg),
		clock:         clock,
		issuerFactory: factory,
		changes:       make(chan CertificateChange, 1),
		errors:        make(chan error, 1),
	}
}

// Load validates and activates only already-committed disk state.
func (m *Manager) Load(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	material, err := m.loadActiveMaterial(ctx, m.clock.Now())
	if err != nil {
		return err
	}
	m.current.Store(material)
	return nil
}

// Ensure reuses valid committed material without constructing an ACME issuer.
func (m *Manager) Ensure(ctx context.Context) (CertificateChange, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return CertificateChange{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return CertificateChange{}, err
	}
	now := m.clock.Now()
	material, err := m.loadActiveMaterial(ctx, now)
	if err != nil {
		return CertificateChange{}, err
	}
	m.current.Store(material)
	change := CertificateChange{NotAfter: material.leaf.NotAfter}
	if !now.Add(m.cfg.RenewBefore).Before(material.leaf.NotAfter) {
		return change, errCertificateRenewalRequired
	}
	return change, nil
}

func (m *Manager) loadActiveMaterial(ctx context.Context, now time.Time) (*activeMaterial, error) {
	roots, err := m.loadRoots(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	privateKeyPEM, err := m.store.readFile(m.cfg.PrivateKeyFile, 0o600, "private_key")
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	certificatePEM, err := m.store.readFile(m.cfg.CertificateFile, 0o644, "certificate")
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parsed, err := parseMaterial(certificatePEM, privateKeyPEM, roots, m.cfg, now)
	if err != nil {
		return nil, err
	}
	return &activeMaterial{
		certificate: parsed.certificate,
		leaf:        parsed.leaf,
		roots:       roots,
		fingerprint: sha256.Sum256(parsed.leaf.Raw),
		identity: committedFileIdentity{
			certificate: sha256.Sum256(certificatePEM),
			privateKey:  sha256.Sum256(privateKeyPEM),
		},
	}, nil
}

func (m *Manager) loadRoots(ctx context.Context) (*x509.CertPool, error) {
	if m.cachedRoots != nil {
		return m.cachedRoots, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	caPEM, err := m.store.readFile(m.cfg.CACertFile, 0o644, "ca_certificate")
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	certificates, _, err := parseCertificateChain(caPEM)
	if err != nil {
		return nil, &StateError{Path: m.cfg.CACertFile, Kind: "ca_certificate", Err: err}
	}
	roots := x509.NewCertPool()
	for _, certificate := range certificates {
		if !certificate.IsCA {
			return nil, &StateError{
				Path: m.cfg.CACertFile,
				Kind: "ca_certificate",
				Err:  errCACertificate,
			}
		}
		roots.AddCert(certificate)
	}
	m.cachedRoots = roots
	return roots, nil
}

// Changes reports committed certificate activations without blocking the manager.
func (m *Manager) Changes() <-chan CertificateChange {
	return m.changes
}

// Errors reports coalesced lifecycle errors without blocking the manager.
func (m *Manager) Errors() <-chan error {
	return m.errors
}
