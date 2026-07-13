package franztls

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
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
	errCACertificate = errors.New("franztls: invalid CA certificate")
	errMaterialState = errors.New("franztls: inconsistent certificate material state")
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

type domainIssueState struct {
	roots             *x509.CertPool
	material          *activeMaterial
	signer            crypto.Signer
	privateKeyPEM     []byte
	persistPrivateKey bool
}

// Manager owns normalized configuration and lifecycle event channels.
type Manager struct {
	cfg           normalizedConfig
	store         *stateStore
	clock         managerClock
	runClock      renewalClock
	runRandom     renewalRandom
	issuerFactory issuerFactory
	lock          issueLock

	mu            sync.Mutex
	eventMu       sync.Mutex
	runActive     atomic.Bool
	current       atomic.Pointer[activeMaterial]
	cachedRoots   *x509.CertPool
	publishChange func(CertificateChange)

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
	manager := &Manager{
		cfg:           cfg,
		store:         newStateStore(cfg),
		clock:         clock,
		runClock:      runtimeRenewalClock{},
		runRandom:     runtimeRenewalRandom{},
		issuerFactory: factory,
		lock:          newIssueLock(cfg),
		changes:       make(chan CertificateChange, 1),
		errors:        make(chan error, 1),
	}
	manager.publishChange = manager.enqueueChange
	return manager
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

// Ensure reuses non-due committed material without creating or waiting on an
// advisory lock. Issuance and renewal re-read state while holding the lock
// through durable persistence, activation, publication, and cleanup.
func (m *Manager) Ensure(ctx context.Context) (change CertificateChange, err error) {
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
	if material, loadErr := m.loadActiveMaterial(ctx, now); loadErr == nil {
		material = m.retainOrActivate(material)
		if !renewalDue(now, m.cfg.RenewBefore, material.leaf.NotAfter) {
			return CertificateChange{NotAfter: material.leaf.NotAfter}, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return m.failureResult(err)
	}

	release, acquireErr := m.lock.Acquire(ctx)
	if acquireErr != nil {
		return m.failureResult(acquireErr)
	}
	defer func() {
		err = errors.Join(err, release())
	}()
	if err := ctx.Err(); err != nil {
		return m.failureResult(err)
	}
	if cleanupErr := m.store.cleanupStaleTemporaryFiles(); cleanupErr != nil {
		return m.failureResult(cleanupErr)
	}
	// Lock acquisition and recovery may have waited behind another complete
	// issuance. All due checks below use fresh time.
	now = m.clock.Now()

	return m.ensureLocked(ctx, now)
}

func (m *Manager) ensureLocked(ctx context.Context, now time.Time) (change CertificateChange, err error) {
	state, err := m.inspectDomainState(ctx, now)
	if err != nil {
		return m.failureResult(err)
	}
	if state.material != nil {
		state.material = m.retainOrActivate(state.material)
		if !renewalDue(now, m.cfg.RenewBefore, state.material.leaf.NotAfter) {
			return CertificateChange{NotAfter: state.material.leaf.NotAfter}, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return m.failureResult(err)
	}

	account, err := m.store.loadAccountState()
	if err != nil {
		return m.failureResult(err)
	}
	if err := ctx.Err(); err != nil {
		return m.failureResult(err)
	}

	acmeIssuer, err := m.issuerFactory.New(
		ctx,
		m.cfg,
		state.roots,
		account.accountKey,
		account.account,
	)
	if err != nil {
		return m.failureResult(err)
	}
	defer func() {
		closeErr := acmeIssuer.Close(context.WithoutCancel(ctx))
		err = errors.Join(err, closeErr)
	}()

	if !account.accountKeyExisted {
		if err := ctx.Err(); err != nil {
			return m.failureResult(err)
		}
		if err := m.store.writeFile(
			m.cfg.AccountKeyFile,
			account.accountKeyPEM,
			0o600,
			"account_key",
		); err != nil {
			return m.failureResult(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return m.failureResult(err)
	}
	resolved, err := acmeIssuer.EnsureAccount(ctx, account.accountKey, account.account)
	if err != nil {
		return m.failureResult(err)
	}
	if resolved == nil || resolved.Location == "" {
		return m.failureResult(&StateError{
			Path: m.cfg.AccountFile,
			Kind: "account",
			Err:  errAccountState,
		})
	}
	if err := ctx.Err(); err != nil {
		return m.failureResult(err)
	}

	certificatePEM, err := acmeIssuer.Obtain(ctx, state.signer)
	if err != nil {
		return m.failureResult(err)
	}
	if err := ctx.Err(); err != nil {
		return m.failureResult(err)
	}
	now = m.clock.Now()
	persisted, err := m.store.persistIssuedMaterial(
		certificatePEM,
		state.signer,
		state.privateKeyPEM,
		state.persistPrivateKey,
		state.roots,
		now,
	)
	if err != nil {
		return m.failureResult(err)
	}
	// A successful persist means the certificate commit marker is durable.
	// Activation must now converge with disk even if the caller canceled at
	// that instant; the validated bytes and signer are already in hand.
	committed := activeMaterialFromParsed(
		persisted,
		certificatePEM,
		state.privateKeyPEM,
		state.roots,
	)
	m.current.Store(committed)
	change = CertificateChange{Renewed: true, NotAfter: committed.leaf.NotAfter}
	if m.publishChange != nil {
		m.publishChange(change)
	}
	return change, nil
}

func (m *Manager) inspectDomainState(ctx context.Context, now time.Time) (domainIssueState, error) {
	roots, err := m.loadRoots(ctx)
	if err != nil {
		return domainIssueState{}, err
	}
	if err := ctx.Err(); err != nil {
		return domainIssueState{}, err
	}

	privateKeyPEM, privateKeyErr := m.store.readFile(
		m.cfg.PrivateKeyFile,
		0o600,
		"private_key",
	)
	if err := ctx.Err(); err != nil {
		return domainIssueState{}, err
	}
	certificatePEM, certificateErr := m.store.readFile(
		m.cfg.CertificateFile,
		0o644,
		"certificate",
	)
	if err := ctx.Err(); err != nil {
		return domainIssueState{}, err
	}

	privateKeyMissing := errors.Is(privateKeyErr, fs.ErrNotExist)
	certificateMissing := errors.Is(certificateErr, fs.ErrNotExist)
	if privateKeyErr != nil && !privateKeyMissing {
		return domainIssueState{}, privateKeyErr
	}
	if certificateErr != nil && !certificateMissing {
		return domainIssueState{}, certificateErr
	}
	if privateKeyMissing {
		if !certificateMissing {
			return domainIssueState{}, &StateError{
				Path: m.cfg.PrivateKeyFile,
				Kind: "material_state",
				Err:  errMaterialState,
			}
		}
		signer, encoded, err := generateRSAKeyPEM()
		if err != nil {
			return domainIssueState{}, &StateError{
				Path: m.cfg.PrivateKeyFile,
				Kind: "private_key",
				Err:  err,
			}
		}
		return domainIssueState{
			roots:             roots,
			signer:            signer,
			privateKeyPEM:     encoded,
			persistPrivateKey: true,
		}, nil
	}

	signer, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return domainIssueState{}, &StateError{
			Path: m.cfg.PrivateKeyFile,
			Kind: "private_key",
			Err:  err,
		}
	}
	state := domainIssueState{
		roots:         roots,
		signer:        signer,
		privateKeyPEM: privateKeyPEM,
	}
	if certificateMissing {
		return state, nil
	}

	parsed, err := parseMaterial(certificatePEM, privateKeyPEM, roots, m.cfg, now)
	if err == nil {
		state.material = activeMaterialFromParsed(parsed, certificatePEM, privateKeyPEM, roots)
		return state, nil
	}
	// A readable, safely-opened certificate that no longer validates can be
	// replaced with a new chain using the existing domain identity.
	return state, nil
}

func renewalDue(now time.Time, renewBefore time.Duration, notAfter time.Time) bool {
	return !now.Add(renewBefore).Before(notAfter)
}

func (m *Manager) retainOrActivate(candidate *activeMaterial) *activeMaterial {
	current := m.current.Load()
	if current != nil &&
		current.identity == candidate.identity &&
		current.fingerprint == candidate.fingerprint {
		return current
	}
	m.current.Store(candidate)
	return candidate
}

func (m *Manager) failureResult(cause error) (CertificateChange, error) {
	if cause == nil {
		cause = ErrNotLoaded
	}
	now := m.clock.Now()
	current := m.current.Load()
	if current != nil && current.leaf != nil && now.Before(current.leaf.NotAfter) {
		change := CertificateChange{NotAfter: current.leaf.NotAfter}
		return change, &DeferredRenewalError{
			NotAfter: current.leaf.NotAfter,
			Err:      cause,
		}
	}
	return CertificateChange{}, errors.Join(ErrNoUsableCertificate, cause)
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
	return activeMaterialFromParsed(parsed, certificatePEM, privateKeyPEM, roots), nil
}

func activeMaterialFromParsed(
	parsed *certificateMaterial,
	certificatePEM []byte,
	privateKeyPEM []byte,
	roots *x509.CertPool,
) *activeMaterial {
	return &activeMaterial{
		certificate: parsed.certificate,
		leaf:        parsed.leaf,
		roots:       roots,
		fingerprint: sha256.Sum256(parsed.leaf.Raw),
		identity: committedFileIdentity{
			certificate: sha256.Sum256(certificatePEM),
			privateKey:  sha256.Sum256(privateKeyPEM),
		},
	}
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

func (m *Manager) enqueueChange(change CertificateChange) {
	m.eventMu.Lock()
	defer m.eventMu.Unlock()
	publishLatest(m.changes, change)
}

func (m *Manager) enqueueError(err error) {
	m.eventMu.Lock()
	defer m.eventMu.Unlock()
	publishLatest(m.errors, err)
}

// Changes reports committed certificate activations without blocking the manager.
func (m *Manager) Changes() <-chan CertificateChange {
	return m.changes
}

// Errors reports coalesced lifecycle errors without blocking the manager.
func (m *Manager) Errors() <-chan error {
	return m.errors
}
