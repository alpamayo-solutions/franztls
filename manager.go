package franztls

// Manager owns normalized configuration and lifecycle event channels.
type Manager struct {
	cfg     Config
	changes chan CertificateChange
	errors  chan error
}

// New validates config without performing filesystem or network I/O.
func New(config Config) (*Manager, error) {
	cfg, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Manager{
		cfg:     cfg,
		changes: make(chan CertificateChange, 1),
		errors:  make(chan error, 1),
	}, nil
}

// Changes reports committed certificate activations without blocking the manager.
func (m *Manager) Changes() <-chan CertificateChange {
	return m.changes
}

// Errors reports coalesced lifecycle errors without blocking the manager.
func (m *Manager) Errors() <-chan error {
	return m.errors
}
