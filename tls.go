package franztls

import "crypto/tls"

// ClientTLSConfig returns an exclusive-trust mTLS client configuration for
// serverName. The returned configuration reads the manager's active client
// certificate for every handshake so renewals take effect without restart.
func (m *Manager) ClientTLSConfig(serverName string) (*tls.Config, error) {
	if serverName == "" {
		return nil, &ConfigError{
			Field:  "serverName",
			Reason: "must not be empty",
		}
	}
	active := m.current.Load()
	if active == nil || active.roots == nil {
		return nil, ErrNotLoaded
	}

	config := &tls.Config{
		RootCAs:    active.roots.Clone(),
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		current := m.current.Load()
		if current == nil {
			return nil, ErrNotLoaded
		}
		certificate := current.certificate
		return &certificate, nil
	}
	return config, nil
}
