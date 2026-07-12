package franztls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	errCertificatePEM         = errors.New("franztls: invalid certificate PEM")
	errCertificateChain       = errors.New("franztls: certificate chain verification failed")
	errCertificateChainOrder  = errors.New("franztls: certificate chain is not leaf-first")
	errCertificateDNS         = errors.New("franztls: certificate does not contain the configured DNS SAN")
	errCertificateNotYetValid = errors.New("franztls: certificate is not yet valid")
	errCertificateExpired     = errors.New("franztls: certificate is expired")
	errCertificateClientAuth  = errors.New("franztls: certificate is not valid for client authentication")
	errPrivateKey             = errors.New("franztls: invalid private key")
	errPrivateKeyMismatch     = errors.New("franztls: private key does not match certificate")
)

type certificateMaterial struct {
	certificate tls.Certificate
	leaf        *x509.Certificate
}

func parseMaterial(
	certificatePEM []byte,
	privateKeyPEM []byte,
	roots *x509.CertPool,
	cfg Config,
	now time.Time,
) (*certificateMaterial, error) {
	certificates, chainDER, err := parseCertificateChain(certificatePEM)
	if err != nil {
		return nil, &StateError{Path: cfg.CertificateFile, Kind: "certificate_pem", Err: err}
	}
	signer, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, &StateError{Path: cfg.PrivateKeyFile, Kind: "private_key", Err: err}
	}
	return validateParsedMaterial(certificates, chainDER, signer, roots, cfg, now)
}

func validateMaterial(
	certificatePEM []byte,
	signer crypto.Signer,
	roots *x509.CertPool,
	cfg Config,
	now time.Time,
) (*certificateMaterial, error) {
	certificates, chainDER, err := parseCertificateChain(certificatePEM)
	if err != nil {
		return nil, &StateError{Path: cfg.CertificateFile, Kind: "certificate_pem", Err: err}
	}
	return validateParsedMaterial(certificates, chainDER, signer, roots, cfg, now)
}

func validateParsedMaterial(
	certificates []*x509.Certificate,
	chainDER [][]byte,
	signer crypto.Signer,
	roots *x509.CertPool,
	cfg Config,
	now time.Time,
) (*certificateMaterial, error) {
	leaf := certificates[0]
	if kind, err := validateSuppliedChainOrder(certificates); err != nil {
		return nil, &StateError{Path: cfg.CertificateFile, Kind: kind, Err: err}
	}
	if !containsExactDNSName(leaf.DNSNames, cfg.Domain) {
		return nil, &StateError{Path: cfg.CertificateFile, Kind: "dns_san", Err: errCertificateDNS}
	}
	if now.Before(leaf.NotBefore) {
		return nil, &StateError{Path: cfg.CertificateFile, Kind: "not_yet_valid", Err: errCertificateNotYetValid}
	}
	if !now.Before(leaf.NotAfter) {
		return nil, &StateError{Path: cfg.CertificateFile, Kind: "expired", Err: errCertificateExpired}
	}
	if !allowsClientAuthentication(leaf) {
		return nil, &StateError{Path: cfg.CertificateFile, Kind: "client_auth", Err: errCertificateClientAuth}
	}
	if roots == nil {
		return nil, &StateError{Path: cfg.CertificateFile, Kind: "chain", Err: errCertificateChain}
	}

	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       cfg.Domain,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil || len(chains) == 0 {
		if err == nil {
			err = errCertificateChain
		}
		return nil, &StateError{
			Path: cfg.CertificateFile,
			Kind: classifyVerifyError(err),
			Err:  err,
		}
	}

	if err := validateMatchingPublicKey(leaf, signer); err != nil {
		kind := "key_mismatch"
		if !errors.Is(err, errPrivateKeyMismatch) {
			kind = "private_key"
		}
		return nil, &StateError{Path: cfg.PrivateKeyFile, Kind: kind, Err: err}
	}

	tlsCertificate := tls.Certificate{
		Certificate: chainDER,
		PrivateKey:  signer,
		Leaf:        leaf,
	}
	return &certificateMaterial{certificate: tlsCertificate, leaf: leaf}, nil
}

func parseCertificateChain(certificatePEM []byte) ([]*x509.Certificate, [][]byte, error) {
	remaining := bytes.TrimSpace(certificatePEM)
	if len(remaining) == 0 {
		return nil, nil, errCertificatePEM
	}

	var certificates []*x509.Certificate
	var chainDER [][]byte
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, nil, errCertificatePEM
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errCertificatePEM
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: malformed certificate DER", errCertificatePEM)
		}
		certificates = append(certificates, certificate)
		chainDER = append(chainDER, bytes.Clone(block.Bytes))
		remaining = bytes.TrimSpace(rest)
	}
	return certificates, chainDER, nil
}

func parsePrivateKey(privateKeyPEM []byte) (crypto.Signer, error) {
	remaining := bytes.TrimSpace(privateKeyPEM)
	if len(remaining) == 0 || !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
		return nil, errPrivateKey
	}
	block, rest := pem.Decode(remaining)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errPrivateKey
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed PKCS#1 key", errPrivateKey)
		}
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("%w: invalid RSA key", errPrivateKey)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed SEC1 key", errPrivateKey)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed PKCS#8 key", errPrivateKey)
		}
		switch key := key.(type) {
		case *rsa.PrivateKey:
			if err := key.Validate(); err != nil {
				return nil, fmt.Errorf("%w: invalid RSA key", errPrivateKey)
			}
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("%w: unsupported PKCS#8 signer", errPrivateKey)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported PEM block", errPrivateKey)
	}
}

func validateSuppliedChainOrder(certificates []*x509.Certificate) (string, error) {
	if len(certificates) == 0 {
		return "certificate_pem", errCertificatePEM
	}
	if certificates[0].IsCA {
		return "chain_order", errCertificateChainOrder
	}
	for _, certificate := range certificates[1:] {
		if !certificate.IsCA {
			return "chain_order", errCertificateChainOrder
		}
	}
	for index := 0; index+1 < len(certificates); index++ {
		if certificates[index].CheckSignatureFrom(certificates[index+1]) == nil {
			continue
		}
		for later := index + 2; later < len(certificates); later++ {
			if certificates[index].CheckSignatureFrom(certificates[later]) == nil {
				return "chain_order", errCertificateChainOrder
			}
		}
		return "chain", errCertificateChain
	}
	return "", nil
}

func containsExactDNSName(dnsNames []string, domain string) bool {
	for _, dnsName := range dnsNames {
		if strings.EqualFold(dnsName, domain) {
			return true
		}
	}
	return false
}

func allowsClientAuthentication(certificate *x509.Certificate) bool {
	if len(certificate.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func classifyVerifyError(err error) string {
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return "dns_san"
	}
	var certificateError x509.CertificateInvalidError
	if errors.As(err, &certificateError) && certificateError.Reason == x509.IncompatibleUsage {
		return "client_auth"
	}
	return "chain"
}

func validateMatchingPublicKey(leaf *x509.Certificate, signer crypto.Signer) error {
	if signer == nil {
		return errPrivateKey
	}
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		if key == nil {
			return errPrivateKey
		}
	case *ecdsa.PrivateKey:
		if key == nil {
			return errPrivateKey
		}
	default:
		return errPrivateKey
	}

	leafPublicKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: unsupported certificate public key", errPrivateKey)
	}
	signerPublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("%w: unsupported signer public key", errPrivateKey)
	}
	if !bytes.Equal(leafPublicKey, signerPublicKey) {
		return errPrivateKeyMismatch
	}
	return nil
}
