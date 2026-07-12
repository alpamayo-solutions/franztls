package franztls

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func TestParsePrivateKeyAcceptsSupportedFormats(t *testing.T) {
	tests := []struct {
		name      string
		algorithm testKeyAlgorithm
		encoding  testKeyEncoding
	}{
		{name: "rsa-pkcs1", algorithm: testKeyRSA, encoding: testKeyPKCS1},
		{name: "rsa-pkcs8", algorithm: testKeyRSA, encoding: testKeyPKCS8},
		{name: "ecdsa-sec1", algorithm: testKeyECDSA, encoding: testKeySEC1},
		{name: "ecdsa-pkcs8", algorithm: testKeyECDSA, encoding: testKeyPKCS8},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := newTestSigner(t, test.algorithm)
			keyPEM := encodeTestPrivateKey(t, want, test.encoding)

			got, err := parsePrivateKey(keyPEM)
			if err != nil {
				t.Fatalf("parsePrivateKey() error = %v", err)
			}
			assertSamePublicKey(t, got, want)
		})
	}
}

func TestParsePrivateKeyRejectsMalformedInput(t *testing.T) {
	validKey := newTestSigner(t, testKeyECDSA)
	validPEM := encodeTestPrivateKey(t, validKey, testKeySEC1)
	_, unsupportedKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	unsupportedDER, err := x509.MarshalPKCS8PrivateKey(unsupportedKey)
	if err != nil {
		t.Fatalf("marshal Ed25519 key: %v", err)
	}

	tests := []struct {
		name string
		key  []byte
	}{
		{name: "empty", key: nil},
		{name: "garbage", key: []byte("not a private key")},
		{
			name: "leading garbage",
			key:  append([]byte("garbage\n"), validPEM...),
		},
		{
			name: "trailing garbage",
			key:  append(bytes.Clone(validPEM), []byte("garbage\n")...),
		},
		{
			name: "multiple blocks",
			key: append(
				bytes.Clone(validPEM),
				pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})...,
			),
		},
		{
			name: "certificate block",
			key:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
		},
		{
			name: "encrypted block",
			key:  pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		},
		{
			name: "unsupported PKCS8 signer",
			key:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: unsupportedDER}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if key, err := parsePrivateKey(test.key); err == nil {
				t.Fatalf("parsePrivateKey() = (%T, nil), want error", key)
			}
		})
	}
}

func TestValidateMaterialAcceptsParsedSigner(t *testing.T) {
	fixture := newTestMaterial(
		t,
		testKeyECDSA,
		testKeySEC1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	signer, err := parsePrivateKey(fixture.privateKeyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey() error = %v", err)
	}

	material, err := validateMaterial(
		fixture.certificatePEM,
		signer,
		fixture.roots,
		fixture.cfg,
		fixture.now,
	)
	if err != nil {
		t.Fatalf("validateMaterial() error = %v", err)
	}
	if material.leaf == nil || !bytes.Equal(material.leaf.Raw, fixture.leafDER) {
		t.Fatal("validateMaterial() did not retain the leaf certificate")
	}
}

func TestValidateMaterialRejectsInvalidState(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*testMaterial)
		wantKind string
		wantPath func(Config) string
	}{
		{"corrupt-pem", corruptCertificatePEM, "certificate_pem", func(cfg Config) string { return cfg.CertificateFile }},
		{"chain-not-leaf-first", reverseChain, "chain_order", func(cfg Config) string { return cfg.CertificateFile }},
		{"wrong-san", useWrongSAN, "dns_san", func(cfg Config) string { return cfg.CertificateFile }},
		{"cn-only", removeSANKeepCN, "dns_san", func(cfg Config) string { return cfg.CertificateFile }},
		{"not-yet-valid", moveValidityForward, "not_yet_valid", func(cfg Config) string { return cfg.CertificateFile }},
		{"expired", expireLeaf, "expired", func(cfg Config) string { return cfg.CertificateFile }},
		{"missing-intermediate", removeIntermediate, "chain", func(cfg Config) string { return cfg.CertificateFile }},
		{"untrusted-root", swapRoot, "chain", func(cfg Config) string { return cfg.CertificateFile }},
		{"server-auth-only", removeClientAuth, "client_auth", func(cfg Config) string { return cfg.CertificateFile }},
		{"mismatched-key", replacePrivateKey, "key_mismatch", func(cfg Config) string { return cfg.PrivateKeyFile }},
		{"corrupt-key", corruptPrivateKeyPEM, "private_key", func(cfg Config) string { return cfg.PrivateKeyFile }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestMaterial(
				t,
				testKeyECDSA,
				testKeySEC1,
				true,
				[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			)
			test.mutate(fixture)

			material, err := parseMaterial(
				fixture.certificatePEM,
				fixture.privateKeyPEM,
				fixture.roots,
				fixture.cfg,
				fixture.now,
			)
			if err == nil {
				t.Fatalf("parseMaterial() = (%v, nil), want %q error", material, test.wantKind)
			}
			if material != nil {
				t.Fatalf("parseMaterial() material = %v, want nil", material)
			}
			assertStateError(t, err, test.wantPath(fixture.cfg), test.wantKind)
		})
	}
}

func TestValidateMaterialAcceptsSupportedState(t *testing.T) {
	tests := []struct {
		name             string
		algorithm        testKeyAlgorithm
		encoding         testKeyEncoding
		withIntermediate bool
		extKeyUsage      []x509.ExtKeyUsage
	}{
		{
			name:             "rsa-pkcs1",
			algorithm:        testKeyRSA,
			encoding:         testKeyPKCS1,
			withIntermediate: true,
			extKeyUsage:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:             "rsa-pkcs8",
			algorithm:        testKeyRSA,
			encoding:         testKeyPKCS8,
			withIntermediate: true,
			extKeyUsage:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:             "ecdsa-sec1",
			algorithm:        testKeyECDSA,
			encoding:         testKeySEC1,
			withIntermediate: true,
			extKeyUsage:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:             "ecdsa-pkcs8",
			algorithm:        testKeyECDSA,
			encoding:         testKeyPKCS8,
			withIntermediate: true,
			extKeyUsage:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:             "explicit-client-auth-eku-direct-root",
			algorithm:        testKeyECDSA,
			encoding:         testKeySEC1,
			withIntermediate: false,
			extKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			},
		},
		{
			name:             "no-eku-restriction",
			algorithm:        testKeyECDSA,
			encoding:         testKeyPKCS8,
			withIntermediate: true,
			extKeyUsage:      nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestMaterial(
				t,
				test.algorithm,
				test.encoding,
				test.withIntermediate,
				test.extKeyUsage,
			)

			material, err := parseMaterial(
				fixture.certificatePEM,
				fixture.privateKeyPEM,
				fixture.roots,
				fixture.cfg,
				fixture.now,
			)
			if err != nil {
				t.Fatalf("parseMaterial() error = %v", err)
			}
			if material.leaf == nil || !bytes.Equal(material.leaf.Raw, fixture.leafDER) {
				t.Fatal("parsed leaf does not match the first certificate")
			}
			if !material.leaf.NotAfter.Equal(fixture.leaf.NotAfter) {
				t.Fatalf("NotAfter = %v, want leaf expiry %v", material.leaf.NotAfter, fixture.leaf.NotAfter)
			}
			if material.certificate.Leaf != material.leaf {
				t.Fatal("tls.Certificate.Leaf does not reference parsed leaf")
			}
			if material.certificate.PrivateKey == nil {
				t.Fatal("tls.Certificate.PrivateKey is nil")
			}
			if got, want := len(material.certificate.Certificate), len(fixture.chainDER); got != want {
				t.Fatalf("certificate chain length = %d, want %d", got, want)
			}
			for index, wantDER := range fixture.chainDER {
				if !bytes.Equal(material.certificate.Certificate[index], wantDER) {
					t.Fatalf("certificate chain element %d changed or reordered", index)
				}
			}
		})
	}
}

func TestValidateMaterialRejectsStrictCertificatePEMViolations(t *testing.T) {
	fixture := newTestMaterial(
		t,
		testKeyECDSA,
		testKeySEC1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	signer, err := parsePrivateKey(fixture.privateKeyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey() error = %v", err)
	}

	tests := []struct {
		name        string
		certificate []byte
	}{
		{name: "empty", certificate: nil},
		{name: "leading garbage", certificate: append([]byte("garbage\n"), fixture.certificatePEM...)},
		{name: "trailing garbage", certificate: append(bytes.Clone(fixture.certificatePEM), []byte("garbage\n")...)},
		{
			name: "trailing private-key block",
			certificate: append(
				bytes.Clone(fixture.certificatePEM),
				fixture.privateKeyPEM...,
			),
		},
		{
			name: "malformed later certificate",
			certificate: append(
				bytes.Clone(fixture.certificatePEM),
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})...,
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material, err := validateMaterial(test.certificate, signer, fixture.roots, fixture.cfg, fixture.now)
			if err == nil {
				t.Fatalf("validateMaterial() = (%v, nil), want certificate_pem error", material)
			}
			assertStateError(t, err, fixture.cfg.CertificateFile, "certificate_pem")
		})
	}
}

func TestValidateMaterialRejectsWildcardOnlySAN(t *testing.T) {
	fixture := newTestMaterial(
		t,
		testKeyECDSA,
		testKeySEC1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	options := cloneTestLeafOptions(fixture.leafOptions)
	options.dnsNames = []string{"*.internal"}
	fixture.reissueLeaf(options)

	material, err := parseMaterial(
		fixture.certificatePEM,
		fixture.privateKeyPEM,
		fixture.roots,
		fixture.cfg,
		fixture.now,
	)
	if err == nil {
		t.Fatalf("parseMaterial() = (%v, nil), want dns_san error", material)
	}
	assertStateError(t, err, fixture.cfg.CertificateFile, "dns_san")
}

func TestValidateMaterialAcceptsNotBeforeBoundary(t *testing.T) {
	fixture := newTestMaterial(
		t,
		testKeyECDSA,
		testKeySEC1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	options := cloneTestLeafOptions(fixture.leafOptions)
	options.notBefore = fixture.now
	options.notAfter = fixture.now.Add(time.Hour)
	fixture.reissueLeaf(options)

	if _, err := parseMaterial(
		fixture.certificatePEM,
		fixture.privateKeyPEM,
		fixture.roots,
		fixture.cfg,
		fixture.now,
	); err != nil {
		t.Fatalf("parseMaterial() at NotBefore boundary error = %v", err)
	}
}

func assertSamePublicKey(t *testing.T, got crypto.Signer, want crypto.Signer) {
	t.Helper()
	gotDER, err := x509.MarshalPKIXPublicKey(got.Public())
	if err != nil {
		t.Fatalf("marshal parsed public key: %v", err)
	}
	wantDER, err := x509.MarshalPKIXPublicKey(want.Public())
	if err != nil {
		t.Fatalf("marshal expected public key: %v", err)
	}
	if !bytes.Equal(gotDER, wantDER) {
		t.Fatal("parsed public key does not match input")
	}
}

func assertStateError(t *testing.T, err error, wantPath string, wantKind string) {
	t.Helper()
	var stateErr *StateError
	if !errors.As(err, &stateErr) {
		t.Fatalf("error = %T %v, want *StateError", err, err)
	}
	if stateErr.Path != wantPath {
		t.Fatalf("StateError.Path = %q, want %q", stateErr.Path, wantPath)
	}
	if stateErr.Kind != wantKind {
		t.Fatalf("StateError.Kind = %q, want %q", stateErr.Kind, wantKind)
	}
}
