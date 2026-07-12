package franztls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

type testKeyAlgorithm string

const (
	testKeyRSA   testKeyAlgorithm = "rsa"
	testKeyECDSA testKeyAlgorithm = "ecdsa"
)

type testKeyEncoding string

const (
	testKeyPKCS1 testKeyEncoding = "pkcs1"
	testKeyPKCS8 testKeyEncoding = "pkcs8"
	testKeySEC1  testKeyEncoding = "sec1"
)

type testIssuer struct {
	certificate *x509.Certificate
	key         crypto.Signer
	der         []byte
}

type testLeafOptions struct {
	dnsNames    []string
	commonName  string
	notBefore   time.Time
	notAfter    time.Time
	extKeyUsage []x509.ExtKeyUsage
}

type testMaterial struct {
	t                *testing.T
	cfg              Config
	now              time.Time
	roots            *x509.CertPool
	certificatePEM   []byte
	privateKeyPEM    []byte
	chainDER         [][]byte
	leafDER          []byte
	intermediateDER  []byte
	leaf             *x509.Certificate
	leafKey          crypto.Signer
	leafOptions      testLeafOptions
	issuer           *testIssuer
	withIntermediate bool
}

func newTestMaterial(
	t *testing.T,
	algorithm testKeyAlgorithm,
	encoding testKeyEncoding,
	withIntermediate bool,
	extKeyUsage []x509.ExtKeyUsage,
) *testMaterial {
	t.Helper()

	now := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	root := newTestRoot(t, "franztls test root", now)
	intermediate := newTestIntermediate(t, root, now)
	issuer := root
	if withIntermediate {
		issuer = intermediate
	}

	leafKey := newTestSigner(t, algorithm)
	material := &testMaterial{
		t:                t,
		cfg:              validConfig(t.TempDir()),
		now:              now,
		roots:            x509.NewCertPool(),
		leafKey:          leafKey,
		issuer:           issuer,
		withIntermediate: withIntermediate,
		intermediateDER:  intermediate.der,
		leafOptions: testLeafOptions{
			dnsNames:    []string{"historian.internal"},
			commonName:  "historian.internal",
			notBefore:   now.Add(-time.Hour),
			notAfter:    now.Add(24 * time.Hour),
			extKeyUsage: append([]x509.ExtKeyUsage(nil), extKeyUsage...),
		},
	}
	material.roots.AddCert(root.certificate)
	material.privateKeyPEM = encodeTestPrivateKey(t, leafKey, encoding)
	material.reissueLeaf(material.leafOptions)
	return material
}

func newTestRoot(t *testing.T, commonName string, now time.Time) *testIssuer {
	t.Helper()
	key := newTestSigner(t, testKeyECDSA)
	template := &x509.Certificate{
		SerialNumber:          newTestSerial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
	}
	der := createTestCertificate(t, template, template, key.Public(), key)
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse generated root: %v", err)
	}
	return &testIssuer{certificate: certificate, key: key, der: der}
}

func newTestIntermediate(t *testing.T, parent *testIssuer, now time.Time) *testIssuer {
	t.Helper()
	key := newTestSigner(t, testKeyECDSA)
	template := &x509.Certificate{
		SerialNumber:          newTestSerial(t),
		Subject:               pkix.Name{CommonName: "franztls test intermediate"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(14 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          []byte{6, 7, 8, 9, 10},
	}
	der := createTestCertificate(t, template, parent.certificate, key.Public(), parent.key)
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse generated intermediate: %v", err)
	}
	return &testIssuer{certificate: certificate, key: key, der: der}
}

func (material *testMaterial) reissueLeaf(options testLeafOptions) {
	material.t.Helper()
	material.leafOptions = cloneTestLeafOptions(options)
	der, leaf := newTestLeaf(material.t, options, material.leafKey, material.issuer)
	material.leafDER = der
	material.leaf = leaf
	if material.withIntermediate {
		material.setCertificateChain(der, material.intermediateDER)
		return
	}
	material.setCertificateChain(der)
}

func newTestLeaf(
	t *testing.T,
	options testLeafOptions,
	key crypto.Signer,
	issuer *testIssuer,
) ([]byte, *x509.Certificate) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: newTestSerial(t),
		Subject: pkix.Name{
			CommonName: options.commonName,
		},
		DNSNames:              append([]string(nil), options.dnsNames...),
		NotBefore:             options.notBefore,
		NotAfter:              options.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           append([]x509.ExtKeyUsage(nil), options.extKeyUsage...),
		BasicConstraintsValid: true,
	}
	der := createTestCertificate(
		t,
		template,
		issuer.certificate,
		key.Public(),
		issuer.key,
	)
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse generated leaf: %v", err)
	}
	return der, leaf
}

func (material *testMaterial) setCertificateChain(chain ...[]byte) {
	material.t.Helper()
	material.chainDER = make([][]byte, len(chain))
	for index, der := range chain {
		material.chainDER[index] = bytes.Clone(der)
	}
	material.certificatePEM = encodeTestCertificateChain(material.t, chain...)
}

func cloneTestLeafOptions(options testLeafOptions) testLeafOptions {
	options.dnsNames = append([]string(nil), options.dnsNames...)
	options.extKeyUsage = append([]x509.ExtKeyUsage(nil), options.extKeyUsage...)
	return options
}

func newTestSigner(t *testing.T, algorithm testKeyAlgorithm) crypto.Signer {
	t.Helper()
	switch algorithm {
	case testKeyRSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		return key
	case testKeyECDSA:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ECDSA key: %v", err)
		}
		return key
	default:
		t.Fatalf("unsupported test key algorithm %q", algorithm)
		return nil
	}
}

func encodeTestPrivateKey(t *testing.T, key crypto.Signer, encoding testKeyEncoding) []byte {
	t.Helper()
	var block *pem.Block
	switch encoding {
	case testKeyPKCS1:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("PKCS#1 requires an RSA key, got %T", key)
		}
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}
	case testKeySEC1:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("SEC1 requires an ECDSA key, got %T", key)
		}
		der, err := x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			t.Fatalf("marshal SEC1 private key: %v", err)
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	case testKeyPKCS8:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal PKCS#8 private key: %v", err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	default:
		t.Fatalf("unsupported test key encoding %q", encoding)
	}
	return pem.EncodeToMemory(block)
}

func encodeTestCertificateChain(t *testing.T, chain ...[]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	for _, der := range chain {
		if err := pem.Encode(&output, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatalf("encode certificate PEM: %v", err)
		}
	}
	return output.Bytes()
}

func createTestCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey any,
	issuerKey crypto.Signer,
) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, issuerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func newTestSerial(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		t.Fatalf("generate certificate serial: %v", err)
	}
	if serial.Sign() == 0 {
		return big.NewInt(1)
	}
	return serial
}

func corruptCertificatePEM(material *testMaterial) {
	material.certificatePEM = []byte("not a PEM certificate")
}

func reverseChain(material *testMaterial) {
	material.setCertificateChain(material.intermediateDER, material.leafDER)
}

func useWrongSAN(material *testMaterial) {
	options := cloneTestLeafOptions(material.leafOptions)
	options.dnsNames = []string{"other.internal"}
	material.reissueLeaf(options)
}

func removeSANKeepCN(material *testMaterial) {
	options := cloneTestLeafOptions(material.leafOptions)
	options.dnsNames = nil
	options.commonName = material.cfg.Domain
	material.reissueLeaf(options)
}

func moveValidityForward(material *testMaterial) {
	options := cloneTestLeafOptions(material.leafOptions)
	options.notBefore = material.now.Add(time.Minute)
	options.notAfter = material.now.Add(24 * time.Hour)
	material.reissueLeaf(options)
}

func expireLeaf(material *testMaterial) {
	options := cloneTestLeafOptions(material.leafOptions)
	options.notBefore = material.now.Add(-24 * time.Hour)
	options.notAfter = material.now
	material.reissueLeaf(options)
}

func removeIntermediate(material *testMaterial) {
	material.setCertificateChain(material.leafDER)
}

func swapRoot(material *testMaterial) {
	otherRoot := newTestRoot(material.t, "untrusted test root", material.now)
	material.roots = x509.NewCertPool()
	material.roots.AddCert(otherRoot.certificate)
}

func removeClientAuth(material *testMaterial) {
	options := cloneTestLeafOptions(material.leafOptions)
	options.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	material.reissueLeaf(options)
}

func replacePrivateKey(material *testMaterial) {
	replacement := newTestSigner(material.t, testKeyRSA)
	material.privateKeyPEM = encodeTestPrivateKey(material.t, replacement, testKeyPKCS1)
}

func corruptPrivateKeyPEM(material *testMaterial) {
	material.privateKeyPEM = []byte("not a PEM private key")
}
