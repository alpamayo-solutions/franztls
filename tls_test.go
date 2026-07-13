package franztls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

const task10HandshakeTimeout = 2 * time.Second

type task10Identity struct {
	certificate tls.Certificate
	leaf        *x509.Certificate
}

func task10NewClientMaterial(t *testing.T, usage []x509.ExtKeyUsage) *testMaterial {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestRoot(t, "franztls Task10 root", now)
	intermediate := newTestIntermediate(t, root, now)
	leafKey := newTestSigner(t, testKeyRSA)
	material := &testMaterial{
		t:                t,
		cfg:              validConfig(storageTempDir(t)),
		now:              now,
		roots:            x509.NewCertPool(),
		leafKey:          leafKey,
		root:             root,
		issuer:           intermediate,
		withIntermediate: true,
		intermediateDER:  intermediate.der,
		leafOptions: testLeafOptions{
			dnsNames:    []string{"historian.internal"},
			commonName:  "historian.internal",
			notBefore:   now.Add(-time.Hour),
			notAfter:    now.Add(24 * time.Hour),
			extKeyUsage: append([]x509.ExtKeyUsage(nil), usage...),
		},
	}
	material.roots.AddCert(root.certificate)
	material.privateKeyPEM = encodeTestPrivateKey(t, leafKey, testKeyPKCS1)
	material.reissueLeaf(material.leafOptions)
	return material
}

func task10NewIdentity(
	t *testing.T,
	now time.Time,
	issuer *testIssuer,
	chainDER [][]byte,
	dnsName string,
	usage []x509.ExtKeyUsage,
) task10Identity {
	t.Helper()
	key := newTestSigner(t, testKeyECDSA)
	options := testLeafOptions{
		dnsNames:    []string{dnsName},
		commonName:  dnsName,
		notBefore:   now.Add(-time.Hour),
		notAfter:    now.Add(8 * time.Hour),
		extKeyUsage: append([]x509.ExtKeyUsage(nil), usage...),
	}
	leafDER, leaf := newTestLeaf(t, options, key, issuer)
	certificateDER := make([][]byte, 0, 1+len(chainDER))
	certificateDER = append(certificateDER, leafDER)
	certificateDER = append(certificateDER, chainDER...)
	certificatePEM := encodeTestCertificateChain(t, certificateDER...)
	privateKeyPEM := encodeTestPrivateKey(t, key, testKeySEC1)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("parse generated TLS identity: %v", err)
	}
	certificate.Leaf = leaf
	return task10Identity{certificate: certificate, leaf: leaf}
}

func task10ConfiguredServerIdentity(t *testing.T, material *testMaterial, dnsName string) task10Identity {
	t.Helper()
	chain := [][]byte(nil)
	if material.withIntermediate {
		chain = [][]byte{material.intermediateDER}
	}
	return task10NewIdentity(
		t,
		material.now,
		material.issuer,
		chain,
		dnsName,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
}

func task10RootSignedServerIdentity(
	t *testing.T,
	now time.Time,
	root *testIssuer,
	dnsName string,
) task10Identity {
	t.Helper()
	return task10NewIdentity(
		t,
		now,
		root,
		nil,
		dnsName,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
}

func task10LoadedManager(t *testing.T, material *testMaterial) *Manager {
	t.Helper()
	writeTestMaterialFiles(t, material.cfg, material)
	manager := newManagerForTest(
		t,
		material.cfg,
		fakeManagerClock{now: material.now},
		&forbiddenIssuerFactory{},
	)
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("Load() TLS material: %v", err)
	}
	assertNoManagerEvents(t, manager)
	return manager
}

func task10ServerConfig(
	identity task10Identity,
	now time.Time,
	clientRoots *x509.CertPool,
	requireClient bool,
) *tls.Config {
	config := &tls.Config{
		Certificates: []tls.Certificate{identity.certificate},
		MinVersion:   tls.VersionTLS12,
		Time: func() time.Time {
			return now
		},
	}
	if requireClient {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = clientRoots
	}
	return config
}

type task10HandshakeOutcome struct {
	side  string
	err   error
	state tls.ConnectionState
}

type task10HandshakeResult struct {
	clientErr   error
	serverErr   error
	clientState tls.ConnectionState
	serverState tls.ConnectionState
}

// task10BufferedPipeConn keeps net.Pipe's deterministic in-memory transport
// while allowing TLS alerts from both peers to cross instead of deadlocking on
// simultaneous synchronous writes.
type task10BufferedPipeConn struct {
	net.Conn
	writes    chan []byte
	done      chan struct{}
	pumpDone  chan struct{}
	closeOnce sync.Once
}

func newTask10BufferedPipeConn(connection net.Conn) *task10BufferedPipeConn {
	buffered := &task10BufferedPipeConn{
		Conn:     connection,
		writes:   make(chan []byte, 64),
		done:     make(chan struct{}),
		pumpDone: make(chan struct{}),
	}
	go buffered.pumpWrites()
	return buffered
}

func (connection *task10BufferedPipeConn) Write(data []byte) (int, error) {
	copyOfData := bytes.Clone(data)
	select {
	case <-connection.done:
		return 0, net.ErrClosed
	case connection.writes <- copyOfData:
		return len(data), nil
	}
}

func (connection *task10BufferedPipeConn) Close() error {
	connection.stop()
	err := connection.Conn.Close()
	<-connection.pumpDone
	return err
}

func (connection *task10BufferedPipeConn) stop() {
	connection.closeOnce.Do(func() { close(connection.done) })
}

func (connection *task10BufferedPipeConn) pumpWrites() {
	defer close(connection.pumpDone)
	for {
		select {
		case <-connection.done:
			return
		case data := <-connection.writes:
			for len(data) > 0 {
				written, err := connection.Conn.Write(data)
				if err != nil {
					connection.stop()
					return
				}
				data = data[written:]
			}
		}
	}
}

func task10PipeHandshake(
	t *testing.T,
	clientConfig *tls.Config,
	serverConfig *tls.Config,
) task10HandshakeResult {
	t.Helper()
	clientPipe, serverPipe := net.Pipe()
	clientRaw := newTask10BufferedPipeConn(clientPipe)
	serverRaw := newTask10BufferedPipeConn(serverPipe)
	defer clientRaw.Close()
	defer serverRaw.Close()
	deadline := time.Now().Add(task10HandshakeTimeout)
	if err := clientRaw.SetDeadline(deadline); err != nil {
		t.Fatalf("set client pipe deadline: %v", err)
	}
	if err := serverRaw.SetDeadline(deadline); err != nil {
		t.Fatalf("set server pipe deadline: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), task10HandshakeTimeout)
	defer cancel()
	client := tls.Client(clientRaw, clientConfig)
	server := tls.Server(serverRaw, serverConfig)
	outcomes := make(chan task10HandshakeOutcome, 2)
	go func() {
		err := client.HandshakeContext(ctx)
		outcomes <- task10HandshakeOutcome{side: "client", err: err, state: client.ConnectionState()}
	}()
	go func() {
		err := server.HandshakeContext(ctx)
		outcomes <- task10HandshakeOutcome{side: "server", err: err, state: server.ConnectionState()}
	}()

	result := task10HandshakeResult{}
	for received := 0; received < 2; received++ {
		select {
		case outcome := <-outcomes:
			switch outcome.side {
			case "client":
				result.clientErr = outcome.err
				result.clientState = outcome.state
			case "server":
				result.serverErr = outcome.err
				result.serverState = outcome.state
			default:
				t.Fatalf("unknown handshake side %q", outcome.side)
			}
			if outcome.err != nil {
				// A peer can be blocked writing its TLS alert after the other side
				// has already returned. Closing both pipe ends reaps it promptly.
				_ = clientRaw.Close()
				_ = serverRaw.Close()
			}
		case <-ctx.Done():
			_ = clientRaw.Close()
			_ = serverRaw.Close()
			for remaining := received; remaining < 2; remaining++ {
				select {
				case <-outcomes:
				case <-time.After(task10HandshakeTimeout):
					t.Fatal("TLS handshake goroutine remained blocked after pipe close")
				}
			}
			t.Fatalf("in-memory TLS handshake exceeded %v", task10HandshakeTimeout)
		}
	}
	return result
}

func task10RequireHandshakeSuccess(t *testing.T, result task10HandshakeResult) {
	t.Helper()
	if result.clientErr != nil || result.serverErr != nil {
		t.Fatalf("TLS handshake errors = client:%v server:%v", result.clientErr, result.serverErr)
	}
}

func task10RequireHandshakeFailure(t *testing.T, result task10HandshakeResult) {
	t.Helper()
	if result.clientErr == nil && result.serverErr == nil {
		t.Fatal("TLS handshake unexpectedly succeeded")
	}
}

type task10RenewedCandidate struct {
	certificatePEM []byte
	signer         crypto.Signer
	leaf           *x509.Certificate
}

func task10NewRenewedCandidate(t *testing.T, material *testMaterial) task10RenewedCandidate {
	t.Helper()
	key := newTestSigner(t, testKeyECDSA)
	options := cloneTestLeafOptions(material.leafOptions)
	options.notBefore = material.now.Add(-time.Hour)
	options.notAfter = material.now.Add(72 * time.Hour)
	leafDER, leaf := newTestLeaf(t, options, key, material.issuer)
	certificatePEM := encodeTestCertificateChain(t, leafDER, material.intermediateDER)
	return task10RenewedCandidate{certificatePEM: certificatePEM, signer: key, leaf: leaf}
}

func task10ClientConfigAt(
	t *testing.T,
	manager *Manager,
	serverName string,
	now time.Time,
) *tls.Config {
	t.Helper()
	config, err := manager.ClientTLSConfig(serverName)
	if err != nil {
		t.Fatalf("ClientTLSConfig(%q): %v", serverName, err)
	}
	config.Time = func() time.Time { return now }
	return config
}

func TestClientTLSConfigBeforeLoadReturnsErrNotLoaded(t *testing.T) {
	material := task10NewClientMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	manager := newManagerForTest(
		t,
		material.cfg,
		fakeManagerClock{now: material.now},
		&forbiddenIssuerFactory{},
	)

	config, err := manager.ClientTLSConfig("mtls.internal")
	if config != nil || !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("ClientTLSConfig before Load = (%v, %T %v), want nil ErrNotLoaded", config, err, err)
	}
}

func TestClientTLSConfigValidatesNameAndUsesExclusiveSafeDefaults(t *testing.T) {
	material := task10NewClientMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	manager := task10LoadedManager(t, material)

	config, err := manager.ClientTLSConfig("")
	var configError *ConfigError
	if config != nil || !errors.As(err, &configError) || configError.Field != "serverName" {
		t.Fatalf("ClientTLSConfig(empty) = (%v, %T %v), want serverName ConfigError", config, err, err)
	}

	config, err = manager.ClientTLSConfig("mtls.internal")
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerName != "mtls.internal" {
		t.Fatalf("ServerName = %q, want mtls.internal", config.ServerName)
	}
	if config.RootCAs == nil {
		t.Fatal("RootCAs is nil")
	}
	if config.RootCAs == manager.current.Load().roots {
		t.Fatal("ClientTLSConfig returned the mutable cached root-pool pointer")
	}
	subjects := config.RootCAs.Subjects()
	if len(subjects) != 1 || !bytes.Equal(subjects[0], material.root.certificate.RawSubject) {
		t.Fatalf("RootCAs subjects = %d, want only configured CA", len(subjects))
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want TLS 1.2", config.MinVersion)
	}
	if config.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is true")
	}
	if len(config.Certificates) != 0 {
		t.Fatalf("static Certificates = %d, want 0", len(config.Certificates))
	}
	if config.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate is nil")
	}
	unrelated := newTestRoot(t, "mutating caller clone", material.now)
	config.RootCAs.AddCert(unrelated.certificate)
	if len(manager.current.Load().roots.Subjects()) != 1 {
		t.Fatal("mutating returned RootCAs changed active configured roots")
	}
	second, err := manager.ClientTLSConfig("mtls.internal")
	if err != nil {
		t.Fatal(err)
	}
	if second.RootCAs == config.RootCAs || second.RootCAs == manager.current.Load().roots {
		t.Fatal("ClientTLSConfig did not return an independently owned root-pool clone")
	}
	if got := second.RootCAs.Subjects(); len(got) != 1 || !bytes.Equal(got[0], material.root.certificate.RawSubject) {
		t.Fatalf("second RootCAs subjects = %d, want only configured CA", len(got))
	}
}

func TestTLSHandshakeAcceptsConfiguredRootSANAndClientCertificate(t *testing.T) {
	material := task10NewClientMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	manager := task10LoadedManager(t, material)
	clientConfig := task10ClientConfigAt(t, manager, "mtls.internal", material.now)
	serverIdentity := task10ConfiguredServerIdentity(t, material, "mtls.internal")
	serverConfig := task10ServerConfig(serverIdentity, material.now, material.roots, true)

	result := task10PipeHandshake(t, clientConfig, serverConfig)
	task10RequireHandshakeSuccess(t, result)
	if result.clientState.Version < tls.VersionTLS12 || result.serverState.Version < tls.VersionTLS12 {
		t.Fatalf("negotiated TLS versions = %#x/%#x, want TLS 1.2+", result.clientState.Version, result.serverState.Version)
	}
	if len(result.serverState.PeerCertificates) == 0 {
		t.Fatal("server did not observe a client certificate")
	}
	gotSerial := result.serverState.PeerCertificates[0].SerialNumber.String()
	wantSerial := material.leaf.SerialNumber.String()
	if gotSerial != wantSerial {
		t.Fatalf("server observed client serial %s, want %s", gotSerial, wantSerial)
	}
}

func TestTLSHandshakeRejectsUnconfiguredTrustWrongSANAndTLS11(t *testing.T) {
	t.Run("unconfigured generated root", func(t *testing.T) {
		material := task10NewClientMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		manager := task10LoadedManager(t, material)
		clientConfig := task10ClientConfigAt(t, manager, "mtls.internal", material.now)
		unconfiguredRoot := newTestRoot(t, "unconfigured generated root", material.now)
		serverIdentity := task10RootSignedServerIdentity(t, material.now, unconfiguredRoot, "mtls.internal")
		serverConfig := task10ServerConfig(serverIdentity, material.now, nil, false)

		result := task10PipeHandshake(t, clientConfig, serverConfig)
		task10RequireHandshakeFailure(t, result)
		if result.clientErr == nil {
			t.Fatal("client accepted a server from an unconfigured generated root")
		}
	})

	t.Run("unrelated private root", func(t *testing.T) {
		material := task10NewClientMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		manager := task10LoadedManager(t, material)
		clientConfig := task10ClientConfigAt(t, manager, "mtls.internal", material.now)
		privateRoot := newTestRoot(t, "unrelated private root", material.now)
		serverIdentity := task10RootSignedServerIdentity(t, material.now, privateRoot, "mtls.internal")
		serverConfig := task10ServerConfig(serverIdentity, material.now, nil, false)

		result := task10PipeHandshake(t, clientConfig, serverConfig)
		task10RequireHandshakeFailure(t, result)
		if result.clientErr == nil {
			t.Fatal("client accepted a server from an unrelated private root")
		}
	})

	t.Run("wrong server SAN", func(t *testing.T) {
		material := task10NewClientMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		manager := task10LoadedManager(t, material)
		clientConfig := task10ClientConfigAt(t, manager, "mtls.internal", material.now)
		serverIdentity := task10ConfiguredServerIdentity(t, material, "other.internal")
		serverConfig := task10ServerConfig(serverIdentity, material.now, nil, false)

		result := task10PipeHandshake(t, clientConfig, serverConfig)
		task10RequireHandshakeFailure(t, result)
		if result.clientErr == nil {
			t.Fatal("client accepted the wrong server SAN")
		}
	})

	t.Run("TLS 1.1 only", func(t *testing.T) {
		material := task10NewClientMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		manager := task10LoadedManager(t, material)
		clientConfig := task10ClientConfigAt(t, manager, "mtls.internal", material.now)
		serverIdentity := task10ConfiguredServerIdentity(t, material, "mtls.internal")
		serverConfig := task10ServerConfig(serverIdentity, material.now, nil, false)
		serverConfig.MinVersion = tls.VersionTLS11
		serverConfig.MaxVersion = tls.VersionTLS11

		result := task10PipeHandshake(t, clientConfig, serverConfig)
		task10RequireHandshakeFailure(t, result)
	})
}

func TestClientTLSConfigRejectsServerAuthOnlyMaterialThroughPublicLoad(t *testing.T) {
	// An omitted EKU is valid for any usage. ServerAuth-only is the
	// deterministic invalid client-auth case required by this boundary.
	material := task10NewClientMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	writeTestMaterialFiles(t, material.cfg, material)
	factory := &forbiddenIssuerFactory{}
	manager := newManagerForTest(
		t,
		material.cfg,
		fakeManagerClock{now: material.now},
		factory,
	)

	err := manager.Load(context.Background())
	var stateError *StateError
	if !errors.As(err, &stateError) || stateError.Kind != "client_auth" {
		t.Fatalf("Load() error = %T %v, want client_auth StateError", err, err)
	}
	if manager.current.Load() != nil {
		t.Fatal("Load activated material without client-auth EKU")
	}
	config, err := manager.ClientTLSConfig("mtls.internal")
	if config != nil || !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("ClientTLSConfig after rejected Load = (%v, %T %v), want nil ErrNotLoaded", config, err, err)
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("rejected local material constructed %d issuers", factory.calls.Load())
	}
}

func TestTLSHandshakeUsesRenewedCertificateFromExistingConfig(t *testing.T) {
	material := task10NewClientMaterial(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	manager := task10LoadedManager(t, material)
	clientConfig := task10ClientConfigAt(t, manager, "mtls.internal", material.now)
	serverIdentity := task10ConfiguredServerIdentity(t, material, "mtls.internal")
	serverConfig := task10ServerConfig(serverIdentity, material.now, material.roots, true)

	firstResult := task10PipeHandshake(t, clientConfig, serverConfig)
	task10RequireHandshakeSuccess(t, firstResult)
	if len(firstResult.serverState.PeerCertificates) == 0 {
		t.Fatal("first handshake did not present a client certificate")
	}
	firstSerial := firstResult.serverState.PeerCertificates[0].SerialNumber.String()

	renewed := task10NewRenewedCandidate(t, material)
	if _, err := manager.store.persistMaterial(
		renewed.certificatePEM,
		renewed.signer,
		material.roots,
		material.now,
	); err != nil {
		t.Fatalf("persist renewed client material: %v", err)
	}
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("Load() renewed client material: %v", err)
	}
	if active := manager.current.Load(); active == nil || active.leaf.SerialNumber.Cmp(renewed.leaf.SerialNumber) != 0 {
		t.Fatal("real persist plus Load did not atomically activate renewed material")
	}
	secondResult := task10PipeHandshake(t, clientConfig, serverConfig)
	task10RequireHandshakeSuccess(t, secondResult)
	if len(secondResult.serverState.PeerCertificates) == 0 {
		t.Fatal("second handshake did not present a client certificate")
	}
	secondSerial := secondResult.serverState.PeerCertificates[0].SerialNumber.String()
	if firstSerial == secondSerial || secondSerial != renewed.leaf.SerialNumber.String() {
		t.Fatalf("client serials = %s then %s, want renewed %s", firstSerial, secondSerial, renewed.leaf.SerialNumber)
	}
}

func TestClientTLSConfigAPIExposesNoPrivateKeyBytesOrSigner(t *testing.T) {
	// Scope this reflection check to direct franztls API results. The returned
	// tls.Config necessarily owns a GetClientCertificate callback whose standard
	// library result contains a signer for the handshake implementation.
	byteSlice := reflect.TypeOf([]byte(nil))
	signer := reflect.TypeOf((*crypto.Signer)(nil)).Elem()
	exposesPrivateMaterial := func(candidate reflect.Type) bool {
		return candidate == byteSlice || candidate.Implements(signer)
	}

	managerValue := reflect.TypeOf(Manager{})
	for index := 0; index < managerValue.NumField(); index++ {
		field := managerValue.Field(index)
		if field.PkgPath == "" && exposesPrivateMaterial(field.Type) {
			t.Fatalf("exported Manager field %s exposes %v", field.Name, field.Type)
		}
	}

	managerPointer := reflect.TypeOf((*Manager)(nil))
	for index := 0; index < managerPointer.NumMethod(); index++ {
		method := managerPointer.Method(index)
		for output := 0; output < method.Type.NumOut(); output++ {
			result := method.Type.Out(output)
			if exposesPrivateMaterial(result) {
				t.Fatalf("exported Manager.%s result %d exposes %v", method.Name, output, result)
			}
		}
	}
}
