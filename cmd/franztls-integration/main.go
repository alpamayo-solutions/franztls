package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	franztls "github.com/alpamayo-solutions/franztls"
)

const (
	defaultDirectoryURL = "https://ca:9000/acme/acme/directory"
	defaultStateDir     = "/etc/certs"
	defaultCACertFile   = "/etc/certs/prekit-ca.crt"
	defaultServerName   = "mtls-server"
	defaultServerAddr   = "mtls-server:8443"
	defaultListenAddr   = ":8443"
	commandTimeout      = 10 * time.Second
)

type managerAPI interface {
	Load(context.Context) error
	Ensure(context.Context) (franztls.CertificateChange, error)
	ClientTLSConfig(string) (*tls.Config, error)
}

type commonFlags struct {
	directory   string
	renewBefore time.Duration
}

type storageOptions struct {
	stateDir string
	caFile   string
}

type serveOptions struct {
	listen          string
	certificateFile string
	privateKeyFile  string
	caFile          string
}

type handshakeOptions struct {
	address    string
	serverName string
}

type certificateRecord struct {
	Serial string `json:"serial"`
	Expiry string `json:"expiry"`
}

type peerRecord struct {
	Serial string `json:"serial"`
}

type storageRecord struct {
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	StateMode     string `json:"state_mode"`
	StateWritable bool   `json:"state_writable"`
	CAReadable    bool   `json:"ca_readable"`
	CAWriteError  string `json:"ca_write_error"`
}

type commandDependencies struct {
	newManager        func(franztls.Config) (managerAPI, error)
	activeCertificate func(managerAPI) (certificateRecord, error)
	checkStorage      func(storageOptions) (storageRecord, error)
	serveMTLS         func(context.Context, serveOptions) error
	handshake         func(context.Context, managerAPI, handshakeOptions) (peerRecord, error)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := runCommand(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultDependencies())
	stop()
	os.Exit(code)
}

func defaultDependencies() commandDependencies {
	return commandDependencies{
		newManager: func(config franztls.Config) (managerAPI, error) {
			return franztls.New(config)
		},
		activeCertificate: activeCertificate,
		checkStorage:      checkStorage,
		serveMTLS:         serveMTLS,
		handshake:         performHandshake,
	}
}

func runCommand(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	dependencies commandDependencies,
) int {
	if len(args) == 0 {
		return argumentFailure(stderr, "command")
	}

	command := args[0]
	switch command {
	case "issue", "load", "ensure", "renew":
		flags, ok := parseCommonFlags(command, args[1:])
		if !ok {
			return argumentFailure(stderr, command)
		}
		manager, err := dependencies.newManager(packageConfig(flags))
		if err != nil {
			return argumentFailure(stderr, command)
		}

		switch command {
		case "load":
			err = manager.Load(ctx)
		default:
			var change franztls.CertificateChange
			change, err = manager.Ensure(ctx)
			if err == nil && (command == "issue" || command == "renew") && !change.Renewed {
				err = errors.New("requested certificate issuance did not occur")
			}
		}
		if err != nil {
			return operationFailure(stderr, command)
		}
		record, err := dependencies.activeCertificate(manager)
		if err != nil {
			return operationFailure(stderr, command)
		}
		if err := writeJSON(stdout, record); err != nil {
			return operationFailure(stderr, command)
		}
		return 0

	case "storage-check":
		options, ok := parseStorageOptions(command, args[1:])
		if !ok {
			return argumentFailure(stderr, command)
		}
		record, err := dependencies.checkStorage(options)
		if err != nil {
			return operationFailure(stderr, command)
		}
		if err := writeJSON(stdout, record); err != nil {
			return operationFailure(stderr, command)
		}
		return 0

	case "serve-mtls":
		options, ok := parseServeOptions(command, args[1:])
		if !ok {
			return argumentFailure(stderr, command)
		}
		if err := dependencies.serveMTLS(ctx, options); err != nil {
			return operationFailure(stderr, command)
		}
		return 0

	case "handshake":
		flags, options, ok := parseHandshakeOptions(command, args[1:])
		if !ok {
			return argumentFailure(stderr, command)
		}
		manager, err := dependencies.newManager(packageConfig(flags))
		if err != nil {
			return argumentFailure(stderr, command)
		}
		if err := manager.Load(ctx); err != nil {
			return operationFailure(stderr, command)
		}
		record, err := dependencies.handshake(ctx, manager, options)
		if err != nil {
			return operationFailure(stderr, command)
		}
		if err := writeJSON(stdout, record); err != nil {
			return operationFailure(stderr, command)
		}
		return 0

	default:
		return argumentFailure(stderr, "command")
	}
}

func packageConfig(flags commonFlags) franztls.Config {
	return franztls.Config{
		Domain:          "franztls-client",
		Email:           "admin@localhost",
		AcceptTerms:     true,
		DirectoryURL:    flags.directory,
		CACertFile:      defaultCACertFile,
		AccountKeyFile:  "/etc/certs/account.key",
		AccountFile:     "/etc/certs/account.json",
		PrivateKeyFile:  "/etc/certs/prekit-tls.key",
		CertificateFile: "/etc/certs/prekit-tls.pem",
		RenewBefore:     flags.renewBefore,
		HTTP01Address:   ":80",
	}
}

func parseCommonFlags(name string, args []string) (commonFlags, bool) {
	flags := commonFlags{
		directory:   defaultDirectoryURL,
		renewBefore: 24 * time.Hour,
	}
	set := quietFlagSet(name)
	set.StringVar(&flags.directory, "directory", flags.directory, "ACME directory URL")
	set.DurationVar(&flags.renewBefore, "renew-before", flags.renewBefore, "renewal window")
	if set.Parse(args) != nil || set.NArg() != 0 {
		return commonFlags{}, false
	}
	if flags.directory == "" || flags.renewBefore < 0 {
		return commonFlags{}, false
	}
	return flags, true
}

func parseStorageOptions(name string, args []string) (storageOptions, bool) {
	options := storageOptions{stateDir: defaultStateDir, caFile: defaultCACertFile}
	set := quietFlagSet(name)
	set.StringVar(&options.stateDir, "state-dir", options.stateDir, "state directory")
	set.StringVar(&options.caFile, "ca-file", options.caFile, "CA certificate file")
	if set.Parse(args) != nil || set.NArg() != 0 ||
		!validAbsolutePath(options.stateDir) || !validAbsolutePath(options.caFile) {
		return storageOptions{}, false
	}
	return options, true
}

func parseServeOptions(name string, args []string) (serveOptions, bool) {
	options := serveOptions{
		listen:          defaultListenAddr,
		certificateFile: "/runtime/server.pem",
		privateKeyFile:  "/runtime/server.key",
		caFile:          defaultCACertFile,
	}
	set := quietFlagSet(name)
	set.StringVar(&options.listen, "listen", options.listen, "listen address")
	set.StringVar(&options.certificateFile, "cert-file", options.certificateFile, "server certificate file")
	set.StringVar(&options.privateKeyFile, "key-file", options.privateKeyFile, "server private key file")
	set.StringVar(&options.caFile, "ca-file", options.caFile, "client CA certificate file")
	if set.Parse(args) != nil || set.NArg() != 0 || !validAddress(options.listen) ||
		!validAbsolutePath(options.certificateFile) ||
		!validAbsolutePath(options.privateKeyFile) ||
		!validAbsolutePath(options.caFile) {
		return serveOptions{}, false
	}
	return options, true
}

func parseHandshakeOptions(name string, args []string) (commonFlags, handshakeOptions, bool) {
	flags := commonFlags{
		directory:   defaultDirectoryURL,
		renewBefore: 24 * time.Hour,
	}
	options := handshakeOptions{address: defaultServerAddr, serverName: defaultServerName}
	set := quietFlagSet(name)
	set.StringVar(&flags.directory, "directory", flags.directory, "ACME directory URL")
	set.DurationVar(&flags.renewBefore, "renew-before", flags.renewBefore, "renewal window")
	set.StringVar(&options.address, "address", options.address, "mTLS server address")
	set.StringVar(&options.serverName, "server-name", options.serverName, "TLS server name")
	if set.Parse(args) != nil || set.NArg() != 0 || flags.directory == "" ||
		flags.renewBefore < 0 || !validAddress(options.address) || options.serverName == "" {
		return commonFlags{}, handshakeOptions{}, false
	}
	return flags, options, true
}

func quietFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func validAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(filepath.Clean(path))
}

func validAddress(address string) bool {
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return false
	}
	number, err := strconv.ParseUint(port, 10, 16)
	return err == nil && number <= 65535
}

func argumentFailure(stderr io.Writer, command string) int {
	_, _ = fmt.Fprintf(stderr, "franztls-integration: invalid %s arguments\n", command)
	return 2
}

func operationFailure(stderr io.Writer, command string) int {
	_, _ = fmt.Fprintf(stderr, "franztls-integration: %s failed\n", command)
	return 1
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(value)
}

func activeCertificate(manager managerAPI) (certificateRecord, error) {
	config, err := manager.ClientTLSConfig("franztls-client")
	if err != nil {
		return certificateRecord{}, err
	}
	if config.GetClientCertificate == nil {
		return certificateRecord{}, errors.New("client certificate callback is absent")
	}
	certificate, err := config.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		return certificateRecord{}, err
	}
	if certificate == nil || len(certificate.Certificate) == 0 {
		return certificateRecord{}, errors.New("active client certificate is absent")
	}
	leaf := certificate.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return certificateRecord{}, err
		}
	}
	if leaf.SerialNumber == nil {
		return certificateRecord{}, errors.New("active client certificate has no serial")
	}
	return certificateRecord{
		Serial: leaf.SerialNumber.String(),
		Expiry: leaf.NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

func checkStorage(options storageOptions) (record storageRecord, err error) {
	if os.Getuid() != 65532 || os.Getgid() != 65532 {
		return storageRecord{}, errors.New("unexpected process identity")
	}
	stateInfo, err := os.Stat(options.stateDir)
	if err != nil {
		return storageRecord{}, err
	}
	if !stateInfo.IsDir() || stateInfo.Mode().Perm() != 0o700 {
		return storageRecord{}, errors.New("state directory permissions are not 0700")
	}

	probe, err := os.CreateTemp(options.stateDir, ".franztls-storage-check-*")
	if err != nil {
		return storageRecord{}, err
	}
	probeName := probe.Name()
	probeClosed := false
	defer func() {
		if !probeClosed {
			err = errors.Join(err, probe.Close())
		}
		err = errors.Join(err, os.Remove(probeName))
	}()
	if err := probe.Close(); err != nil {
		return storageRecord{}, err
	}
	probeClosed = true

	caInfo, err := os.Lstat(options.caFile)
	if err != nil {
		return storageRecord{}, err
	}
	if !caInfo.Mode().IsRegular() {
		return storageRecord{}, errors.New("CA path is not a regular file")
	}
	ca, err := os.Open(options.caFile)
	if err != nil {
		return storageRecord{}, err
	}
	buffer := make([]byte, 1)
	readCount, readErr := ca.Read(buffer)
	closeErr := ca.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return storageRecord{}, errors.Join(readErr, closeErr)
	}
	if closeErr != nil || readCount == 0 {
		return storageRecord{}, errors.Join(errors.New("CA file is empty or unreadable"), closeErr)
	}

	writableCA, writeErr := os.OpenFile(options.caFile, os.O_WRONLY, 0)
	if writeErr == nil {
		closeErr := writableCA.Close()
		return storageRecord{}, errors.Join(errors.New("CA file unexpectedly opened for writing"), closeErr)
	}
	if !errors.Is(writeErr, syscall.EROFS) {
		return storageRecord{}, errors.New("CA write failed for a reason other than EROFS")
	}

	return storageRecord{
		UID:           os.Getuid(),
		GID:           os.Getgid(),
		StateMode:     fmt.Sprintf("%04o", stateInfo.Mode().Perm()),
		StateWritable: true,
		CAReadable:    true,
		CAWriteError:  "EROFS",
	}, nil
}

func serveMTLS(ctx context.Context, options serveOptions) error {
	roots, err := loadRoots(options.caFile)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(options.certificateFile, options.privateKeyFile)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", options.listen)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS12,
	})
	server := &http.Server{
		Handler:           mtlsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       commandTimeout,
		WriteTimeout:      commandTimeout,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(tlsListener)
	}()

	select {
	case serveErr := <-serveErrors:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		shutdownErr := server.Shutdown(shutdownCtx)
		cancel()
		if shutdownErr != nil {
			shutdownErr = errors.Join(shutdownErr, server.Close())
		}
		serveErr := <-serveErrors
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, serveErr)
	}
}

func mtlsHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 ||
			len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		leaf := request.TLS.VerifiedChains[0][0]
		if leaf == nil || leaf.SerialNumber == nil {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := writeJSON(writer, peerRecord{Serial: leaf.SerialNumber.String()}); err != nil {
			return
		}
	})
}

func performHandshake(
	ctx context.Context,
	manager managerAPI,
	options handshakeOptions,
) (peerRecord, error) {
	tlsConfig, err := manager.ClientTLSConfig(options.serverName)
	if err != nil {
		return peerRecord{}, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: commandTimeout}
	endpoint := (&url.URL{Scheme: "https", Host: options.address, Path: "/"}).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return peerRecord{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return peerRecord{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return peerRecord{}, errors.New("mTLS server returned a non-success status")
	}

	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	decoder.DisallowUnknownFields()
	var record peerRecord
	if err := decoder.Decode(&record); err != nil {
		return peerRecord{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return peerRecord{}, errors.New("mTLS server returned trailing JSON")
	}
	serial, ok := new(big.Int).SetString(record.Serial, 10)
	if !ok || serial.Sign() <= 0 {
		return peerRecord{}, errors.New("mTLS server returned an invalid serial")
	}
	return record, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("CA file contains no certificates")
	}
	return roots, nil
}
