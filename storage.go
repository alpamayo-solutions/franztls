package franztls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v5/acme"
)

var (
	errUnsafeStatePath   = errors.New("franztls: unsafe state path")
	errNotRegularFile    = errors.New("franztls: state path is not a regular file")
	errWrongMode         = errors.New("franztls: state path has unexpected permissions")
	errAccountState      = errors.New("franztls: inconsistent account state")
	errStateFileTooLarge = errors.New("franztls: state file exceeds size limit")
)

// maxStateFileSize bounds every descriptor-relative state read. Certificate,
// key, CA, and account files are all small; a generous cap keeps corrupt or
// hostile files from causing unbounded allocations while preserving normal
// interoperability.
const maxStateFileSize = 4 << 20

// DurabilityUncertainError means rename completed but syncing the containing
// directory failed. Callers must re-read and validate disk state before
// activating it or attempting another issuance.
type DurabilityUncertainError struct {
	Path string
	Err  error
}

func (e *DurabilityUncertainError) Error() string {
	if e == nil {
		return "franztls: state durability is uncertain"
	}
	return fmt.Sprintf("franztls: state durability is uncertain at %s", e.Path)
}

func (e *DurabilityUncertainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// UnsupportedSafeOpenError reports a platform where descriptor-relative,
// no-follow state access is unavailable. It never falls back to following
// paths by name.
type UnsupportedSafeOpenError struct {
	GOOS string
}

func (e *UnsupportedSafeOpenError) Error() string {
	if e == nil || e.GOOS == "" {
		return "franztls: safe state-file access is unsupported"
	}
	return fmt.Sprintf("franztls: safe state-file access is unsupported on %s", e.GOOS)
}

type atomicFile interface {
	Chmod(fs.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type atomicDirectory interface {
	createTemp(string) (atomicFile, string, error)
	remove(string) error
	rename(string, string) error
	sync() error
	path(string) string
}

func atomicWrite(directory atomicDirectory, name string, data []byte, mode fs.FileMode) error {
	file, temporaryName, err := directory.createTemp(".franztls-")
	if err != nil {
		return err
	}
	defer func() { _ = directory.remove(temporaryName) }()

	open := true
	closeFile := func() error {
		if !open {
			return nil
		}
		open = false
		return file.Close()
	}
	fail := func(operationErr error) error {
		if closeErr := closeFile(); closeErr != nil {
			return errors.Join(operationErr, closeErr)
		}
		return operationErr
	}

	if err := file.Chmod(mode.Perm()); err != nil {
		return fail(err)
	}
	written, err := file.Write(data)
	if err != nil {
		return fail(err)
	}
	if written != len(data) {
		return fail(io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := closeFile(); err != nil {
		return err
	}
	if err := directory.rename(temporaryName, name); err != nil {
		return err
	}
	if err := directory.sync(); err != nil {
		return &DurabilityUncertainError{Path: directory.path(name), Err: err}
	}
	return nil
}

type stateDir struct {
	root     string
	platform *platformDir
}

func openStateDir(path string, create bool) (*stateDir, error) {
	directory, err := platformOpenDir(path, create, 0o700)
	if err != nil {
		return nil, err
	}
	return &stateDir{root: filepath.Clean(path), platform: directory}, nil
}

func openReadDir(path string) (*stateDir, error) {
	directory, err := platformOpenDir(path, false, 0)
	if err != nil {
		return nil, err
	}
	return &stateDir{root: filepath.Clean(path), platform: directory}, nil
}

func (d *stateDir) createTemp(prefix string) (atomicFile, string, error) {
	return d.platform.createTemp(prefix)
}

func (d *stateDir) remove(name string) error {
	return d.platform.remove(name)
}

func (d *stateDir) rename(oldName, newName string) error {
	return d.platform.rename(oldName, newName)
}

func (d *stateDir) sync() error {
	return d.platform.sync()
}

func (d *stateDir) path(name string) string {
	return filepath.Join(d.root, name)
}

func (d *stateDir) close() error {
	if d == nil || d.platform == nil {
		return nil
	}
	return d.platform.close()
}

func (d *stateDir) atomicWrite(name string, data []byte, mode fs.FileMode) error {
	if !safeBaseName(name) {
		return errUnsafeStatePath
	}
	return atomicWrite(d, name, data, mode)
}

func (d *stateDir) readFile(name string) ([]byte, fs.FileMode, error) {
	if !safeBaseName(name) {
		return nil, 0, errUnsafeStatePath
	}
	return d.platform.readFile(name)
}

func safeBaseName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name
}

type stateStore struct {
	cfg       Config
	stateRoot string
}

type accountState struct {
	accountKey        crypto.Signer
	accountKeyPEM     []byte
	accountKeyExisted bool
	account           *acme.ExtendedAccount
}

func newStateStore(cfg Config) *stateStore {
	return &stateStore{cfg: cfg, stateRoot: filepath.Dir(cfg.AccountKeyFile)}
}

func (s *stateStore) loadAccountState() (accountState, error) {
	keyPEM, keyErr := s.readFile(s.cfg.AccountKeyFile, 0o600, "account_key")
	accountJSON, accountErr := s.readFile(s.cfg.AccountFile, 0o600, "account")
	keyMissing := errors.Is(keyErr, fs.ErrNotExist)
	accountMissing := errors.Is(accountErr, fs.ErrNotExist)

	if keyErr != nil && !keyMissing {
		return accountState{}, keyErr
	}
	if accountErr != nil && !accountMissing {
		return accountState{}, accountErr
	}
	if keyMissing {
		if !accountMissing {
			return accountState{}, &StateError{
				Path: s.cfg.AccountFile,
				Kind: "account_state",
				Err:  errAccountState,
			}
		}
		key, encoded, err := generateRSAKeyPEM()
		if err != nil {
			return accountState{}, &StateError{
				Path: s.cfg.AccountKeyFile,
				Kind: "account_key",
				Err:  err,
			}
		}
		return accountState{accountKey: key, accountKeyPEM: encoded}, nil
	}

	signer, err := parsePrivateKey(keyPEM)
	if err != nil {
		return accountState{}, &StateError{
			Path: s.cfg.AccountKeyFile,
			Kind: "account_key",
			Err:  err,
		}
	}
	if _, ok := signer.(*rsa.PrivateKey); !ok {
		return accountState{}, &StateError{
			Path: s.cfg.AccountKeyFile,
			Kind: "account_key",
			Err:  errAccountState,
		}
	}
	state := accountState{
		accountKey:        signer,
		accountKeyPEM:     keyPEM,
		accountKeyExisted: true,
	}
	if accountMissing {
		return state, nil
	}
	var account acme.ExtendedAccount
	if err := json.Unmarshal(accountJSON, &account); err != nil || account.Location == "" {
		return accountState{}, &StateError{
			Path: s.cfg.AccountFile,
			Kind: "account",
			Err:  errAccountState,
		}
	}
	state.account = &account
	return state, nil
}

func (s *stateStore) persistAccount(account *acme.ExtendedAccount) error {
	if account == nil || account.Location == "" {
		return &StateError{
			Path: s.cfg.AccountFile,
			Kind: "account",
			Err:  errAccountState,
		}
	}
	encoded, err := json.Marshal(account)
	if err != nil {
		return &StateError{Path: s.cfg.AccountFile, Kind: "account", Err: err}
	}
	return s.writeFile(s.cfg.AccountFile, encoded, 0o600, "account")
}

func (s *stateStore) writeFile(path string, data []byte, mode fs.FileMode, kind string) error {
	cleaned := filepath.Clean(path)
	if !s.isWritablePath(cleaned) || filepath.Dir(cleaned) != s.stateRoot {
		return &StateError{Path: cleaned, Kind: "unsafe_path", Err: errUnsafeStatePath}
	}
	directory, err := openStateDir(s.stateRoot, true)
	if err != nil {
		return wrapStorageError(cleaned, kind, err)
	}
	defer directory.close()
	if err := directory.atomicWrite(filepath.Base(cleaned), data, mode); err != nil {
		var uncertain *DurabilityUncertainError
		if errors.As(err, &uncertain) {
			return err
		}
		return wrapStorageError(cleaned, kind, err)
	}
	return nil
}

func (s *stateStore) readFile(path string, expectedMode fs.FileMode, kind string) ([]byte, error) {
	cleaned := filepath.Clean(path)
	if !s.isKnownPath(cleaned) {
		return nil, &StateError{Path: cleaned, Kind: "unsafe_path", Err: errUnsafeStatePath}
	}
	var (
		directory *stateDir
		err       error
	)
	if filepath.Dir(cleaned) == s.stateRoot {
		directory, err = openStateDir(s.stateRoot, false)
	} else {
		directory, err = openReadDir(filepath.Dir(cleaned))
	}
	if err != nil {
		return nil, wrapStorageError(cleaned, kind, err)
	}
	defer directory.close()

	data, actualMode, err := directory.readFile(filepath.Base(cleaned))
	if err != nil {
		return nil, wrapStorageError(cleaned, kind, err)
	}
	if actualMode != 0 && actualMode.Perm() != expectedMode.Perm() {
		return nil, &StateError{Path: cleaned, Kind: "permissions", Err: errWrongMode}
	}
	return data, nil
}

func (s *stateStore) isKnownPath(path string) bool {
	return path == filepath.Clean(s.cfg.CACertFile) || s.isWritablePath(path)
}

func (s *stateStore) isWritablePath(path string) bool {
	for _, candidate := range []string{
		s.cfg.AccountKeyFile,
		s.cfg.AccountFile,
		s.cfg.PrivateKeyFile,
		s.cfg.CertificateFile,
	} {
		if path == filepath.Clean(candidate) {
			return true
		}
	}
	return false
}

func (s *stateStore) persistMaterial(
	certificatePEM []byte,
	signer crypto.Signer,
	roots *x509.CertPool,
	now time.Time,
) (*certificateMaterial, error) {
	return s.persistIssuedMaterial(
		certificatePEM,
		signer,
		nil,
		true,
		roots,
		now,
	)
}

func (s *stateStore) persistIssuedMaterial(
	certificatePEM []byte,
	signer crypto.Signer,
	privateKeyPEM []byte,
	persistPrivateKey bool,
	roots *x509.CertPool,
	now time.Time,
) (*certificateMaterial, error) {
	// Validate the complete candidate before creating a directory or replacing
	// any usable on-disk domain state.
	material, err := validateMaterial(certificatePEM, signer, roots, s.cfg, now)
	if err != nil {
		return nil, err
	}
	if persistPrivateKey {
		if len(privateKeyPEM) == 0 {
			privateKeyPEM, err = marshalSignerPEM(signer)
			if err != nil {
				return nil, &StateError{
					Path: s.cfg.PrivateKeyFile,
					Kind: "private_key",
					Err:  err,
				}
			}
		}
		if err := s.writeFile(
			s.cfg.PrivateKeyFile,
			privateKeyPEM,
			0o600,
			"private_key",
		); err != nil {
			return nil, err
		}
	}
	// The certificate is the commit marker and is therefore always written last.
	if err := s.writeFile(
		s.cfg.CertificateFile,
		certificatePEM,
		0o644,
		"certificate",
	); err != nil {
		return nil, err
	}
	return material, nil
}

func wrapStorageError(path, fallbackKind string, err error) error {
	kind := fallbackKind
	switch {
	case errors.Is(err, errUnsafeStatePath):
		kind = "unsafe_path"
	case errors.Is(err, errNotRegularFile):
		kind = "not_regular"
	case errors.Is(err, errWrongMode):
		kind = "permissions"
	}
	return &StateError{Path: path, Kind: kind, Err: err}
}

func generateRSAKeyPEM() (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if len(encoded) == 0 {
		return nil, nil, errors.New("encode RSA private key")
	}
	return key, encoded, nil
}

func marshalSignerPEM(signer crypto.Signer) ([]byte, error) {
	var block pem.Block
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		if key == nil {
			return nil, errors.New("nil RSA private key")
		}
		block = pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	case *ecdsa.PrivateKey:
		if key == nil {
			return nil, errors.New("nil ECDSA private key")
		}
		encoded, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal ECDSA private key: %w", err)
		}
		block = pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}
	default:
		return nil, errors.New("unsupported private-key signer")
	}
	encoded := pem.EncodeToMemory(&block)
	if len(encoded) == 0 {
		return nil, errors.New("encode private key")
	}
	return encoded, nil
}
