package franztls

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrNotLoaded              = errors.New("franztls: certificate is not loaded")
	ErrNoUsableCertificate    = errors.New("franztls: no usable certificate")
	ErrRenewalAlreadyRunning  = errors.New("franztls: certificate renewal loop is already running")
	ErrExternalAccountBinding = errors.New("franztls: ACME server requires unsupported external account binding")
)

// ConfigError identifies one invalid configuration field without retaining its value.
type ConfigError struct {
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	if e == nil {
		return "franztls: invalid configuration"
	}
	return fmt.Sprintf("franztls: invalid %s: %s", e.Field, e.Reason)
}

func (e *ConfigError) Unwrap() error {
	return nil
}

// StateError classifies a certificate-state failure without exposing its contents.
type StateError struct {
	Path string
	Kind string
	Err  error
}

func (e *StateError) Error() string {
	if e == nil {
		return "franztls: certificate state error"
	}
	return fmt.Sprintf("franztls: certificate state %s at %s", e.Kind, e.Path)
}

func (e *StateError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// DeferredRenewalError reports a failed renewal while a certificate remains usable.
type DeferredRenewalError struct {
	NotAfter time.Time
	Err      error
}

func (e *DeferredRenewalError) Error() string {
	if e == nil {
		return "franztls: certificate renewal deferred"
	}
	return fmt.Sprintf(
		"franztls: certificate renewal deferred after %s; certificate expires at %s",
		deferredRenewalOperationClass(e.Err),
		e.NotAfter.UTC().Format(time.RFC3339),
	)
}

func (e *DeferredRenewalError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func deferredRenewalOperationClass(err error) string {
	if errors.Is(err, ErrExternalAccountBinding) {
		return "external account binding"
	}
	var stateErr *StateError
	if errors.As(err, &stateErr) {
		return "certificate state validation"
	}
	if errors.Is(err, ErrNoUsableCertificate) || errors.Is(err, ErrNotLoaded) {
		return "certificate availability check"
	}
	return "ACME operation"
}
