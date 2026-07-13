package franztls

import (
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultRenewBefore = 24 * time.Hour

// Config describes certificate-manager identity, endpoints, and local state.
type Config struct {
	Domain          string
	Email           string
	AcceptTerms     bool
	DirectoryURL    string
	CACertFile      string
	AccountKeyFile  string
	AccountFile     string
	PrivateKeyFile  string
	CertificateFile string
	RenewBefore     time.Duration
	HTTP01Address   string
}

// CertificateChange describes newly activated certificate material.
type CertificateChange struct {
	Renewed  bool
	NotAfter time.Time
}

func normalizeConfig(config Config) (Config, error) {
	config.Domain = strings.ToLower(config.Domain)
	if reason := invalidDNSName(config.Domain); reason != "" {
		return Config{}, &ConfigError{Field: "Domain", Reason: reason}
	}
	if reason := invalidEmail(config.Email); reason != "" {
		return Config{}, &ConfigError{Field: "Email", Reason: reason}
	}
	if !config.AcceptTerms {
		return Config{}, &ConfigError{Field: "AcceptTerms", Reason: "must be true"}
	}
	if reason := invalidDirectoryURL(config.DirectoryURL); reason != "" {
		return Config{}, &ConfigError{Field: "DirectoryURL", Reason: reason}
	}

	paths := []struct {
		field string
		value *string
	}{
		{field: "CACertFile", value: &config.CACertFile},
		{field: "AccountKeyFile", value: &config.AccountKeyFile},
		{field: "AccountFile", value: &config.AccountFile},
		{field: "PrivateKeyFile", value: &config.PrivateKeyFile},
		{field: "CertificateFile", value: &config.CertificateFile},
	}
	for _, path := range paths {
		if *path.value == "" {
			return Config{}, &ConfigError{Field: path.field, Reason: "must not be empty"}
		}
		cleaned := filepath.Clean(*path.value)
		if !filepath.IsAbs(cleaned) {
			return Config{}, &ConfigError{Field: path.field, Reason: "must be an absolute path"}
		}
		*path.value = cleaned
	}

	writablePaths := []struct {
		field string
		value string
	}{
		{field: "AccountKeyFile", value: config.AccountKeyFile},
		{field: "AccountFile", value: config.AccountFile},
		{field: "PrivateKeyFile", value: config.PrivateKeyFile},
		{field: "CertificateFile", value: config.CertificateFile},
	}
	stateParent := filepath.Dir(writablePaths[0].value)
	for _, path := range writablePaths[1:] {
		if filepath.Dir(path.value) != stateParent {
			return Config{}, &ConfigError{
				Field:  path.field,
				Reason: "must share one parent directory with all writable state files",
			}
		}
	}

	if config.RenewBefore < 0 {
		return Config{}, &ConfigError{Field: "RenewBefore", Reason: "must not be negative"}
	}
	if config.RenewBefore == 0 {
		config.RenewBefore = defaultRenewBefore
	}
	if config.HTTP01Address == "" {
		config.HTTP01Address = ":80"
	}
	if reason := invalidListenAddress(config.HTTP01Address); reason != "" {
		return Config{}, &ConfigError{Field: "HTTP01Address", Reason: reason}
	}

	return config, nil
}

func invalidDNSName(domain string) string {
	if domain == "" {
		return "must not be empty"
	}
	if len(domain) > 253 {
		return "must not exceed 253 bytes"
	}
	if strings.HasPrefix(domain, "*.") || domain == "*" {
		return "must not be a wildcard"
	}
	if net.ParseIP(domain) != nil {
		return "must be a DNS name, not an IP address"
	}

	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return "must not contain an empty label"
		}
		if len(label) > 63 {
			return "must not contain a label longer than 63 bytes"
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "labels must start and end with a letter or digit"
		}
		for _, char := range []byte(label) {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return "must contain only ASCII letters, digits, hyphens, and dots"
		}
	}
	return ""
}

func invalidEmail(email string) string {
	if email == "" {
		return "must not be empty"
	}
	if strings.Count(email, "@") != 1 {
		return "must be a mailbox address"
	}
	separator := strings.LastIndexByte(email, '@')
	if separator == 0 || separator == len(email)-1 {
		return "must be a mailbox address"
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return "must be a mailbox address without a display name"
	}
	return ""
}

func invalidDirectoryURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" {
		return "must be an absolute HTTPS URL"
	}
	if parsed.User != nil {
		return "must not contain credentials"
	}
	if parsed.Fragment != "" {
		return "must not contain a fragment"
	}
	return ""
}

func invalidListenAddress(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "must contain a host and numeric port"
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber > 65535 {
		return "must contain a numeric port between 0 and 65535"
	}
	return ""
}
