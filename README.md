# franztls

`franztls` is an embeddable ACME certificate manager for Python and Go. It
issues and renews one DNS identity through HTTP-01, validates committed
certificate state before activation, and keeps the Python `CertManager` API
compatible while Go services migrate onto the same files.

## Installation

Python 3.10 or newer:

```bash
python -m pip install franztls
```

Go 1.25.12 or newer:

```bash
go get github.com/alpamayo-solutions/franztls@v0.2.0
```

The Go package is the root module
`github.com/alpamayo-solutions/franztls`; it has no `/go` suffix and does not
require a local module replacement.

## Python API

The existing constructor, properties, methods, and exception remain available:

```python
import ssl

from franztls import CertManager


certificates = CertManager(
    domain="service.internal",
    acme_directory="https://ca.internal:9000/acme/acme/directory",
    ca_file="/etc/certs/ca.crt",
    account_key_path="/etc/certs/account.key",
    domain_key_path="/etc/certs/domain.key",
    csr_path="/etc/certs/domain.csr",
    cert_path="/etc/certs/domain.pem",
    renewal_buffer_hours=24,
)
certificates.renew_if_necessary()

client_context = ssl.create_default_context(cafile=certificates.ca)
client_context.load_cert_chain(
    certfile=certificates.cert_file,
    keyfile=certificates.key_file,
)
```

`force_renew()` remains available when a caller explicitly needs a new
certificate. `CertificateExpiredException` remains exported, and
`franztls.__version__` is derived from the installed package metadata.

## Go lifecycle

Create a manager with explicit identity, ACME, trust, and state paths:

```go
manager, err := franztls.New(franztls.Config{
    Domain:          "service.internal",
    Email:           "admin@example.com",
    AcceptTerms:     true,
    DirectoryURL:    "https://ca.internal:9000/acme/acme/directory",
    CACertFile:      "/etc/certs/ca.crt",
    AccountKeyFile:  "/etc/certs/account.key",
    AccountFile:     "/etc/certs/account.json",
    PrivateKeyFile:  "/etc/certs/domain.key",
    CertificateFile: "/etc/certs/domain.pem",
    RenewBefore:     24 * time.Hour,
    HTTP01Address:   ":80",
})
if err != nil {
    return err
}
```

`New` validates configuration only. It does not read files, create state, bind a
port, or contact the ACME directory.

Choose the lifecycle operation that matches the caller:

- `Load(ctx)` is disk-only. It validates and activates an existing keypair and
  chain without taking the issuance lock or contacting ACME. It is suitable for
  health checks, offline startup, and Python-created state.
- `Ensure(ctx)` loads a valid non-due certificate without network I/O. When
  state is absent or due, it serializes issuance across goroutines and
  processes, completes ACME HTTP-01, durably commits the new files, then
  activates them. It returns `CertificateChange{Renewed, NotAfter}`.
- `Run(ctx)` is the long-running renewal loop. Call `Load` or `Ensure` first so
  usable material is active. `Run` schedules the next check, retries transient
  failures with bounded jitter, detects external file replacement, publishes
  changes and errors, and exits when the context is canceled or no usable
  certificate remains.

Zero values select the package defaults: `RenewBefore` becomes 24 hours and
`HTTP01Address` becomes `:80`.

## Complete Go example

This example accepts a deferred renewal failure only while the manager still
has a usable current certificate. It starts the renewal loop, drains both event
channels, and cancels cleanly during shutdown.

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "os"
    "os/signal"
    "time"

    "github.com/alpamayo-solutions/franztls"
)

func run(ctx context.Context) error {
    manager, err := franztls.New(franztls.Config{
        Domain:          "service.internal",
        Email:           "admin@example.com",
        AcceptTerms:     true,
        DirectoryURL:    "https://ca.internal:9000/acme/acme/directory",
        CACertFile:      "/etc/certs/ca.crt",
        AccountKeyFile:  "/etc/certs/account.key",
        AccountFile:     "/etc/certs/account.json",
        PrivateKeyFile:  "/etc/certs/domain.key",
        CertificateFile: "/etc/certs/domain.pem",
        RenewBefore:     24 * time.Hour,
        HTTP01Address:   ":80",
    })
    if err != nil {
        return err
    }

    change, ensureErr := manager.Ensure(ctx)
    if ensureErr != nil {
        if errors.Is(ensureErr, franztls.ErrNoUsableCertificate) {
            return ensureErr
        }
        var deferred *franztls.DeferredRenewalError
        if !errors.As(ensureErr, &deferred) {
            return ensureErr
        }
        // The deferred error carries a safe operation class and expiry. The
        // already-activated certificate remains usable until deferred.NotAfter.
        fmt.Printf("renewal deferred; current certificate expires at %s\n", deferred.NotAfter)
    } else if change.Renewed {
        fmt.Printf("activated renewed certificate through %s\n", change.NotAfter)
    }

    tlsConfig, err := manager.ClientTLSConfig("upstream.internal")
    if err != nil {
        return err
    }
    _ = tlsConfig // Pass this to the caller's TLS-capable client.

    runResult := make(chan error, 1)
    go func() {
        runResult <- manager.Run(ctx)
    }()

    for {
        select {
        case change := <-manager.Changes():
            fmt.Printf("certificate changed; renewed=%t expires=%s\n", change.Renewed, change.NotAfter)
            // Reconnect clients that cache TLS sessions or connections.
        case renewalErr := <-manager.Errors():
            fmt.Printf("renewal deferred: %v\n", renewalErr)
        case runErr := <-runResult:
            if errors.Is(runErr, context.Canceled) {
                return nil
            }
            return runErr
        case <-ctx.Done():
            runErr := <-runResult
            if errors.Is(runErr, context.Canceled) {
                return nil
            }
            return runErr
        }
    }
}

func main() {
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
    defer stop()
    if err := run(ctx); err != nil {
        panic(err)
    }
}
```

`Changes()` and `Errors()` are bounded latest-value channels. Consumers should
drain both for the lifetime of `Run`; they are not log archives.

## TLS behavior

`ClientTLSConfig(serverName)` returns a mutually authenticated client
configuration with:

- exclusive trust in the configured CA file, never appended system roots;
- hostname verification for the explicit server name;
- a TLS 1.2 minimum;
- the active client certificate loaded atomically for every new handshake.

Certificate renewal is hot-swapped for new handshakes. Existing network
connections remain the caller's responsibility, so reconnect them after a
change when the protocol caches a connection. The CA pool is a validated
snapshot and is not live-reloaded; create a new manager to activate a changed
CA file.

The package does not set `InsecureSkipVerify`, configure NATS credentials or
authorization, reconnect NATS clients, or expose raw private-key bytes. Those
remain application responsibilities.

## ACME scope and limitations

- `DirectoryURL` must be an absolute HTTPS URL.
- `Email` must be explicit and `AcceptTerms` must be true.
- One exact DNS SAN is issued for `Domain`; wildcards and IP identities are not
  accepted.
- Issuance uses a bounded HTTP-01 server at `HTTP01Address`.
- External Account Binding is not supported. A CA requiring EAB returns
  `ErrExternalAccountBinding` without issuing.

HTTP-01 requires that the CA can resolve the configured DNS identity to the
manager and reach its challenge port. Binding `:80` as a non-root container may
require only the `NET_BIND_SERVICE` capability; no host-published port is
required when CA and client share an internal network.

## State and compatibility

All writable paths (`AccountKeyFile`, `AccountFile`, `PrivateKeyFile`, and
`CertificateFile`) must share one absolute parent directory. The CA file may be
mounted read-only from a different directory.

The manager enforces:

- state directory mode `0700`;
- account key, account JSON, private key, and `.franztls.lock` mode `0600`;
- certificate and CA mode `0644`;
- regular files only, with symlinks/reparse points and descriptor swaps
  rejected;
- leaf-first PEM chains, an exact DNS SAN, current validity, client-auth usage,
  CA verification, and a matching private key;
- one context-cancellable advisory lock across the complete issuance and
  durable commit;
- same-filesystem temporary writes, file sync, atomic rename, parent-directory
  sync, and activation only after the certificate commit marker is durable.

The default paths and PEM/PKCS#1 formats remain compatible with the Python
manager. Go can load Python-created account/domain keys and full chains; Python
can load and renew Go-created state. Go additionally stores ACME account
metadata in `AccountFile` and can recover it from an existing Python account
key when that file is absent.

## Development

Run the local language and integration gates before proposing a release:

```bash
go test ./...
go test -race ./...
python -m pip install -e '.[dev]'
python -m pytest tests/python -q
bash integration/run.sh
```

The integration runner uses an isolated internal Docker network, publishes no
host ports, creates all CA secrets at runtime, and removes its containers,
volumes, network, and secret directory on exit.
