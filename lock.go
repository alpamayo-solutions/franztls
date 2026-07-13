package franztls

import (
	"context"
	"path/filepath"
	"time"
)

const (
	issueLockFileName = ".franztls.lock"
	issueLockMode     = 0o600
)

type issueLock interface {
	Acquire(context.Context) (func() error, error)
}

type fileIssueLock struct {
	stateRoot                string
	name                     string
	path                     string
	pollInterval             time.Duration
	afterDescriptorValidated func()
	onContention             func()
}

func newIssueLock(cfg normalizedConfig) issueLock {
	stateRoot := filepath.Dir(cfg.AccountKeyFile)
	return &fileIssueLock{
		stateRoot: stateRoot,
		name:      issueLockFileName,
		path:      filepath.Join(stateRoot, issueLockFileName),
	}
}

func (lock *fileIssueLock) Acquire(ctx context.Context) (func() error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name := lock.name
	if name == "" {
		name = issueLockFileName
	}
	path := lock.path
	if path == "" {
		path = filepath.Join(lock.stateRoot, name)
	}
	release, err := acquirePlatformIssueLock(
		ctx,
		lock.stateRoot,
		name,
		lock.pollInterval,
		lock.afterDescriptorValidated,
		lock.onContention,
	)
	if err != nil {
		return nil, wrapStorageError(path, "lock", err)
	}
	return release, nil
}
