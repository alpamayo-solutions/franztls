package franztls

import (
	"context"
	"path/filepath"
)

const (
	issueLockFileName = ".franztls.lock"
	issueLockMode     = 0o600
)

type issueLock interface {
	Acquire(context.Context) (func() error, error)
}

type fileIssueLock struct {
	stateRoot string
	path      string
}

func newIssueLock(cfg normalizedConfig) issueLock {
	stateRoot := filepath.Dir(cfg.AccountKeyFile)
	return &fileIssueLock{
		stateRoot: stateRoot,
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
	release, err := acquirePlatformIssueLock(ctx, lock.stateRoot, issueLockFileName)
	if err != nil {
		return nil, wrapStorageError(lock.path, "lock", err)
	}
	return release, nil
}
