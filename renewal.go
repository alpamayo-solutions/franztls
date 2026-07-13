package franztls

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"
)

const (
	minimumRenewalCheckInterval = time.Minute
	initialRenewalRetryBase     = 5 * time.Second
	maximumRenewalRetryBase     = 5 * time.Minute
)

type renewalTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type renewalClock interface {
	Now() time.Time
	NewTimer(time.Duration) renewalTimer
}

type renewalRandom interface {
	Int63() int64
}

type runtimeRenewalClock struct{}

func (runtimeRenewalClock) Now() time.Time {
	return time.Now()
}

func (runtimeRenewalClock) NewTimer(delay time.Duration) renewalTimer {
	return &runtimeRenewalTimer{timer: time.NewTimer(delay)}
}

type runtimeRenewalTimer struct {
	timer *time.Timer
}

func (timer *runtimeRenewalTimer) C() <-chan time.Time {
	return timer.timer.C
}

func (timer *runtimeRenewalTimer) Stop() bool {
	return timer.timer.Stop()
}

type runtimeRenewalRandom struct{}

func (runtimeRenewalRandom) Int63() int64 {
	return rand.Int64()
}

// Run continuously checks and renews the active certificate until ctx is
// canceled or no usable certificate remains. Load or Ensure must first
// activate a usable certificate; a deferred renewal error is compatible with
// Run while that active certificate remains valid.
func (m *Manager) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !m.runActive.CompareAndSwap(false, true) {
		return ErrRenewalAlreadyRunning
	}
	defer m.runActive.Store(false)
	clock := m.runClock
	if clock == nil {
		clock = runtimeRenewalClock{}
	}
	random := m.runRandom
	if random == nil {
		random = runtimeRenewalRandom{}
	}

	retryBase := initialRenewalRetryBase
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := clock.Now()
		before := m.current.Load()
		if !usableRenewalMaterial(before, now) {
			return noUsableRenewalError(lastErr)
		}
		beforeFingerprint := before.fingerprint

		change, ensureErr := m.Ensure(ctx)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(ensureErr, context.Canceled) {
			return context.Canceled
		}

		now = clock.Now()
		current := m.current.Load()
		if !usableRenewalMaterial(current, now) {
			return noUsableRenewalError(ensureErr)
		}
		if !change.Renewed && current.fingerprint != beforeFingerprint {
			m.enqueueChange(CertificateChange{
				NotAfter: current.leaf.NotAfter,
			})
		}
		if ensureErr != nil {
			lifecycleErr := deferredRenewalLifecycleError(ensureErr, current)
			lastErr = lifecycleErr
			m.enqueueError(lifecycleErr)
			delay := equalJitter(retryBase, random.Int63())
			remaining := current.leaf.NotAfter.Sub(now)
			if delay > remaining {
				delay = remaining
			}
			if delay <= 0 {
				return noUsableRenewalError(lastErr)
			}
			retryBase = nextRenewalRetryBase(retryBase)
			if err := waitForRenewalTimer(ctx, clock, delay); err != nil {
				return err
			}
			continue
		}

		lastErr = nil
		retryBase = initialRenewalRetryBase
		next := nextRenewalCheck(now, current.leaf.NotAfter, m.cfg.RenewBefore)
		if err := waitForRenewalTimer(ctx, clock, next.Sub(now)); err != nil {
			return err
		}
	}
}

func usableRenewalMaterial(material *activeMaterial, now time.Time) bool {
	return material != nil &&
		material.leaf != nil &&
		now.Before(material.leaf.NotAfter)
}

func noUsableRenewalError(cause error) error {
	if cause == nil {
		return ErrNoUsableCertificate
	}
	return errors.Join(ErrNoUsableCertificate, cause)
}

func deferredRenewalLifecycleError(
	cause error,
	material *activeMaterial,
) error {
	var deferred *DeferredRenewalError
	if errors.As(cause, &deferred) {
		return cause
	}
	return &DeferredRenewalError{
		NotAfter: material.leaf.NotAfter,
		Err:      cause,
	}
}

func nextRenewalCheck(now, notAfter time.Time, renewBefore time.Duration) time.Time {
	wanted := notAfter.Add(-renewBefore)
	minimum := now.Add(minimumRenewalCheckInterval)
	if wanted.Before(minimum) {
		return minimum
	}
	return wanted
}

func nextRenewalRetryBase(base time.Duration) time.Duration {
	if base >= maximumRenewalRetryBase/2 {
		return maximumRenewalRetryBase
	}
	return base * 2
}

func equalJitter(base time.Duration, random int64) time.Duration {
	half := base / 2
	return half + time.Duration(random%int64(base-half+1))
}

func waitForRenewalTimer(
	ctx context.Context,
	clock renewalClock,
	delay time.Duration,
) error {
	timer := clock.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C():
		return nil
	}
}

func publishLatest[T any](channel chan T, value T) {
	select {
	case channel <- value:
		return
	default:
	}
	select {
	case <-channel:
	default:
	}
	select {
	case channel <- value:
	default:
	}
}
