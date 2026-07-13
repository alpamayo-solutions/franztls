package franztls

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
)

const task9TestTimeout = 2 * time.Second

type task9OrderedTrace struct {
	mu     sync.Mutex
	values []string
}

func (trace *task9OrderedTrace) add(value string) {
	trace.mu.Lock()
	trace.values = append(trace.values, value)
	trace.mu.Unlock()
}

func (trace *task9OrderedTrace) snapshot() []string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]string(nil), trace.values...)
}

type task9FakeRenewalClock struct {
	mu      sync.Mutex
	now     time.Time
	created chan *task9FakeRenewalTimer
	trace   *task9OrderedTrace
}

func newTask9FakeRenewalClock(now time.Time) *task9FakeRenewalClock {
	return &task9FakeRenewalClock{
		now:     now,
		created: make(chan *task9FakeRenewalTimer, 32),
	}
}

func (clock *task9FakeRenewalClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *task9FakeRenewalClock) NewTimer(delay time.Duration) renewalTimer {
	clock.mu.Lock()
	timer := &task9FakeRenewalTimer{
		clock: clock,
		delay: delay,
		when:  clock.now.Add(delay),
		ch:    make(chan time.Time, 1),
	}
	trace := clock.trace
	clock.mu.Unlock()
	if trace != nil {
		trace.add("timer")
	}
	clock.created <- timer
	return timer
}

type task9FakeRenewalTimer struct {
	mu      sync.Mutex
	clock   *task9FakeRenewalClock
	delay   time.Duration
	when    time.Time
	ch      chan time.Time
	stopped bool
	fired   bool
}

func (timer *task9FakeRenewalTimer) C() <-chan time.Time {
	return timer.ch
}

func (timer *task9FakeRenewalTimer) Stop() bool {
	timer.mu.Lock()
	defer timer.mu.Unlock()
	wasActive := !timer.stopped && !timer.fired
	timer.stopped = true
	return wasActive
}

func (timer *task9FakeRenewalTimer) fire(t *testing.T) {
	t.Helper()
	timer.mu.Lock()
	if timer.stopped {
		timer.mu.Unlock()
		t.Fatal("cannot fire a stopped renewal timer")
	}
	if timer.fired {
		timer.mu.Unlock()
		t.Fatal("cannot fire a renewal timer twice")
	}
	timer.fired = true
	timer.mu.Unlock()

	timer.clock.mu.Lock()
	if timer.when.Before(timer.clock.now) {
		timer.clock.mu.Unlock()
		t.Fatalf("timer deadline %v precedes fake time %v", timer.when, timer.clock.now)
	}
	timer.clock.now = timer.when
	timer.clock.mu.Unlock()
	timer.ch <- timer.when
}

func (timer *task9FakeRenewalTimer) isStopped() bool {
	timer.mu.Lock()
	defer timer.mu.Unlock()
	return timer.stopped
}

type task9SequenceRandom struct {
	mu     sync.Mutex
	values []int64
	calls  int
}

func (random *task9SequenceRandom) Int63() int64 {
	random.mu.Lock()
	defer random.mu.Unlock()
	value := int64(0)
	if random.calls < len(random.values) {
		value = random.values[random.calls]
	}
	random.calls++
	return value
}

func (random *task9SequenceRandom) callCount() int {
	random.mu.Lock()
	defer random.mu.Unlock()
	return random.calls
}

type task9RunResult struct {
	err error
}

func task9StartRun(manager *Manager, ctx context.Context) <-chan task9RunResult {
	result := make(chan task9RunResult, 1)
	go func() {
		result <- task9RunResult{err: manager.Run(ctx)}
	}()
	return result
}

func task9AwaitRun(t *testing.T, result <-chan task9RunResult) error {
	t.Helper()
	select {
	case got := <-result:
		return got.err
	case <-time.After(task9TestTimeout):
		t.Fatal("Run did not return within the test bound")
		return nil
	}
}

func task9NextTimer(t *testing.T, clock *task9FakeRenewalClock) *task9FakeRenewalTimer {
	t.Helper()
	select {
	case timer := <-clock.created:
		if timer.delay < 0 {
			t.Fatalf("negative renewal timer delay: %v", timer.delay)
		}
		return timer
	case <-time.After(task9TestTimeout):
		t.Fatal("Run did not create the expected renewal timer")
		return nil
	}
}

func task9AssertNoTimer(t *testing.T, clock *task9FakeRenewalClock) {
	t.Helper()
	select {
	case timer := <-clock.created:
		t.Fatalf("unexpected renewal timer with delay %v", timer.delay)
	default:
	}
}

func task9CancelAndAwait(
	t *testing.T,
	cancel context.CancelFunc,
	result <-chan task9RunResult,
) {
	t.Helper()
	cancel()
	if err := task9AwaitRun(t, result); err != context.Canceled {
		t.Fatalf("Run cancellation error = %T %v, want context.Canceled", err, err)
	}
}

func task9ReceiveError(t *testing.T, manager *Manager) error {
	t.Helper()
	select {
	case err := <-manager.Errors():
		return err
	case <-time.After(task9TestTimeout):
		t.Fatal("Run did not publish the expected lifecycle error")
		return nil
	}
}

func task9ReceiveChange(t *testing.T, manager *Manager) CertificateChange {
	t.Helper()
	select {
	case change := <-manager.Changes():
		return change
	case <-time.After(task9TestTimeout):
		t.Fatal("Run did not publish the expected certificate change")
		return CertificateChange{}
	}
}

func task9NewManager(
	t *testing.T,
	cfg Config,
	now time.Time,
	factory issuerFactory,
) (*Manager, *task9FakeRenewalClock, *task9SequenceRandom) {
	t.Helper()
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	clock := newTask9FakeRenewalClock(now)
	random := &task9SequenceRandom{}
	manager := newManager(normalized, clock, factory)
	manager.runClock = clock
	manager.runRandom = random
	return manager, clock, random
}

func task9Material(
	t *testing.T,
	validFor time.Duration,
	renewBefore time.Duration,
) *testMaterial {
	t.Helper()
	material := newTestMaterial(
		t,
		testKeyRSA,
		testKeyPKCS1,
		true,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	options := cloneTestLeafOptions(material.leafOptions)
	options.notBefore = material.now.Add(-time.Hour)
	options.notAfter = material.now.Add(validFor)
	material.reissueLeaf(options)
	material.cfg.RenewBefore = renewBefore
	writeTestMaterialFiles(t, material.cfg, material)
	return material
}

func task9LoadedManager(
	t *testing.T,
	material *testMaterial,
	factory issuerFactory,
) (*Manager, *task9FakeRenewalClock, *task9SequenceRandom) {
	t.Helper()
	manager, clock, random := task9NewManager(t, material.cfg, material.now, factory)
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("Load() test material: %v", err)
	}
	assertNoManagerEvents(t, manager)
	return manager, clock, random
}

func task9ReplacementCertificate(
	t *testing.T,
	material *testMaterial,
	notAfter time.Time,
) ([]byte, *x509.Certificate) {
	t.Helper()
	options := cloneTestLeafOptions(material.leafOptions)
	options.notBefore = material.now.Add(-time.Hour)
	options.notAfter = notAfter
	leafDER, leaf := newTestLeaf(t, options, material.leafKey, material.issuer)
	return encodeTestCertificateChain(t, leafDER, material.intermediateDER), leaf
}

func task9RecordingIssuer(cfg Config, account *acme.ExtendedAccount) *recordingManagerIssuer {
	recorder := &recordingManagerIssuer{}
	recorder.ensureAccount = func(
		_ context.Context,
		_ crypto.Signer,
		existing *acme.ExtendedAccount,
	) (*acme.ExtendedAccount, error) {
		resolved := existing
		if resolved == nil {
			resolved = account
		}
		if resolved == nil || resolved.Location == "" {
			return nil, errors.New("task9 recording issuer has no account")
		}
		if err := newStateStore(cfg).persistAccount(resolved); err != nil {
			return nil, err
		}
		return resolved, nil
	}
	return recorder
}

type task9FailureLock struct {
	err   error
	calls atomic.Int32
}

func (lock *task9FailureLock) Acquire(ctx context.Context) (func() error, error) {
	lock.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, lock.err
}

type task9GatedFailureLock struct {
	err         error
	trace       *task9OrderedTrace
	entered     chan struct{}
	releaseGate chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func newTask9GatedFailureLock(cause error, trace *task9OrderedTrace) *task9GatedFailureLock {
	return &task9GatedFailureLock{
		err:         cause,
		trace:       trace,
		entered:     make(chan struct{}),
		releaseGate: make(chan struct{}),
	}
}

func (lock *task9GatedFailureLock) Acquire(ctx context.Context) (func() error, error) {
	lock.trace.add("ensure")
	lock.enteredOnce.Do(func() { close(lock.entered) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-lock.releaseGate:
		return nil, lock.err
	}
}

func (lock *task9GatedFailureLock) release() {
	lock.releaseOnce.Do(func() { close(lock.releaseGate) })
}

type task9ContextLock struct {
	entered     chan struct{}
	enteredOnce sync.Once
	calls       atomic.Int32
}

func newTask9ContextLock() *task9ContextLock {
	return &task9ContextLock{entered: make(chan struct{})}
}

func (lock *task9ContextLock) Acquire(ctx context.Context) (func() error, error) {
	lock.calls.Add(1)
	lock.enteredOnce.Do(func() { close(lock.entered) })
	<-ctx.Done()
	return nil, ctx.Err()
}

type task9SequenceLock struct {
	mu         sync.Mutex
	calls      int
	commitAt   int
	commit     func() error
	err        error
	releaseErr error
}

func (lock *task9SequenceLock) Acquire(ctx context.Context) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lock.mu.Lock()
	lock.calls++
	call := lock.calls
	lock.mu.Unlock()
	if call == lock.commitAt {
		if err := lock.commit(); err != nil {
			return nil, err
		}
		return func() error { return lock.releaseErr }, nil
	}
	return nil, lock.err
}

func (lock *task9SequenceLock) callCount() int {
	lock.mu.Lock()
	defer lock.mu.Unlock()
	return lock.calls
}

type task9BlockingHTTPProvider struct {
	entered     chan struct{}
	enteredOnce sync.Once
	closeCalls  atomic.Int32
}

func newTask9BlockingHTTPProvider() *task9BlockingHTTPProvider {
	return &task9BlockingHTTPProvider{entered: make(chan struct{})}
}

func (provider *task9BlockingHTTPProvider) Present(
	ctx context.Context,
	_, _, _ string,
) error {
	provider.enteredOnce.Do(func() { close(provider.entered) })
	<-ctx.Done()
	return ctx.Err()
}

func (*task9BlockingHTTPProvider) CleanUp(context.Context, string, string, string) error {
	return nil
}

func (provider *task9BlockingHTTPProvider) close(context.Context) error {
	provider.closeCalls.Add(1)
	return nil
}

func task9AssertActiveCancellationIsDeferred(t *testing.T, manager *Manager) {
	t.Helper()
	_, err := manager.failureResult(context.Canceled)
	var deferred *DeferredRenewalError
	if !errors.As(err, &deferred) || !errors.Is(err, context.Canceled) {
		t.Fatalf("valid active cancellation = %T %v, want canceled DeferredRenewalError", err, err)
	}
}

func task9AssertCanceledRealEnsureRun(
	t *testing.T,
	manager *Manager,
	clock *task9FakeRenewalClock,
	entered <-chan struct{},
) {
	t.Helper()
	active := manager.current.Load()
	if active == nil || active.leaf == nil || !clock.Now().Before(active.leaf.NotAfter) {
		t.Fatal("cancellation test does not start with valid active material")
	}
	task9AssertActiveCancellationIsDeferred(t, manager)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)
	select {
	case <-entered:
	case <-time.After(task9TestTimeout):
		t.Fatal("Run did not enter the expected real Ensure phase")
	}
	task9CancelAndAwait(t, cancel, result)
	if manager.current.Load() != active {
		t.Fatal("canceled Run replaced valid active material")
	}
	task9AssertNoTimer(t, clock)
	assertNoManagerEvents(t, manager)
}

func TestEqualJitterUsesInclusiveHalfToFullRange(t *testing.T) {
	for _, base := range []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		5 * time.Minute,
	} {
		t.Run(base.String(), func(t *testing.T) {
			half := base / 2
			if got := equalJitter(base, 0); got != half {
				t.Fatalf("equalJitter(%v, 0) = %v, want %v", base, got, half)
			}
			if got := equalJitter(base, int64(base-half)); got != base {
				t.Fatalf("equalJitter(%v, endpoint) = %v, want %v", base, got, base)
			}
			for _, random := range []int64{1, 17, 1<<31 - 1, 1<<62 - 1} {
				first := equalJitter(base, random)
				second := equalJitter(base, random)
				if first < half || first > base {
					t.Fatalf("equalJitter(%v, %d) = %v, want [%v, %v]", base, random, first, half, base)
				}
				if second != first {
					t.Fatalf("equalJitter(%v, %d) was not deterministic: %v then %v", base, random, first, second)
				}
			}
		})
	}
}

func TestRunWithoutActiveMaterialReturnsBeforeTimerEnsureOrIssuer(t *testing.T) {
	now := time.Date(2026, time.July, 13, 8, 0, 0, 0, time.UTC)
	factory := &forbiddenIssuerFactory{}
	manager, clock, random := task9NewManager(t, validConfig(storageTempDir(t)), now, factory)

	err := manager.Run(context.Background())
	if !errors.Is(err, ErrNoUsableCertificate) {
		t.Fatalf("Run() error = %T %v, want ErrNoUsableCertificate", err, err)
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("Run constructed %d issuers without active material", factory.calls.Load())
	}
	if random.callCount() != 0 {
		t.Fatalf("Run consumed %d random values without active material", random.callCount())
	}
	task9AssertNoTimer(t, clock)
	assertNoManagerEvents(t, manager)
}

func TestRunRejectsConcurrentLoopAndAllowsRestartAfterExit(t *testing.T) {
	material := task9Material(t, 8*time.Hour, 3*time.Hour)
	factory := &forbiddenIssuerFactory{}
	manager, clock, _ := task9LoadedManager(t, material, factory)
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	t.Cleanup(cancelFirst)
	firstResult := task9StartRun(manager, firstCtx)
	firstTimer := task9NextTimer(t, clock)

	secondCtx, cancelSecond := context.WithCancel(context.Background())
	t.Cleanup(cancelSecond)
	secondResult := task9StartRun(manager, secondCtx)
	select {
	case got := <-secondResult:
		if !errors.Is(got.err, ErrRenewalAlreadyRunning) {
			t.Fatalf(
				"concurrent Run error = %T %v, want ErrRenewalAlreadyRunning",
				got.err,
				got.err,
			)
		}
	case timer := <-clock.created:
		cancelSecond()
		if err := task9AwaitRun(t, secondResult); err != context.Canceled {
			t.Fatalf("unguarded concurrent Run cancellation = %v", err)
		}
		t.Fatalf("concurrent Run created a second lifecycle timer with delay %v", timer.delay)
	case <-time.After(task9TestTimeout):
		cancelSecond()
		_ = task9AwaitRun(t, secondResult)
		t.Fatal("concurrent Run neither rejected nor entered a detectable lifecycle")
	}
	task9AssertNoTimer(t, clock)
	task9CancelAndAwait(t, cancelFirst, firstResult)
	if !firstTimer.isStopped() {
		t.Fatal("first Run did not stop its timer on exit")
	}

	thirdCtx, cancelThird := context.WithCancel(context.Background())
	t.Cleanup(cancelThird)
	thirdResult := task9StartRun(manager, thirdCtx)
	_ = task9NextTimer(t, clock)
	task9CancelAndAwait(t, cancelThird, thirdResult)
	if factory.calls.Load() != 0 {
		t.Fatalf("concurrent/restarted Runs constructed %d issuers", factory.calls.Load())
	}
}

func TestRunCallsRealEnsureBeforeCreatingFirstTimer(t *testing.T) {
	material := task9Material(t, 2*time.Hour, 3*time.Hour)
	factory := &forbiddenIssuerFactory{}
	manager, clock, _ := task9LoadedManager(t, material, factory)
	trace := &task9OrderedTrace{}
	clock.trace = trace
	cause := errors.New("gated renewal failure")
	lock := newTask9GatedFailureLock(cause, trace)
	manager.lock = lock
	t.Cleanup(lock.release)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)

	select {
	case <-lock.entered:
	case <-time.After(task9TestTimeout):
		t.Fatal("real Ensure did not reach the gated lock")
	}
	if got := trace.snapshot(); len(got) != 1 || got[0] != "ensure" {
		t.Fatalf("trace before releasing Ensure = %q, want [ensure]", got)
	}
	task9AssertNoTimer(t, clock)
	lock.release()
	timer := task9NextTimer(t, clock)
	if got := trace.snapshot(); len(got) != 2 || got[0] != "ensure" || got[1] != "timer" {
		t.Fatalf("ordered trace = %q, want [ensure timer]", got)
	}
	if err := task9ReceiveError(t, manager); !errors.Is(err, cause) {
		t.Fatalf("published gated error = %T %v, want cause", err, err)
	}
	task9CancelAndAwait(t, cancel, result)
	if !timer.isStopped() {
		t.Fatal("Run did not stop the first retry timer")
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("gated lock failure constructed %d issuers", factory.calls.Load())
	}
}

func TestRunSchedulesRenewalBoundaryWithOneMinuteFloor(t *testing.T) {
	for _, test := range []struct {
		name      string
		offset    time.Duration
		wantDelay time.Duration
	}{
		{name: "future three-hour PREKIT boundary", offset: 9 * time.Hour, wantDelay: 6 * time.Hour},
		{name: "boundary exactly at floor", offset: 3*time.Hour + time.Minute, wantDelay: time.Minute},
		{name: "boundary before floor", offset: 3*time.Hour + 10*time.Second, wantDelay: time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			material := task9Material(t, test.offset, 3*time.Hour)
			factory := &forbiddenIssuerFactory{}
			manager, clock, _ := task9LoadedManager(t, material, factory)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			result := task9StartRun(manager, ctx)
			timer := task9NextTimer(t, clock)
			if timer.delay != test.wantDelay {
				t.Fatalf("scheduled delay = %v, want %v", timer.delay, test.wantDelay)
			}
			task9CancelAndAwait(t, cancel, result)
			if factory.calls.Load() != 0 {
				t.Fatalf("offline scheduling constructed %d issuers", factory.calls.Load())
			}
		})
	}
}

func TestRunInvokesRealEnsureAtRenewalBoundary(t *testing.T) {
	material := task9Material(t, 7*time.Hour, 3*time.Hour)
	factory := &forbiddenIssuerFactory{}
	manager, clock, _ := task9LoadedManager(t, material, factory)
	lock := newTask9ContextLock()
	manager.lock = lock
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)
	first := task9NextTimer(t, clock)
	first.fire(t)
	select {
	case <-lock.entered:
	case <-time.After(task9TestTimeout):
		t.Fatal("real Ensure did not run at the scheduled boundary")
	}
	wantBoundary := material.leaf.NotAfter.Add(-3 * time.Hour)
	if got := clock.Now(); !got.Equal(wantBoundary) {
		t.Fatalf("boundary Ensure time = %v, want %v", got, wantBoundary)
	}
	task9CancelAndAwait(t, cancel, result)
	if lock.calls.Load() != 1 {
		t.Fatalf("boundary lock calls = %d, want 1", lock.calls.Load())
	}
	task9AssertNoTimer(t, clock)
	assertNoManagerEvents(t, manager)
}

func TestRunImmediateDeferredRenewalUsesFiveSecondRetryBase(t *testing.T) {
	material := task9Material(t, 2*time.Hour, 3*time.Hour)
	cause := errors.New("transient initial renewal")
	lock := &task9FailureLock{err: cause}
	manager, clock, _ := task9LoadedManager(t, material, &forbiddenIssuerFactory{})
	manager.lock = lock
	active := manager.current.Load()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)

	timer := task9NextTimer(t, clock)
	if timer.delay != 2500*time.Millisecond {
		t.Fatalf("first deferred delay = %v, want equal-jitter half of 5s", timer.delay)
	}
	var deferred *DeferredRenewalError
	if err := task9ReceiveError(t, manager); !errors.As(err, &deferred) || !errors.Is(err, cause) {
		t.Fatalf("published error = %T %v, want DeferredRenewalError wrapping cause", err, err)
	}
	if manager.current.Load() != active {
		t.Fatal("deferred renewal replaced still-valid active material")
	}
	task9CancelAndAwait(t, cancel, result)
	if !timer.isStopped() {
		t.Fatal("Run did not stop the retry timer on cancellation")
	}
}

func TestRunEqualJitterBackoffCapsAtFiveMinutesAndResets(t *testing.T) {
	material := task9Material(t, 2*time.Hour, 3*time.Hour)
	replacementPEM, replacement := task9ReplacementCertificate(t, material, material.now.Add(100*time.Hour))
	cause := errors.New("retryable renewal")
	store := newStateStore(material.cfg)
	lock := &task9SequenceLock{
		commitAt: 9,
		err:      cause,
		commit: func() error {
			return store.writeFile(material.cfg.CertificateFile, replacementPEM, 0o644, "certificate")
		},
	}
	factory := &forbiddenIssuerFactory{}
	manager, clock, random := task9LoadedManager(t, material, factory)
	manager.lock = lock
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)

	bases := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		5 * time.Minute,
		5 * time.Minute,
	}
	for index, retryBase := range bases {
		timer := task9NextTimer(t, clock)
		if want := retryBase / 2; timer.delay != want {
			t.Fatalf("retry %d delay = %v, want %v from base %v", index+1, timer.delay, want, retryBase)
		}
		var deferred *DeferredRenewalError
		if err := task9ReceiveError(t, manager); !errors.As(err, &deferred) || !errors.Is(err, cause) {
			t.Fatalf("retry %d error = %T %v, want deferred cause", index+1, err, err)
		}
		timer.fire(t)
	}

	normalTimer := task9NextTimer(t, clock)
	wantBoundary := replacement.NotAfter.Add(-3 * time.Hour)
	if !normalTimer.when.Equal(wantBoundary) {
		t.Fatalf("post-success schedule = %v, want boundary %v", normalTimer.when, wantBoundary)
	}
	external := task9ReceiveChange(t, manager)
	if external.Renewed || !external.NotAfter.Equal(replacement.NotAfter) {
		t.Fatalf("backoff recovery change = %+v, want external replacement", external)
	}
	normalTimer.fire(t)
	resetTimer := task9NextTimer(t, clock)
	if resetTimer.delay != 2500*time.Millisecond {
		t.Fatalf("post-success retry delay = %v, want reset 5s base equal-jittered to 2.5s", resetTimer.delay)
	}
	if err := task9ReceiveError(t, manager); !errors.Is(err, cause) {
		t.Fatalf("post-reset published error = %T %v, want retry cause", err, err)
	}
	if lock.callCount() != 10 {
		t.Fatalf("real Ensure lock calls = %d, want 10", lock.callCount())
	}
	if random.callCount() != 9 {
		t.Fatalf("random calls = %d, want one for each of 9 retry delays", random.callCount())
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("external recovery constructed %d issuers", factory.calls.Load())
	}
	task9CancelAndAwait(t, cancel, result)
}

func TestRunDeferredRenewalBecomesFatalAtExpiry(t *testing.T) {
	material := task9Material(t, 7*time.Second, 3*time.Hour)
	cause := errors.New("renewal stayed unavailable")
	lock := &task9FailureLock{err: cause}
	manager, clock, _ := task9LoadedManager(t, material, &forbiddenIssuerFactory{})
	manager.lock = lock
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)

	first := task9NextTimer(t, clock)
	if first.delay != 2500*time.Millisecond {
		t.Fatalf("first retry delay = %v, want 2.5s", first.delay)
	}
	if err := task9ReceiveError(t, manager); !errors.Is(err, cause) {
		t.Fatalf("first published error = %T %v, want cause", err, err)
	}
	first.fire(t)
	second := task9NextTimer(t, clock)
	remaining := material.leaf.NotAfter.Sub(clock.Now())
	if second.delay > 5*time.Second || second.delay > remaining {
		t.Fatalf("expiry-bound retry delay = %v, want no later than min(5s, %v)", second.delay, remaining)
	}
	if err := task9ReceiveError(t, manager); !errors.Is(err, cause) {
		t.Fatalf("second published error = %T %v, want cause", err, err)
	}
	second.fire(t)
	err := task9AwaitRun(t, result)
	if !errors.Is(err, ErrNoUsableCertificate) || !errors.Is(err, cause) {
		t.Fatalf("expired Run error = %T %v, want ErrNoUsableCertificate and last cause", err, err)
	}
	if clock.Now().After(material.leaf.NotAfter) {
		t.Fatalf("Run became fatal at %v, after certificate expiry %v", clock.Now(), material.leaf.NotAfter)
	}
	if lock.calls.Load() != 2 {
		t.Fatalf("real Ensure calls before expiry = %d, want 2", lock.calls.Load())
	}
	task9AssertNoTimer(t, clock)
}

func TestRunCancellationDuringRealEnsureLockReturnsContextCanceled(t *testing.T) {
	material := task9Material(t, 2*time.Hour, 3*time.Hour)
	factory := &forbiddenIssuerFactory{}
	manager, clock, _ := task9LoadedManager(t, material, factory)
	lock := newTask9ContextLock()
	manager.lock = lock

	task9AssertCanceledRealEnsureRun(t, manager, clock, lock.entered)
	if lock.calls.Load() != 1 {
		t.Fatalf("canceled lock calls = %d, want 1", lock.calls.Load())
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("canceled lock constructed %d issuers", factory.calls.Load())
	}
}

func TestRunCancellationDuringRealEnsureACMEOrderReturnsContextCanceled(t *testing.T) {
	material := task9Material(t, 2*time.Hour, 3*time.Hour)
	_, _, account := writeManagerIssueAccount(t, material.cfg)
	entered := make(chan struct{})
	var enteredOnce sync.Once
	recorder := task9RecordingIssuer(material.cfg, account)
	recorder.obtain = func(ctx context.Context, _ crypto.Signer) ([]byte, error) {
		enteredOnce.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, safeACMEOperationError("order", ctx.Err())
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		context.Context,
		normalizedConfig,
		*x509.CertPool,
		crypto.Signer,
		*acme.ExtendedAccount,
	) (issuer, error) {
		return recorder, nil
	}}
	manager, clock, _ := task9LoadedManager(t, material, factory)

	task9AssertCanceledRealEnsureRun(t, manager, clock, entered)
	accounts, orders, closes := recorder.counts()
	if factory.callCount() != 1 || accounts != 1 || orders != 1 || closes != 1 {
		t.Fatalf("factory/account/order/close calls = %d/%d/%d/%d, want 1/1/1/1",
			factory.callCount(), accounts, orders, closes)
	}
}

func TestRunCancellationDuringRealHTTPProviderReturnsContextCanceled(t *testing.T) {
	material := task9Material(t, 2*time.Hour, 3*time.Hour)
	accountKey, _, account := writeManagerIssueAccount(t, material.cfg)
	provider := newTask9BlockingHTTPProvider()
	operations := &recordingLegoOperations{queryAccount: account}
	operations.obtain = func(ctx context.Context, _ certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
		if operations.provider == nil {
			return nil, errors.New("HTTP provider was not installed")
		}
		if err := operations.provider.Present(ctx, material.cfg.Domain, "task9-token", "task9-key-auth"); err != nil {
			return nil, err
		}
		return nil, errors.New("HTTP provider unexpectedly returned without cancellation")
	}
	adapter, err := newLegoIssuerWithOperations(
		material.cfg,
		accountKey,
		account,
		false,
		operations,
		provider,
	)
	if err != nil {
		t.Fatalf("create injected lego issuer: %v", err)
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		context.Context,
		normalizedConfig,
		*x509.CertPool,
		crypto.Signer,
		*acme.ExtendedAccount,
	) (issuer, error) {
		return adapter, nil
	}}
	manager, clock, _ := task9LoadedManager(t, material, factory)

	task9AssertCanceledRealEnsureRun(t, manager, clock, provider.entered)
	if factory.callCount() != 1 || len(operations.obtainRequests) != 1 || provider.closeCalls.Load() != 1 {
		t.Fatalf("factory/order/provider-close calls = %d/%d/%d, want 1/1/1",
			factory.callCount(), len(operations.obtainRequests), provider.closeCalls.Load())
	}
}

func TestCoalescingLatestErrorReplacesStaleValueWithoutBlocking(t *testing.T) {
	material := task9Material(t, 2*time.Hour, 3*time.Hour)
	oldCause := errors.New("stale renewal error")
	newCause := errors.New("latest renewal error")
	manager, clock, _ := task9LoadedManager(t, material, &forbiddenIssuerFactory{})
	manager.lock = &task9FailureLock{err: newCause}
	manager.errors <- &DeferredRenewalError{NotAfter: material.leaf.NotAfter, Err: oldCause}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)

	_ = task9NextTimer(t, clock)
	published := task9ReceiveError(t, manager)
	if !errors.Is(published, newCause) || errors.Is(published, oldCause) {
		t.Fatalf("coalesced error = %T %v, want only latest cause", published, published)
	}
	task9CancelAndAwait(t, cancel, result)
}

func TestCoalescingExternalDiskReplacementReloadsAndPublishesLatest(t *testing.T) {
	material := task9Material(t, 8*time.Hour, 3*time.Hour)
	factory := &forbiddenIssuerFactory{}
	manager, clock, _ := task9LoadedManager(t, material, factory)
	oldActive := manager.current.Load()
	replacementPEM, replacement := task9ReplacementCertificate(t, material, material.now.Add(12*time.Hour))
	if err := newStateStore(material.cfg).writeFile(
		material.cfg.CertificateFile,
		replacementPEM,
		0o644,
		"certificate",
	); err != nil {
		t.Fatalf("commit external certificate replacement: %v", err)
	}
	manager.changes <- CertificateChange{Renewed: true, NotAfter: material.now.Add(time.Hour)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)

	timer := task9NextTimer(t, clock)
	if want := replacement.NotAfter.Add(-3 * time.Hour); !timer.when.Equal(want) {
		t.Fatalf("external replacement schedule = %v, want %v", timer.when, want)
	}
	change := task9ReceiveChange(t, manager)
	if change.Renewed || !change.NotAfter.Equal(replacement.NotAfter) {
		t.Fatalf("external replacement change = %+v, want Renewed:false through %v", change, replacement.NotAfter)
	}
	active := manager.current.Load()
	if active == oldActive || active.leaf.SerialNumber.Cmp(replacement.SerialNumber) != 0 {
		t.Fatal("real Ensure did not reload and activate external certificate bytes")
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("external non-due replacement constructed %d issuers", factory.calls.Load())
	}
	task9CancelAndAwait(t, cancel, result)
	select {
	case extra := <-manager.Changes():
		t.Fatalf("external replacement emitted an extra change: %+v", extra)
	default:
	}
}

func TestRunPublishesExternalReplacementWhenLockReleaseFails(t *testing.T) {
	material := task9Material(t, 2*time.Hour, 3*time.Hour)
	replacementPEM, replacement := task9ReplacementCertificate(
		t,
		material,
		material.now.Add(12*time.Hour),
	)
	releaseErr := errors.New("release after external activation")
	store := newStateStore(material.cfg)
	lock := &task9SequenceLock{
		commitAt:   1,
		releaseErr: releaseErr,
		commit: func() error {
			return store.writeFile(
				material.cfg.CertificateFile,
				replacementPEM,
				0o644,
				"certificate",
			)
		},
	}
	factory := &forbiddenIssuerFactory{}
	manager, clock, _ := task9LoadedManager(t, material, factory)
	manager.lock = lock
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)

	retry := task9NextTimer(t, clock)
	if retry.delay != 2500*time.Millisecond {
		t.Fatalf("release-error retry delay = %v, want 2.5s", retry.delay)
	}
	publishedErr := task9ReceiveError(t, manager)
	var deferred *DeferredRenewalError
	if !errors.As(publishedErr, &deferred) ||
		!errors.Is(publishedErr, releaseErr) ||
		!deferred.NotAfter.Equal(replacement.NotAfter) {
		t.Fatalf(
			"release error publication = %T %v, want deferred external material through %v",
			publishedErr,
			publishedErr,
			replacement.NotAfter,
		)
	}
	change := task9ReceiveChange(t, manager)
	if change.Renewed || !change.NotAfter.Equal(replacement.NotAfter) {
		t.Fatalf(
			"release-error external change = %+v, want Renewed:false through %v",
			change,
			replacement.NotAfter,
		)
	}
	active := manager.current.Load()
	if active == nil || active.leaf.SerialNumber.Cmp(replacement.SerialNumber) != 0 {
		t.Fatal("release error lost the externally activated certificate")
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("external release error constructed %d issuers", factory.calls.Load())
	}
	task9CancelAndAwait(t, cancel, result)
}

func TestRunSameFingerprintDifferentActivePointerDoesNotPublish(t *testing.T) {
	material := task9Material(t, 8*time.Hour, 3*time.Hour)
	factory := &forbiddenIssuerFactory{}
	manager, clock, _ := task9LoadedManager(t, material, factory)
	oldActive := manager.current.Load()
	pkcs8 := encodeTestPrivateKey(t, material.leafKey, testKeyPKCS8)
	if err := newStateStore(material.cfg).writeFile(
		material.cfg.PrivateKeyFile,
		pkcs8,
		0o600,
		"private_key",
	); err != nil {
		t.Fatalf("commit equivalent key encoding: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)
	_ = task9NextTimer(t, clock)
	newActive := manager.current.Load()
	if newActive == oldActive {
		t.Fatal("test did not create a different active-material pointer")
	}
	if newActive.fingerprint != oldActive.fingerprint {
		t.Fatal("equivalent key encoding unexpectedly changed certificate fingerprint")
	}
	select {
	case change := <-manager.Changes():
		t.Fatalf("same certificate fingerprint emitted a change: %+v", change)
	default:
	}
	if factory.calls.Load() != 0 {
		t.Fatalf("equivalent non-due material constructed %d issuers", factory.calls.Load())
	}
	task9CancelAndAwait(t, cancel, result)
}

func TestRunUnchangedMaterialDoesNotPublishCertificateChange(t *testing.T) {
	material := task9Material(t, 8*time.Hour, 3*time.Hour)
	manager, clock, _ := task9LoadedManager(t, material, &forbiddenIssuerFactory{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)
	_ = task9NextTimer(t, clock)
	select {
	case change := <-manager.Changes():
		t.Fatalf("unchanged material emitted a change: %+v", change)
	default:
	}
	task9CancelAndAwait(t, cancel, result)
}

func TestRunOwnRenewalDrainsEnsureEventBeforeProvingExactlyOnce(t *testing.T) {
	material := task9Material(t, 2*time.Hour, 3*time.Hour)
	_, _, account := writeManagerIssueAccount(t, material.cfg)
	recorder := task9RecordingIssuer(material.cfg, account)
	renewedPEM := managerIssueChain(t, material, material.leafKey, nil)
	recorder.obtain = func(_ context.Context, signer crypto.Signer) ([]byte, error) {
		if !sameSigner(signer, material.leafKey) {
			return nil, errors.New("renewal did not reuse the active domain key")
		}
		return renewedPEM, nil
	}
	factory := &recordingManagerIssuerFactory{makeIssuer: func(
		context.Context,
		normalizedConfig,
		*x509.CertPool,
		crypto.Signer,
		*acme.ExtendedAccount,
	) (issuer, error) {
		return recorder, nil
	}}
	manager, clock, _ := task9LoadedManager(t, material, factory)
	published := make(chan struct{})
	allowEnsureReturn := make(chan struct{})
	var publishedOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(allowEnsureReturn) }) }
	t.Cleanup(release)
	var publicationCalls atomic.Int32
	manager.publishChange = func(change CertificateChange) {
		publicationCalls.Add(1)
		manager.enqueueChange(change)
		publishedOnce.Do(func() { close(published) })
		<-allowEnsureReturn
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := task9StartRun(manager, ctx)

	select {
	case <-published:
	case <-time.After(task9TestTimeout):
		t.Fatal("real Ensure did not publish its renewal event")
	}
	change := task9ReceiveChange(t, manager)
	if !change.Renewed || !change.NotAfter.Equal(material.now.Add(72*time.Hour)) {
		t.Fatalf("own renewal change = %+v, want real Ensure renewal through %v", change, material.now.Add(72*time.Hour))
	}
	select {
	case extra := <-manager.Changes():
		t.Fatalf("event duplicated before Ensure returned: %+v", extra)
	default:
	}
	release()
	timer := task9NextTimer(t, clock)
	if want := change.NotAfter.Add(-3 * time.Hour); !timer.when.Equal(want) {
		t.Fatalf("own renewal schedule = %v, want %v", timer.when, want)
	}
	if publicationCalls.Load() != 1 {
		t.Fatalf("renewal publication calls = %d, want exactly 1", publicationCalls.Load())
	}
	select {
	case extra := <-manager.Changes():
		t.Fatalf("Run emitted a second public renewal event after Ensure: %+v", extra)
	default:
	}
	accounts, orders, closes := recorder.counts()
	if factory.callCount() != 1 || accounts != 1 || orders != 1 || closes != 1 {
		t.Fatalf("factory/account/order/close calls = %d/%d/%d/%d, want 1/1/1/1",
			factory.callCount(), accounts, orders, closes)
	}
	task9CancelAndAwait(t, cancel, result)
}
