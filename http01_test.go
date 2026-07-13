package franztls

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge"
)

const (
	http01Domain  = "historian.internal"
	http01Token   = "exact-token"
	http01KeyAuth = "key-authorization"
)

type testHTTP01Deadlines struct {
	header   time.Duration
	read     time.Duration
	write    time.Duration
	idle     time.Duration
	shutdown time.Duration
}

type http01TestOptions struct {
	deadlines  testHTTP01Deadlines
	listen     func(ctx context.Context, network, address string) (net.Listener, error)
	diagnostic func(error)
}

func TestHTTP01ServesOnlyExactEscapedTokenAndHost(t *testing.T) {
	escapedToken := "exact/token% value"
	provider := startHTTP01Provider(t, escapedToken, http01KeyAuth, http01TestOptions{})
	escapedPath := "/.well-known/acme-challenge/" + url.PathEscape(escapedToken)

	for _, host := range []string{http01Domain, http01Domain + ":4711"} {
		response, body := rawHTTP01Request(t, provider, http.MethodGet, escapedPath, host, nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("Host %q status = %d, want 200", host, response.StatusCode)
		}
		if body != http01KeyAuth {
			t.Fatalf("Host %q body = %q, want key authorization", host, body)
		}
		if got := response.Header.Get("Content-Type"); got != "text/plain" {
			t.Fatalf("Content-Type = %q, want text/plain", got)
		}
		if !response.Close {
			t.Fatal("challenge response did not close its connection")
		}
	}
}

func TestHTTP01RejectsNearMissRoutesAndHosts(t *testing.T) {
	provider := startHTTP01Provider(t, http01Token, http01KeyAuth, http01TestOptions{})
	prefix := "/.well-known/acme-challenge/"
	tests := []struct {
		name string
		path string
		host string
	}{
		{"wrong token", prefix + "other-token", http01Domain},
		{"extra segment", prefix + http01Token + "/extra", http01Domain},
		{"query derived token", prefix + "?token=" + http01Token, http01Domain},
		{"semantically equal escaped path", prefix + "%65xact-token", http01Domain},
		{"wrong host", prefix + http01Token, "other.internal"},
		{"host suffix", prefix + http01Token, http01Domain + ".attacker"},
		{"empty host", prefix + http01Token, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, _ := rawHTTP01Request(t, provider, http.MethodGet, test.path, test.host, nil)
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", response.StatusCode)
			}
		})
	}
}

func TestHTTP01AllowsOnlyGETWithoutBody(t *testing.T) {
	provider := startHTTP01Provider(t, http01Token, http01KeyAuth, http01TestOptions{})
	path := "/.well-known/acme-challenge/" + http01Token
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			response, _ := rawHTTP01Request(t, provider, method, path, http01Domain, nil)
			if response.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", response.StatusCode)
			}
			if got := response.Header.Get("Allow"); got != http.MethodGet {
				t.Fatalf("Allow = %q, want GET", got)
			}
		})
	}

	extra := "Content-Length: 1\r\n"
	response, _ := rawHTTP01Request(t, provider, http.MethodGet, path, http01Domain, &extra)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("request with Content-Length status = %d, want 400", response.StatusCode)
	}

	extra = "Transfer-Encoding: chunked\r\n"
	response, _ = rawHTTP01Request(t, provider, http.MethodGet, path, http01Domain, &extra)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("chunked request status = %d, want 400", response.StatusCode)
	}
}

func TestHTTP01EnforcesExactHeaderByteLimit(t *testing.T) {
	provider := startHTTP01Provider(t, http01Token, http01KeyAuth, http01TestOptions{})
	path := "/.well-known/acme-challenge/" + http01Token

	for _, test := range []struct {
		size int
		want int
	}{
		{size: 16_384, want: http.StatusOK},
		{size: 16_385, want: http.StatusRequestHeaderFieldsTooLarge},
	} {
		t.Run(fmt.Sprintf("bytes-%d", test.size), func(t *testing.T) {
			request := exactSizeHTTPRequest(t, test.size, path, http01Domain)
			response, _ := exchangeRawHTTP01(t, provider, request, http.MethodGet)
			if response.StatusCode != test.want {
				t.Fatalf("%d-byte header status = %d, want %d", test.size, response.StatusCode, test.want)
			}
		})
	}
}

func TestHTTP01DefaultDeadlinesAreBounded(t *testing.T) {
	provider := newHTTP01Provider(http01Domain, "127.0.0.1:0")
	want := testHTTP01Deadlines{
		header:   5 * time.Second,
		read:     10 * time.Second,
		write:    10 * time.Second,
		idle:     30 * time.Second,
		shutdown: 5 * time.Second,
	}
	got := testHTTP01Deadlines{
		header: provider.deadlines.header, read: provider.deadlines.read,
		write: provider.deadlines.write, idle: provider.deadlines.idle,
		shutdown: provider.deadlines.shutdown,
	}
	if got != want {
		t.Fatalf("deadlines = %+v, want %+v", got, want)
	}
}

func TestHTTP01AppliesIdleAndWriteDeadlinesBeforeEarlyResponses(t *testing.T) {
	provider := configureHTTP01ProviderForTest(http01Domain, "127.0.0.1:0", http01TestOptions{})
	serverConnection, clientConnection := net.Pipe()
	recordingConnection := &deadlineRecordingHTTP01Conn{Conn: serverConnection}
	provider.workers.Add(1)
	served := make(chan struct{})
	go func() {
		provider.serveConnection(recordingConnection)
		close(served)
	}()
	defer clientConnection.Close()

	if err := clientConnection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := exactSizeHTTPRequest(
		t,
		http01HeaderLimit+1,
		"/.well-known/acme-challenge/"+http01Token,
		http01Domain,
	)
	if _, err := io.WriteString(clientConnection, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(
		bufio.NewReader(clientConnection),
		&http.Request{Method: http.MethodGet},
	)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431", response.StatusCode)
	}
	select {
	case <-served:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("early response did not complete")
	}

	if !recordingConnection.recorded("idle") {
		t.Fatal("connection idle deadline was not applied")
	}
	if !recordingConnection.recorded("write") {
		t.Fatal("early response did not receive a write deadline")
	}
}

func TestHTTP01HeaderAndTotalReadDeadlinesCloseSlowClients(t *testing.T) {
	for _, test := range []struct {
		name      string
		deadlines testHTTP01Deadlines
	}{
		{
			name: "header deadline",
			deadlines: testHTTP01Deadlines{
				header: 100 * time.Millisecond, read: time.Second,
				write: time.Second, idle: time.Second, shutdown: 500 * time.Millisecond,
			},
		},
		{
			name: "total read deadline",
			deadlines: testHTTP01Deadlines{
				header: time.Second, read: 100 * time.Millisecond,
				write: time.Second, idle: time.Second, shutdown: 500 * time.Millisecond,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := startHTTP01Provider(t, http01Token, http01KeyAuth, http01TestOptions{deadlines: test.deadlines})
			connection := dialHTTP01(t, provider)
			defer connection.Close()
			if _, err := io.WriteString(connection, "GET /.well-known/acme-challenge/"); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			_, err := connection.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("slow connection remained readable")
			}
			if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
				t.Fatalf("slow connection closed after %v", elapsed)
			}
		})
	}
}

func TestHTTP01WriteDeadlineBoundsUnreadResponse(t *testing.T) {
	diagnostics := make(chan error, 4)
	deadlines := testHTTP01Deadlines{
		header: time.Second, read: time.Second,
		write: 150 * time.Millisecond, idle: time.Second, shutdown: 500 * time.Millisecond,
	}
	keyAuth := strings.Repeat("k", 8<<20)
	provider := startHTTP01Provider(t, http01Token, keyAuth, http01TestOptions{
		deadlines: deadlines,
		diagnostic: func(err error) {
			diagnostics <- err
		},
	})
	connection := dialHTTP01(t, provider)
	defer connection.Close()
	if tcp, ok := connection.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(1)
	}
	request := fmt.Sprintf(
		"GET /.well-known/acme-challenge/%s HTTP/1.1\r\nHost: %s\r\n\r\n",
		http01Token,
		http01Domain,
	)
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-diagnostics:
		if err == nil {
			t.Fatal("write failure diagnostic is nil")
		}
		assertHTTP01Redacted(t, err, http01Token, keyAuth)
	case <-time.After(2 * time.Second):
		t.Fatal("unread response was not bounded by write deadline")
	}
}

func TestHTTP01ImplementsLegoProvider(t *testing.T) {
	var _ challenge.Provider = (*http01Provider)(nil)
}

func TestHTTP01CleanUpClosesListenerAndActiveConnections(t *testing.T) {
	deadlines := testHTTP01Deadlines{
		header: time.Second, read: time.Second, write: time.Second,
		idle: time.Second, shutdown: 100 * time.Millisecond,
	}
	provider := startHTTP01Provider(t, http01Token, http01KeyAuth, http01TestOptions{deadlines: deadlines})
	connection := dialHTTP01(t, provider)
	if _, err := io.WriteString(connection, "GET /partial"); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	if err := provider.CleanUp(context.Background(), http01Domain, http01Token, http01KeyAuth); err != nil {
		assertHTTP01Redacted(t, err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("CleanUp returned after %v", elapsed)
	}
	waitHTTP01Closed(t, provider)
	assertHTTP01ChallengeCleared(t, provider)
	if err := connection.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("active connection survived CleanUp")
	}
	_ = connection.Close()
	assertHTTP01CannotDial(t, provider)
}

func TestHTTP01ContextCancellationClosesListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	provider := newHTTP01Provider(http01Domain, "127.0.0.1:0")
	if err := provider.Present(ctx, http01Domain, http01Token, http01KeyAuth); err != nil {
		t.Fatalf("Present() error = %v", err)
	}
	connection := dialHTTP01(t, provider)
	cancel()
	waitHTTP01Closed(t, provider)
	assertHTTP01ChallengeCleared(t, provider)
	if err := connection.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("active connection survived context cancellation")
	}
	_ = connection.Close()
	assertHTTP01CannotDial(t, provider)
}

func TestHTTP01ListenerFailureClosesAndRedactsDiagnostics(t *testing.T) {
	listenerErr := errors.New("accept failed containing " + http01Token + " and " + http01KeyAuth)
	listener := newFailingHTTP01Listener(listenerErr)
	diagnostics := make(chan error, 2)
	provider := configureHTTP01ProviderForTest(http01Domain, "127.0.0.1:0", http01TestOptions{
		listen: func(context.Context, string, string) (net.Listener, error) {
			return listener, nil
		},
		diagnostic: func(err error) {
			diagnostics <- err
		},
	})
	if err := provider.Present(context.Background(), http01Domain, http01Token, http01KeyAuth); err != nil {
		t.Fatalf("Present() error = %v", err)
	}
	waitHTTP01Closed(t, provider)
	assertHTTP01ChallengeCleared(t, provider)
	select {
	case err := <-diagnostics:
		assertHTTP01Redacted(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("listener failure did not produce a diagnostic")
	}
	select {
	case <-listener.closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("failed listener was not closed")
	}
}

func TestHTTP01PresentFailureIsSafeAndLeavesNoListener(t *testing.T) {
	bindErr := errors.New("bind failed containing " + http01Token + " and " + http01KeyAuth)
	provider := configureHTTP01ProviderForTest(http01Domain, "127.0.0.1:0", http01TestOptions{
		listen: func(context.Context, string, string) (net.Listener, error) {
			return nil, bindErr
		},
	})
	err := provider.Present(context.Background(), http01Domain, http01Token, http01KeyAuth)
	if err == nil {
		t.Fatal("Present() unexpectedly succeeded")
	}
	assertHTTP01Redacted(t, err)
	waitHTTP01Closed(t, provider)
	assertHTTP01ChallengeCleared(t, provider)

	wrongDomain := newHTTP01Provider(http01Domain, "127.0.0.1:0")
	err = wrongDomain.Present(context.Background(), "other.internal", http01Token, http01KeyAuth)
	if err == nil {
		t.Fatal("Present() accepted a domain other than the configured domain")
	}
	assertHTTP01Redacted(t, err)
	waitHTTP01Closed(t, wrongDomain)
}

func TestHTTP01LateListenerCannotResurrectCompletedStartup(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	lateListener := newBlockingHTTP01Listener()
	provider := configureHTTP01ProviderForTest(http01Domain, "127.0.0.1:0", http01TestOptions{
		listen: func(context.Context, string, string) (net.Listener, error) {
			enteredOnce.Do(func() { close(entered) })
			<-release
			return lateListener, nil
		},
	})
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		unblock()
		_ = lateListener.Close()
		if err := provider.CleanUp(context.Background(), http01Domain, http01Token, http01KeyAuth); err != nil {
			t.Errorf("CleanUp() error = %v", err)
		}
		waitHTTP01Closed(t, provider)
	})

	presentResult := make(chan error, 1)
	go func() {
		presentResult <- provider.Present(context.Background(), http01Domain, http01Token, http01KeyAuth)
	}()
	select {
	case <-entered:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Present did not enter injected listen")
	}
	if err := provider.CleanUp(context.Background(), http01Domain, http01Token, http01KeyAuth); err != nil {
		t.Fatalf("CleanUp during startup error = %v", err)
	}
	waitHTTP01Closed(t, provider)
	assertHTTP01ChallengeCleared(t, provider)
	unblock()

	select {
	case err := <-presentResult:
		if err == nil {
			t.Fatal("Present succeeded after its generation completed")
		}
		assertHTTP01Redacted(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Present remained blocked after listen returned")
	}
	select {
	case <-lateListener.closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("late listener was not closed")
	}
	provider.mu.Lock()
	resurrected := provider.started || provider.listener != nil
	provider.mu.Unlock()
	if resurrected {
		t.Fatal("completed HTTP-01 generation was resurrected")
	}
}

func TestHTTP01CancellationCompletesBlockedStartup(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	lateListener := newBlockingHTTP01Listener()
	provider := configureHTTP01ProviderForTest(http01Domain, "127.0.0.1:0", http01TestOptions{
		listen: func(ctx context.Context, _, _ string) (net.Listener, error) {
			enteredOnce.Do(func() { close(entered) })
			select {
			case <-ctx.Done():
				_ = lateListener.Close()
				return nil, ctx.Err()
			case <-release:
				return lateListener, nil
			}
		},
	})
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		unblock()
		_ = lateListener.Close()
		if err := provider.CleanUp(context.Background(), http01Domain, http01Token, http01KeyAuth); err != nil {
			t.Errorf("CleanUp() error = %v", err)
		}
		waitHTTP01Closed(t, provider)
	})

	ctx, cancel := context.WithCancel(context.Background())
	presentResult := make(chan error, 1)
	go func() {
		presentResult <- provider.Present(ctx, http01Domain, http01Token, http01KeyAuth)
	}()
	select {
	case <-entered:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Present did not enter injected listen")
	}
	cancel()
	select {
	case err := <-presentResult:
		if err == nil {
			t.Fatal("Present succeeded after cancellation completed startup")
		}
		assertHTTP01Redacted(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Present remained blocked after cancellation")
	}
	waitHTTP01Closed(t, provider)
	assertHTTP01ChallengeCleared(t, provider)
	select {
	case <-lateListener.closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("listener returned after cancellation was not closed")
	}
}

func TestHTTP01CleanUpAfterChallengeFailureIsBoundedAndRedacted(t *testing.T) {
	provider := startHTTP01Provider(t, http01Token, http01KeyAuth, http01TestOptions{})
	err := provider.CleanUp(
		context.Background(),
		http01Domain,
		http01Token,
		http01KeyAuth,
	)
	if err != nil {
		assertHTTP01Redacted(t, err)
	}
	waitHTTP01Closed(t, provider)
	assertHTTP01ChallengeCleared(t, provider)
	assertHTTP01CannotDial(t, provider)
}

func TestHTTP01CleanUpTimeoutBoundsStalledListenerClose(t *testing.T) {
	listener := newStalledCloseHTTP01Listener()
	deadlines := testHTTP01Deadlines{
		header: time.Second, read: time.Second, write: time.Second,
		idle: time.Second, shutdown: 150 * time.Millisecond,
	}
	provider := startHTTP01Provider(t, http01Token, http01KeyAuth, http01TestOptions{
		deadlines: deadlines,
		listen: func(context.Context, string, string) (net.Listener, error) {
			return listener, nil
		},
	})
	releaseTimer := time.AfterFunc(time.Second, listener.releaseClose)
	defer func() {
		releaseTimer.Stop()
		listener.releaseClose()
	}()

	started := time.Now()
	err := provider.CleanUp(context.Background(), http01Domain, http01Token, http01KeyAuth)
	if err == nil {
		t.Fatal("CleanUp unexpectedly waited through stalled listener close")
	}
	assertHTTP01Redacted(t, err)
	if elapsed := time.Since(started); elapsed > 650*time.Millisecond {
		t.Fatalf("CleanUp returned after %v, want shutdown timeout bound", elapsed)
	}
	select {
	case <-listener.closeStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("listener close was not attempted")
	}
	listener.releaseClose()
	waitHTTP01Closed(t, provider)
	assertHTTP01ChallengeCleared(t, provider)
}

func TestHTTP01CanBeReusedAndStaleCleanUpDoesNotStopRenewal(t *testing.T) {
	provider := newHTTP01Provider(http01Domain, "127.0.0.1:0")
	if err := provider.Present(context.Background(), http01Domain, http01Token, http01KeyAuth); err != nil {
		t.Fatalf("first Present() error = %v", err)
	}
	firstDone := provider.done()
	if err := provider.CleanUp(context.Background(), http01Domain, http01Token, http01KeyAuth); err != nil {
		t.Fatalf("first CleanUp() error = %v", err)
	}
	select {
	case <-firstDone:
	case <-time.After(750 * time.Millisecond):
		t.Fatal("first challenge did not close")
	}
	assertHTTP01ChallengeCleared(t, provider)

	renewalToken := "renewal-token"
	renewalKeyAuth := "renewal-key-authorization"
	if err := provider.Present(context.Background(), http01Domain, renewalToken, renewalKeyAuth); err != nil {
		t.Fatalf("renewal Present() error = %v", err)
	}
	renewalDone := provider.done()
	if renewalDone == firstDone {
		t.Fatal("renewal reused the completed lifecycle channel")
	}
	t.Cleanup(func() {
		if err := provider.CleanUp(context.Background(), http01Domain, renewalToken, renewalKeyAuth); err != nil {
			t.Errorf("renewal CleanUp() error = %v", err)
		}
		waitHTTP01Closed(t, provider)
	})

	if err := provider.CleanUp(context.Background(), http01Domain, http01Token, http01KeyAuth); err != nil {
		assertHTTP01Redacted(t, err)
	}
	select {
	case <-renewalDone:
		t.Fatal("stale cleanup stopped the active renewal")
	default:
	}
	path := "/.well-known/acme-challenge/" + renewalToken
	response, body := rawHTTP01Request(t, provider, http.MethodGet, path, http01Domain, nil)
	if response.StatusCode != http.StatusOK || body != renewalKeyAuth {
		t.Fatalf("renewal response = (%d, %q), want (200, renewal key authorization)", response.StatusCode, body)
	}
}

func TestHTTP01TimeoutDiagnosticsNeverExposeRequestSecrets(t *testing.T) {
	diagnostics := make(chan error, 4)
	deadlines := testHTTP01Deadlines{
		header: 100 * time.Millisecond, read: time.Second,
		write: time.Second, idle: time.Second, shutdown: 500 * time.Millisecond,
	}
	provider := startHTTP01Provider(t, http01Token, http01KeyAuth, http01TestOptions{
		deadlines: deadlines,
		diagnostic: func(err error) {
			diagnostics <- err
		},
	})
	connection := dialHTTP01(t, provider)
	defer connection.Close()
	partial := "GET /.well-known/acme-challenge/" + http01Token + " HTTP/1.1\r\nX-Key: " + http01KeyAuth
	if _, err := io.WriteString(connection, partial); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-diagnostics:
		assertHTTP01Redacted(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("header timeout did not produce a diagnostic")
	}
}

func startHTTP01Provider(
	t *testing.T,
	token string,
	keyAuth string,
	options http01TestOptions,
) *http01Provider {
	t.Helper()
	provider := configureHTTP01ProviderForTest(http01Domain, "127.0.0.1:0", options)
	if err := provider.Present(context.Background(), http01Domain, token, keyAuth); err != nil {
		t.Fatalf("Present() error = %v", err)
	}
	t.Cleanup(func() {
		if err := provider.CleanUp(context.Background(), http01Domain, token, keyAuth); err != nil {
			t.Errorf("CleanUp() error = %v", err)
		}
		waitHTTP01Closed(t, provider)
	})
	return provider
}

func configureHTTP01ProviderForTest(
	domain string,
	address string,
	options http01TestOptions,
) *http01Provider {
	deadlines := http01Deadlines{}
	if options.deadlines != (testHTTP01Deadlines{}) {
		deadlines = http01Deadlines{
			header:   options.deadlines.header,
			read:     options.deadlines.read,
			write:    options.deadlines.write,
			idle:     options.deadlines.idle,
			shutdown: options.deadlines.shutdown,
		}
	}
	return newHTTP01ProviderWithOptions(domain, address, http01ProviderOptions{
		deadlines:  deadlines,
		listen:     options.listen,
		diagnostic: options.diagnostic,
	})
}

func rawHTTP01Request(
	t *testing.T,
	provider *http01Provider,
	method string,
	path string,
	host string,
	extraHeader *string,
) (*http.Response, string) {
	t.Helper()
	headers := ""
	if host != "" {
		headers += "Host: " + host + "\r\n"
	}
	if extraHeader != nil {
		headers += *extraHeader
	}
	request := fmt.Sprintf("%s %s HTTP/1.1\r\n%s\r\n", method, path, headers)
	return exchangeRawHTTP01(t, provider, request, method)
}

func exchangeRawHTTP01(
	t *testing.T,
	provider *http01Provider,
	request string,
	method string,
) (*http.Response, string) {
	t.Helper()
	connection := dialHTTP01(t, provider)
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return response, string(body)
}

func exactSizeHTTPRequest(t *testing.T, size int, path string, host string) string {
	t.Helper()
	prefix := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nX-Fill: ", path, host)
	suffix := "\r\n\r\n"
	fill := size - len(prefix) - len(suffix)
	if fill < 0 {
		t.Fatalf("request framing exceeds requested size %d", size)
	}
	request := prefix + strings.Repeat("a", fill) + suffix
	if len(request) != size {
		t.Fatalf("request size = %d, want %d", len(request), size)
	}
	return request
}

func dialHTTP01(t *testing.T, provider *http01Provider) net.Conn {
	t.Helper()
	parsed, err := url.Parse(provider.URL())
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp", parsed.Host, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial HTTP-01 listener: %v", err)
	}
	return connection
}

func waitHTTP01Closed(t *testing.T, provider *http01Provider) {
	t.Helper()
	select {
	case <-provider.done():
	case <-time.After(750 * time.Millisecond):
		t.Fatal("HTTP-01 provider did not close")
	}
}

func assertHTTP01CannotDial(t *testing.T, provider *http01Provider) {
	t.Helper()
	parsed, err := url.Parse(provider.URL())
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp", parsed.Host, 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("HTTP-01 listener still accepts connections")
	}
}

func assertHTTP01Redacted(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	if len(secrets) == 0 {
		secrets = []string{http01Token, http01KeyAuth}
	}
	message := err.Error()
	for _, secret := range secrets {
		if strings.Contains(message, secret) {
			t.Fatalf("error exposed challenge secret: %q", message)
		}
	}
}

func assertHTTP01ChallengeCleared(t *testing.T, provider *http01Provider) {
	t.Helper()
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.challenge != (http01Challenge{}) {
		t.Fatal("provider retained challenge material after shutdown")
	}
}

type failingHTTP01Listener struct {
	err    error
	closed chan struct{}
	once   sync.Once
}

func newFailingHTTP01Listener(err error) *failingHTTP01Listener {
	return &failingHTTP01Listener{err: err, closed: make(chan struct{})}
}

func (listener *failingHTTP01Listener) Accept() (net.Conn, error) {
	return nil, listener.err
}

func (listener *failingHTTP01Listener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}

func (listener *failingHTTP01Listener) Addr() net.Addr {
	return staticHTTP01Address("127.0.0.1:1")
}

type staticHTTP01Address string

func (address staticHTTP01Address) Network() string { return "tcp" }
func (address staticHTTP01Address) String() string  { return string(address) }

type blockingHTTP01Listener struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingHTTP01Listener() *blockingHTTP01Listener {
	return &blockingHTTP01Listener{closed: make(chan struct{})}
}

func (listener *blockingHTTP01Listener) Accept() (net.Conn, error) {
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *blockingHTTP01Listener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}

func (listener *blockingHTTP01Listener) Addr() net.Addr {
	return staticHTTP01Address("127.0.0.1:1")
}

type stalledCloseHTTP01Listener struct {
	closeStarted chan struct{}
	closeRelease chan struct{}
	acceptDone   chan struct{}
	startOnce    sync.Once
	releaseOnce  sync.Once
	doneOnce     sync.Once
}

func newStalledCloseHTTP01Listener() *stalledCloseHTTP01Listener {
	return &stalledCloseHTTP01Listener{
		closeStarted: make(chan struct{}),
		closeRelease: make(chan struct{}),
		acceptDone:   make(chan struct{}),
	}
}

func (listener *stalledCloseHTTP01Listener) Accept() (net.Conn, error) {
	<-listener.acceptDone
	return nil, net.ErrClosed
}

func (listener *stalledCloseHTTP01Listener) Close() error {
	listener.startOnce.Do(func() { close(listener.closeStarted) })
	<-listener.closeRelease
	listener.doneOnce.Do(func() { close(listener.acceptDone) })
	return nil
}

func (listener *stalledCloseHTTP01Listener) Addr() net.Addr {
	return staticHTTP01Address("127.0.0.1:1")
}

func (listener *stalledCloseHTTP01Listener) releaseClose() {
	listener.releaseOnce.Do(func() { close(listener.closeRelease) })
}

type deadlineRecordingHTTP01Conn struct {
	net.Conn
	mu    sync.Mutex
	kinds []string
}

func (connection *deadlineRecordingHTTP01Conn) SetDeadline(deadline time.Time) error {
	connection.record("idle")
	return connection.Conn.SetDeadline(deadline)
}

func (connection *deadlineRecordingHTTP01Conn) SetReadDeadline(deadline time.Time) error {
	connection.record("read")
	return connection.Conn.SetReadDeadline(deadline)
}

func (connection *deadlineRecordingHTTP01Conn) SetWriteDeadline(deadline time.Time) error {
	connection.record("write")
	return connection.Conn.SetWriteDeadline(deadline)
}

func (connection *deadlineRecordingHTTP01Conn) record(kind string) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.kinds = append(connection.kinds, kind)
}

func (connection *deadlineRecordingHTTP01Conn) recorded(kind string) bool {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	for _, recorded := range connection.kinds {
		if recorded == kind {
			return true
		}
	}
	return false
}
