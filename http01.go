package franztls

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	http01HeaderLimit = 16 * 1024
	http01PathPrefix  = "/.well-known/acme-challenge/"
)

var (
	errHTTP01HeaderTooLarge = errors.New("HTTP-01 request headers too large")
	errHTTP01RequestBody    = errors.New("HTTP-01 request body is not accepted")
)

type http01Deadlines struct {
	header   time.Duration
	read     time.Duration
	write    time.Duration
	idle     time.Duration
	shutdown time.Duration
}

type http01ProviderOptions struct {
	deadlines  http01Deadlines
	listen     func(ctx context.Context, network, address string) (net.Listener, error)
	diagnostic func(error)
}

type http01Challenge struct {
	domain      string
	token       string
	escapedPath string
	keyAuth     string
}

type http01Provider struct {
	domain  string
	address string

	deadlines  http01Deadlines
	listen     func(ctx context.Context, network, address string) (net.Listener, error)
	diagnostic func(error)

	mu          sync.Mutex
	listener    net.Listener
	listenerURL string
	challenge   http01Challenge
	connections map[net.Conn]struct{}
	started     bool
	stopping    bool
	generation  uint64
	completed   bool

	workers sync.WaitGroup
	doneCh  chan struct{}
}

func newHTTP01Provider(domain, address string) *http01Provider {
	return newHTTP01ProviderWithOptions(domain, address, http01ProviderOptions{})
}

func newHTTP01ProviderWithOptions(
	domain string,
	address string,
	options http01ProviderOptions,
) *http01Provider {
	provider := &http01Provider{
		domain:  domain,
		address: address,
		deadlines: http01Deadlines{
			header:   5 * time.Second,
			read:     10 * time.Second,
			write:    10 * time.Second,
			idle:     30 * time.Second,
			shutdown: 5 * time.Second,
		},
		listen:      new(net.ListenConfig).Listen,
		diagnostic:  func(error) {},
		connections: make(map[net.Conn]struct{}),
		doneCh:      make(chan struct{}),
	}
	if options.deadlines != (http01Deadlines{}) {
		provider.deadlines = options.deadlines
	}
	if options.listen != nil {
		provider.listen = options.listen
	}
	if options.diagnostic != nil {
		provider.diagnostic = options.diagnostic
	}
	return provider
}

func (p *http01Provider) Present(ctx context.Context, domain, token, keyAuth string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	generation, done, ok := p.beginGeneration()
	if !ok {
		return errors.New("franztls: HTTP-01 challenge is already active")
	}
	if err := ctx.Err(); err != nil {
		p.finishFailedStart(generation)
		return errors.New("franztls: HTTP-01 challenge start canceled")
	}
	if !strings.EqualFold(domain, p.domain) || token == "" || keyAuth == "" {
		p.finishFailedStart(generation)
		return errors.New("franztls: invalid HTTP-01 challenge")
	}

	p.mu.Lock()
	p.challenge = http01Challenge{
		domain:      p.domain,
		token:       token,
		escapedPath: http01PathPrefix + url.PathEscape(token),
		keyAuth:     keyAuth,
	}
	p.mu.Unlock()

	listener, err := p.listen(ctx, "tcp", p.address)
	if err != nil {
		p.finishFailedStart(generation)
		return errors.New("franztls: HTTP-01 listener start failed")
	}
	if ctx.Err() != nil {
		_ = listener.Close()
		p.finishFailedStart(generation)
		return errors.New("franztls: HTTP-01 challenge start canceled")
	}

	p.mu.Lock()
	if p.generation != generation || !p.started || p.stopping || p.completed {
		p.mu.Unlock()
		_ = listener.Close()
		p.finishFailedStart(generation)
		return errors.New("franztls: HTTP-01 challenge stopped during startup")
	}
	p.listener = listener
	p.listenerURL = "http://" + listener.Addr().String()
	p.workers.Add(1)
	p.mu.Unlock()

	go p.acceptLoop(listener, generation)
	go p.finishWhenWorkersStop(generation)
	go func(generation uint64, done <-chan struct{}) {
		select {
		case <-ctx.Done():
			p.initiateShutdown(generation)
		case <-done:
		}
	}(generation, done)
	return nil
}

func (p *http01Provider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	generation, done, shutdown, ok := p.cleanupTarget(domain, token, keyAuth)
	if !ok {
		return nil
	}
	p.initiateShutdown(generation)
	timer := time.NewTimer(shutdown)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		p.initiateShutdown(generation)
		return errors.New("franztls: HTTP-01 shutdown canceled")
	case <-timer.C:
		p.initiateShutdown(generation)
		return errors.New("franztls: HTTP-01 shutdown timed out")
	}
}

func (p *http01Provider) URL() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.listenerURL
}

func (p *http01Provider) done() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.doneCh
}

func (p *http01Provider) acceptLoop(listener net.Listener, generation uint64) {
	defer p.workers.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if !p.isStoppingGeneration(generation) {
				p.report(errors.New("franztls: HTTP-01 listener failed"))
				p.initiateShutdown(generation)
			}
			return
		}
		if !p.trackConnectionForGeneration(connection, generation) {
			_ = connection.Close()
			return
		}
		p.workers.Add(1)
		go p.serveConnection(connection)
	}
}

func (p *http01Provider) serveConnection(connection net.Conn) {
	defer p.workers.Done()
	defer p.untrackConnection(connection)
	defer connection.Close()

	now := time.Now()
	if err := connection.SetDeadline(now.Add(p.deadlines.idle)); err != nil {
		p.reportConnectionError("idle deadline", err)
		return
	}
	readDeadline := now.Add(p.deadlines.read)
	headerDeadline := now.Add(p.deadlines.header)
	if headerDeadline.Before(readDeadline) {
		readDeadline = headerDeadline
	}
	if err := connection.SetReadDeadline(readDeadline); err != nil {
		p.reportConnectionError("read deadline", err)
		return
	}

	request, err := readBoundedHTTP01Request(connection)
	if deadlineErr := connection.SetWriteDeadline(time.Now().Add(p.deadlines.write)); deadlineErr != nil {
		p.reportConnectionError("write deadline", deadlineErr)
		return
	}
	if err != nil {
		if errors.Is(err, errHTTP01HeaderTooLarge) {
			p.writeStatus(connection, http.StatusRequestHeaderFieldsTooLarge, nil, "")
			return
		}
		if errors.Is(err, errHTTP01RequestBody) {
			p.writeStatus(connection, http.StatusBadRequest, nil, "")
			return
		}
		if !errors.Is(err, io.EOF) && !p.isStopping() {
			p.report(errors.New("franztls: HTTP-01 request read failed"))
		}
		return
	}

	p.respond(connection, request)
}

func (p *http01Provider) respond(connection net.Conn, request *http.Request) {
	p.mu.Lock()
	challenge := p.challenge
	p.mu.Unlock()

	host, ok := http01HostWithoutOptionalPort(request.Host)
	if !ok || !strings.EqualFold(host, challenge.domain) || request.URL.EscapedPath() != challenge.escapedPath {
		p.writeStatus(connection, http.StatusNotFound, nil, "")
		return
	}
	if request.Method != http.MethodGet {
		p.writeStatus(connection, http.StatusMethodNotAllowed, map[string]string{"Allow": http.MethodGet}, "")
		return
	}
	p.writeStatus(connection, http.StatusOK, map[string]string{"Content-Type": "text/plain"}, challenge.keyAuth)
}

func (p *http01Provider) writeStatus(
	connection net.Conn,
	status int,
	headers map[string]string,
	body string,
) {
	var response strings.Builder
	fmt.Fprintf(&response, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for name, value := range headers {
		fmt.Fprintf(&response, "%s: %s\r\n", name, value)
	}
	fmt.Fprintf(&response, "Content-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	if _, err := io.WriteString(connection, response.String()); err != nil {
		p.reportConnectionError("response write", err)
		return
	}
	if body == "" {
		return
	}
	if _, err := io.Copy(connection, strings.NewReader(body)); err != nil {
		p.reportConnectionError("response write", err)
	}
}

func readBoundedHTTP01Request(connection net.Conn) (*http.Request, error) {
	reader := bufio.NewReaderSize(connection, 4*1024)
	buffer := make([]byte, 0, http01HeaderLimit)
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		buffer = append(buffer, value)
		if len(buffer) > http01HeaderLimit {
			return nil, errHTTP01HeaderTooLarge
		}
		if len(buffer) >= 4 && bytes.Equal(buffer[len(buffer)-4:], []byte("\r\n\r\n")) {
			break
		}
	}

	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buffer)))
	if err != nil {
		return nil, errors.New("malformed HTTP-01 request")
	}
	if request.Body != nil {
		defer request.Body.Close()
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		return nil, errHTTP01RequestBody
	}
	return request, nil
}

func http01HostWithoutOptionalPort(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	if !strings.Contains(host, ":") {
		return host, true
	}
	name, port, err := net.SplitHostPort(host)
	if err != nil || name == "" || port == "" {
		return "", false
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", false
	}
	return name, true
}

func (p *http01Provider) trackConnectionForGeneration(connection net.Conn, generation uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started || p.stopping || p.generation != generation {
		return false
	}
	p.connections[connection] = struct{}{}
	return true
}

func (p *http01Provider) untrackConnection(connection net.Conn) {
	p.mu.Lock()
	delete(p.connections, connection)
	p.mu.Unlock()
}

func (p *http01Provider) beginGeneration() (uint64, <-chan struct{}, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started || p.stopping {
		return 0, nil, false
	}
	p.generation++
	p.started = true
	p.completed = false
	p.listener = nil
	p.challenge = http01Challenge{}
	p.connections = make(map[net.Conn]struct{})
	p.workers = sync.WaitGroup{}
	p.doneCh = make(chan struct{})
	return p.generation, p.doneCh, true
}

func (p *http01Provider) cleanupTarget(
	domain string,
	token string,
	keyAuth string,
) (uint64, <-chan struct{}, time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started || p.completed {
		return 0, nil, 0, false
	}
	challenge := p.challenge
	if !strings.EqualFold(domain, challenge.domain) ||
		token != challenge.token || keyAuth != challenge.keyAuth {
		return 0, nil, 0, false
	}
	return p.generation, p.doneCh, p.deadlines.shutdown, true
}

func (p *http01Provider) initiateShutdown(generation uint64) {
	p.mu.Lock()
	if p.generation != generation || !p.started || p.stopping {
		p.mu.Unlock()
		return
	}
	p.stopping = true
	listener := p.listener
	connections := make([]net.Conn, 0, len(p.connections))
	for connection := range p.connections {
		connections = append(connections, connection)
	}
	p.mu.Unlock()

	if listener != nil {
		go func() { _ = listener.Close() }()
	}
	for _, connection := range connections {
		go func(connection net.Conn) { _ = connection.Close() }(connection)
	}
	if listener == nil {
		p.completeGeneration(generation)
	}
}

func (p *http01Provider) finishWhenWorkersStop(generation uint64) {
	p.workers.Wait()
	p.completeGeneration(generation)
}

func (p *http01Provider) finishFailedStart(generation uint64) {
	p.completeGeneration(generation)
}

func (p *http01Provider) completeGeneration(generation uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.generation != generation || p.completed {
		return
	}
	p.completed = true
	p.challenge = http01Challenge{}
	p.listener = nil
	p.started = false
	p.stopping = false
	close(p.doneCh)
}

func (p *http01Provider) isStopping() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopping
}

func (p *http01Provider) isStoppingGeneration(generation uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation != generation || p.stopping
}

func (p *http01Provider) reportConnectionError(operation string, _ error) {
	if p.isStopping() {
		return
	}
	p.report(fmt.Errorf("franztls: HTTP-01 %s failed", operation))
}

func (p *http01Provider) report(err error) {
	p.diagnostic(err)
}
