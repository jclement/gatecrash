package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// RouteTarget defines a backend target for routing.
type RouteTarget struct {
	Host string
	Port int
	TLS  string // "", "tls", or "tls-insecure"
}

// Config holds the client configuration.
type Config struct {
	ServerAddr string                 // host:port of the SSH server
	Token      string                 // tunnel token (tunnel_id:secret)
	TargetHost string                 // default target service host
	TargetPort int                    // default target service port
	HostKey    string                 // optional SSH host key fingerprint (SHA256:...)
	TargetTLS  string                 // "", "tls", or "tls-insecure"
	Routes     map[string]RouteTarget // hostname or "tcp" → target
}

// responseHeaderTimeout bounds how long the local backend may take to produce
// response headers before the request is failed as a 502. Generous enough not to
// trip a slow first byte on a cold-start or a heavy query, short enough that a
// wedged backend does not accumulate stuck goroutines and SSH channels.
const responseHeaderTimeout = 60 * time.Second

// maxIdleConnsPerBackend caps idle keep-alive connections held open to the local
// backend. Sized for a page load's worth of concurrent asset requests rather
// than Go's default of 2, which forces a fresh dial for every request past the
// second whenever a browser opens several at once.
const maxIdleConnsPerBackend = 64

// Client connects to the gatecrash server and handles tunnel requests.
type Client struct {
	cfg        Config
	version    string
	httpClient *http.Client
}

// New creates a new client instance.
func New(cfg Config, version string) *Client {
	c := &Client{cfg: cfg, version: version}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TargetTLS == "tls-insecure" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	// Bound a backend that accepts the connection and then never answers.
	// Without this the forwarding goroutine — and the SSH channel it holds —
	// parks forever, since nothing else in the path has a deadline.
	//
	// This is deliberately ResponseHeaderTimeout rather than http.Client.Timeout:
	// Client.Timeout covers reading the body too, which would sever every
	// long-lived response (Server-Sent Events, streaming downloads, long-poll) at
	// the deadline. ResponseHeaderTimeout stops at the response headers, so a hung
	// backend is caught while a slow or endless *body* is left alone.
	transport.ResponseHeaderTimeout = responseHeaderTimeout

	// Go's default is 2 idle connections per host, so a burst of more than two
	// concurrent requests dials a fresh TCP connection to the backend for each
	// one and discards it afterwards. The backend here is normally on localhost
	// or a Docker bridge, where that churn is cheap but not free, and it leaves
	// TIME_WAIT sockets behind under sustained load.
	transport.MaxIdleConnsPerHost = maxIdleConnsPerBackend

	// Do not let the transport add its own Accept-Encoding. When a visitor sends
	// none (curl, monitors, most API clients), Go would request gzip from the
	// backend and transparently decompress it here — the backend compresses and
	// this process immediately undoes it, for a body that must go up the tunnel
	// uncompressed either way because the visitor never asked for gzip. That is
	// pure wasted CPU on both sides of the loopback, and it also erases the
	// backend's Content-Length (forcing a chunked response through the tunnel).
	//
	// This does not reduce uplink bytes: what the visitor accepts decides what we
	// must send. Visitors that DO send Accept-Encoding are unaffected either way,
	// since that header is forwarded verbatim and Go leaves an explicitly
	// requested encoding alone.
	transport.DisableCompression = true
	c.httpClient = &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return c
}

// Run connects to the server and handles requests. Reconnects on failure.
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		connStart := time.Now()
		err := c.connect(ctx)
		connDuration := time.Since(connStart)

		if ctx.Err() != nil {
			return ctx.Err()
		}

		slog.Warn("connection lost", "error", err, "duration", connDuration.Round(time.Second))

		// Reset backoff if we were connected for a while
		if connDuration > 60*time.Second {
			backoff = time.Second
		}

		slog.Info("reconnecting", "backoff", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}

		// Exponential backoff
		backoff = min(backoff*2, maxBackoff)
	}
}

func (c *Client) connect(ctx context.Context) error {
	slog.Info("connecting", "server", c.cfg.ServerAddr)

	if c.cfg.HostKey == "" {
		return fmt.Errorf("SSH host key fingerprint is required (use --host-key flag)")
	}

	hostKeyCallback, err := makeHostKeyCallback(c.cfg.HostKey)
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}

	sshConfig := &gossh.ClientConfig{
		User: "tunnel",
		Auth: []gossh.AuthMethod{
			gossh.Password(c.cfg.Token),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	// Dial manually so we can enable OS-level TCP keepalives on the underlying
	// socket — this lets the client notice a half-open server connection even if
	// the application keepalive somehow stalls.
	netConn, err := net.DialTimeout("tcp", c.cfg.ServerAddr, sshConfig.Timeout)
	if err != nil {
		return fmt.Errorf("SSH dial: %w", err)
	}
	if tc, ok := netConn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	sshClientConn, chans, reqs, err := gossh.NewClientConn(netConn, c.cfg.ServerAddr, sshConfig)
	if err != nil {
		netConn.Close()
		return fmt.Errorf("SSH handshake: %w", err)
	}
	conn := gossh.NewClient(sshClientConn, chans, reqs)
	defer conn.Close()

	slog.Info("connected", "server", c.cfg.ServerAddr)

	// Open control channel
	controlCh, controlReqs, err := conn.OpenChannel(protocol.ChannelControl, nil)
	if err != nil {
		return fmt.Errorf("control channel: %w", err)
	}
	defer controlCh.Close()
	go gossh.DiscardRequests(controlReqs)

	// Send client info
	hostname, _ := os.Hostname()
	info := protocol.ClientInfo{
		Version:  c.version,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
	}
	infoMsg := protocol.ControlMessage{Type: protocol.ControlClientInfo}
	infoMsg.Data, _ = json.Marshal(info)
	infoBytes, _ := json.Marshal(infoMsg)
	controlCh.Write(infoBytes)

	// Start heartbeat. This probes the server over the SSH connection and tears
	// the connection down (triggering a reconnect) if the link goes half-open.
	go c.heartbeatLoop(ctx, conn)

	// Register channel handlers for each type the server may open
	httpChs := conn.HandleChannelOpen(protocol.ChannelHTTP)
	tcpChs := conn.HandleChannelOpen(protocol.ChannelDirectTCPIP)
	diagChs := conn.HandleChannelOpen(protocol.ChannelDiagnostic)

	// Wait for connection to close
	connDone := make(chan struct{})
	go func() {
		conn.Wait()
		close(connDone)
	}()

	// Pre-open a pool of channels the server can lease per request, so requests
	// skip the channel-open round trip. Started after the handlers above are
	// registered. Harmless against a server that does not support it: the first
	// open is rejected and the pool quietly gives up.
	go c.maintainWarmPool(ctx, conn, connDone)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-connDone:
			return fmt.Errorf("connection closed")
		case newCh, ok := <-httpChs:
			if !ok {
				return fmt.Errorf("HTTP channel closed")
			}
			go c.handleHTTPChannel(newCh)
		case newCh, ok := <-tcpChs:
			if !ok {
				return fmt.Errorf("TCP channel closed")
			}
			go c.handleDirectTCPIP(newCh)
		case newCh, ok := <-diagChs:
			if !ok {
				return fmt.Errorf("diagnostic channel closed")
			}
			go c.handleDiagnosticChannel(newCh)
		}
	}
}

// heartbeatLoop probes the server with an SSH keepalive global request. A reply
// (accepted or rejected) proves the link is two-way alive; a timeout or error
// means the connection is half-open, so we close it to force a reconnect. The
// timeout is required because SendRequest blocks forever on a dead connection.
func (c *Client) heartbeatLoop(ctx context.Context, conn gossh.Conn) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res := make(chan bool, 1)
			go func() {
				_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
				res <- err == nil
			}()
			select {
			case alive := <-res:
				if !alive {
					slog.Warn("server keepalive failed, dropping connection")
					conn.Close()
					return
				}
			case <-time.After(10 * time.Second):
				slog.Warn("server keepalive timed out, dropping connection")
				conn.Close()
				return
			}
		}
	}
}

func (c *Client) targetAddr() string {
	return net.JoinHostPort(c.cfg.TargetHost, fmt.Sprintf("%d", c.cfg.TargetPort))
}

func (c *Client) targetScheme() string {
	if c.cfg.TargetTLS != "" {
		return "https"
	}
	return "http"
}

// resolveTarget returns the target address and scheme for a given hostname.
// Checks routes first, then falls back to the default target.
// The key is the public hostname for HTTP, or "tcp" for TCP tunnels.
func (c *Client) resolveTarget(key string) (addr, scheme, tlsMode string) {
	if rt, ok := c.cfg.Routes[key]; ok {
		addr = net.JoinHostPort(rt.Host, fmt.Sprintf("%d", rt.Port))
		if rt.TLS != "" {
			return addr, "https", rt.TLS
		}
		return addr, "http", ""
	}
	return c.targetAddr(), c.targetScheme(), c.cfg.TargetTLS
}

// makeHostKeyCallback creates a host key callback that verifies the server key
// fingerprint matches the expected SHA256 fingerprint.
func makeHostKeyCallback(fingerprint string) (gossh.HostKeyCallback, error) {
	// Expect format: SHA256:base64digest
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return nil, fmt.Errorf("expected SHA256:... format, got %q", fingerprint)
	}
	expectedDigest := strings.TrimPrefix(fingerprint, "SHA256:")
	// Validate it's valid base64
	if _, err := base64.RawStdEncoding.DecodeString(expectedDigest); err != nil {
		return nil, fmt.Errorf("invalid fingerprint base64: %w", err)
	}

	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		actual := gossh.FingerprintSHA256(key)
		if actual != fingerprint {
			return fmt.Errorf("host key mismatch: got %s, want %s", actual, fingerprint)
		}
		return nil
	}, nil
}
