package client

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// sshPair brings up a real SSH connection over loopback TCP and returns the
// server side plus a connected *gossh.Client. Using a genuine connection rather
// than a stub is the point: the warm-channel design turns on real channel-open
// semantics (who opens, how an unknown type is rejected), which a fake would let
// us assert incorrectly.
func sshPair(t *testing.T) (*gossh.ServerConn, <-chan gossh.NewChannel, *gossh.Client) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	srvCfg := &gossh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	type accepted struct {
		conn  *gossh.ServerConn
		chans <-chan gossh.NewChannel
		err   error
	}
	accCh := make(chan accepted, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			accCh <- accepted{err: err}
			return
		}
		sc, chans, reqs, err := gossh.NewServerConn(nc, srvCfg)
		if err != nil {
			accCh <- accepted{err: err}
			return
		}
		go gossh.DiscardRequests(reqs)
		accCh <- accepted{conn: sc, chans: chans}
	}()

	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cc, chans, reqs, err := gossh.NewClientConn(nc, ln.Addr().String(), &gossh.ClientConfig{
		User:            "test",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	client := gossh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { client.Close() })

	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("server handshake: %v", acc.err)
	}
	t.Cleanup(func() { acc.conn.Close() })

	return acc.conn, acc.chans, client
}

// TestWarmPool_ServesRequestWithoutChannelOpen is the whole point of the feature:
// the request travels on a channel that was already open and confirmed, so it
// never pays the CHANNEL_OPEN round trip.
func TestWarmPool_ServesRequestWithoutChannelOpen(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Path", r.URL.Path)
		w.Write([]byte("from backend"))
	}))
	defer backend.Close()

	host, port := splitHostPort(t, backend.Listener.Addr().String())
	c := New(Config{TargetHost: host, TargetPort: port}, "test")

	_, serverChans, client := sshPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connDone := make(chan struct{})
	go c.maintainWarmPool(ctx, client, connDone)

	// The server side: accept the first pre-opened channel the client offers.
	var ch gossh.Channel
	select {
	case newCh := <-serverChans:
		if newCh.ChannelType() != protocol.ChannelHTTPWarm {
			t.Fatalf("expected a %s channel, got %s", protocol.ChannelHTTPWarm, newCh.ChannelType())
		}
		var reqs <-chan *gossh.Request
		var err error
		ch, reqs, err = newCh.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		go gossh.DiscardRequests(reqs)
	case <-time.After(5 * time.Second):
		t.Fatal("client never offered a pre-opened channel")
	}
	defer ch.Close()

	// Lease it: metadata prelude, then the HTTP request, exactly as proxyHTTP does.
	data := &protocol.HTTPChannelData{
		RequestID:  "req-1",
		Method:     "GET",
		URI:        "/hello",
		Host:       "example.test",
		RemoteAddr: "203.0.113.7",
	}
	if err := protocol.WriteHTTPPrelude(ch, data); err != nil {
		t.Fatalf("write prelude: %v", err)
	}
	req, _ := http.NewRequest("GET", "http://example.test/hello", nil)
	if err := req.Write(ch); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if cw, ok := ch.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}

	resp, err := http.ReadResponse(bufio.NewReader(ch), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Saw-Path"); got != "/hello" {
		t.Fatalf("backend saw path %q, want /hello", got)
	}
	body := make([]byte, 32)
	n, _ := resp.Body.Read(body)
	if got := string(body[:n]); !strings.Contains(got, "from backend") {
		t.Fatalf("body = %q", got)
	}
}

// TestWarmPool_GivesUpAgainstOlderServer is the backwards-compatibility guarantee
// in the new-client/old-server direction: a server that does not know the channel
// type rejects it, and the client must treat that as normal negotiation — stop
// offering, keep the connection, and let every request use the on-demand path.
func TestWarmPool_GivesUpAgainstOlderServer(t *testing.T) {
	_, serverChans, client := sshPair(t)

	// Stand in for an older server: reject anything it does not recognise,
	// which is what both gliderlabs' "default" handler and x/crypto do.
	rejected := make(chan string, warmPoolSize+4)
	go func() {
		for newCh := range serverChans {
			rejected <- newCh.ChannelType()
			newCh.Reject(gossh.UnknownChannelType, "unsupported channel type")
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connDone := make(chan struct{})

	done := make(chan struct{})
	go func() {
		c := New(Config{}, "test")
		c.maintainWarmPool(ctx, client, connDone)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("client kept trying to open pre-opened channels against a server that rejects them")
	}

	if len(rejected) == 0 {
		t.Fatal("client never attempted a warm channel")
	}
	// It must give up, not hammer: a handful of attempts at most, never a spin.
	if n := len(rejected); n > warmPoolSize {
		t.Fatalf("client made %d attempts after rejection; expected it to stop", n)
	}

	// Crucially, the rejection must not have harmed the connection: the legacy
	// path still has to work over it.
	if _, _, err := client.OpenChannel("gatecrash-http", nil); err == nil {
		t.Log("legacy channel accepted")
	} else if !strings.Contains(err.Error(), "unsupported") && !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("connection was damaged by the rejection: %v", err)
	}
}

// TestWarmPool_StopsWhenConnectionCloses ensures the pool does not keep opening
// channels after the connection is gone.
func TestWarmPool_StopsWhenConnectionCloses(t *testing.T) {
	_, serverChans, client := sshPair(t)
	go func() {
		for newCh := range serverChans {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			go gossh.DiscardRequests(reqs)
			_ = ch
		}
	}()

	ctx := context.Background()
	connDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		c := New(Config{}, "test")
		c.maintainWarmPool(ctx, client, connDone)
		close(done)
	}()

	time.Sleep(200 * time.Millisecond)
	client.Close()
	close(connDone)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("warm pool kept running after the connection closed")
	}
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	var port int
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	return host, port
}
