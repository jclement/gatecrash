package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// blockingConn is a controllable ssh.Conn fake. OpenChannel and SendRequest
// block until the test releases them (or forever, simulating a half-open peer).
// Close() releases everything and records that it was called.
type blockingConn struct {
	release chan struct{} // closed to unblock pending calls
	closed  atomic.Bool
	// replyOnRelease controls what SendRequest returns once released.
	replyErr error
}

func newBlockingConn() *blockingConn {
	return &blockingConn{release: make(chan struct{})}
}

func (c *blockingConn) OpenChannel(string, []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	<-c.release
	return nil, nil, net.ErrClosed
}

func (c *blockingConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	<-c.release
	return false, nil, c.replyErr
}

func (c *blockingConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.release)
	}
	return nil
}
func (c *blockingConn) Wait() error           { return nil }
func (c *blockingConn) LocalAddr() net.Addr   { return nil }
func (c *blockingConn) RemoteAddr() net.Addr  { return nil }
func (c *blockingConn) SessionID() []byte     { return nil }
func (c *blockingConn) ClientVersion() []byte { return nil }
func (c *blockingConn) ServerVersion() []byte { return nil }
func (c *blockingConn) User() string          { return "" }

func TestOpenChannelTimeout_ClosesConnOnTimeout(t *testing.T) {
	conn := newBlockingConn()

	start := time.Now()
	_, _, err := openChannelTimeout(conn, "x", nil, 50*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("returned too early: %v", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("returned too late: %v", elapsed)
	}
	// The whole point: timing out must close the conn so the parked OpenChannel
	// goroutine (and any others blocked on this conn) can unwind.
	if !conn.closed.Load() {
		t.Fatal("expected conn.Close() to be called on timeout")
	}
}

func TestPingConn_TimeoutOnHalfOpen(t *testing.T) {
	conn := newBlockingConn() // SendRequest blocks forever
	if pingConn(conn, 50*time.Millisecond) {
		t.Fatal("expected pingConn to report dead on a blocked SendRequest")
	}
	conn.Close() // release the parked goroutine
}

func TestPingConn_AliveOnReply(t *testing.T) {
	conn := newBlockingConn()
	close(conn.release) // SendRequest returns immediately with nil error → alive
	if !pingConn(conn, time.Second) {
		t.Fatal("expected pingConn to report alive when the peer replies")
	}
}

func TestKeepaliveLoop_EvictsAndClosesDeadConn(t *testing.T) {
	tunnel := &TunnelState{ID: "t1"}
	conn := newBlockingConn() // never replies → keepalive will time out

	s := &Server{}
	tunnel.AddClient(conn, "test")
	if tunnel.ClientCount() != 1 {
		t.Fatalf("setup: expected 1 client, got %d", tunnel.ClientCount())
	}

	done := make(chan struct{})
	go func() {
		s.keepaliveLoopParams(conn, tunnel, "t1", make(chan struct{}), 10*time.Millisecond, 20*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keepaliveLoop did not evict dead conn in time")
	}

	if tunnel.ClientCount() != 0 {
		t.Fatalf("expected dead conn evicted, still have %d clients", tunnel.ClientCount())
	}
	if !conn.closed.Load() {
		t.Fatal("expected dead conn to be closed")
	}
}
