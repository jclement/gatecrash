package server

import (
	"io"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// fakeChannel is a no-op gossh.Channel for exercising pool mechanics.
type fakeChannel struct{ closed bool }

func (f *fakeChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (f *fakeChannel) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeChannel) Close() error                { f.closed = true; return nil }
func (f *fakeChannel) CloseWrite() error           { return nil }
func (f *fakeChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (f *fakeChannel) Stderr() io.ReadWriter { return nil }

// TestWarmPool_EmptyForOlderClientsIsTheLegacyPath is the backwards-compatibility
// guarantee in the old-client/new-server direction. A client too old to offer
// pre-opened channels never fills the pool, so every request must find it empty
// and fall through to opening a channel on demand — which is exactly what a nil
// return from takeWarmChannel makes proxyHTTP do.
func TestWarmPool_EmptyForOlderClientsIsTheLegacyPath(t *testing.T) {
	tunnel := &TunnelState{ID: "t1"}
	tunnel.AddClient(fakeConn(1), "10.0.0.1:1")

	_, state, release := tunnel.AcquireConnState()
	defer release()

	for i := range 5 {
		if ch := takeWarmChannel(state); ch != nil {
			t.Fatalf("take %d returned a channel for a client that never offered one", i)
		}
	}
}

// TestWarmPool_OfferThenTake covers the normal lease cycle.
func TestWarmPool_OfferThenTake(t *testing.T) {
	tunnel := &TunnelState{ID: "t1"}
	conn := fakeConn(1)
	tunnel.AddClient(conn, "10.0.0.1:1")

	ch := &fakeChannel{}
	if !tunnel.OfferWarmChannel(conn, ch) {
		t.Fatal("offer rejected on an empty pool")
	}

	_, state, release := tunnel.AcquireConnState()
	defer release()

	got := takeWarmChannel(state)
	if got != gossh.Channel(ch) {
		t.Fatalf("take returned %v, want the parked channel", got)
	}
	// A leased channel must not be handed out twice.
	if again := takeWarmChannel(state); again != nil {
		t.Fatal("the same warm channel was leased twice")
	}
}

// TestWarmPool_RejectsOfferForUnknownConnection guards the startup race: the
// server registers a connection on the control channel, which the client's first
// warm opens can beat. The offer must be refused (so the caller closes the
// channel) rather than panic or silently drop it.
func TestWarmPool_RejectsOfferForUnknownConnection(t *testing.T) {
	tunnel := &TunnelState{ID: "t1"}
	if tunnel.OfferWarmChannel(fakeConn(99), &fakeChannel{}) {
		t.Fatal("offer accepted for a connection that is not registered")
	}
}

// TestWarmPool_BoundedCapacity ensures a client cannot make the server hold an
// unbounded number of parked channels.
func TestWarmPool_BoundedCapacity(t *testing.T) {
	tunnel := &TunnelState{ID: "t1"}
	conn := fakeConn(1)
	tunnel.AddClient(conn, "10.0.0.1:1")

	for i := range warmPoolCapacity {
		if !tunnel.OfferWarmChannel(conn, &fakeChannel{}) {
			t.Fatalf("offer %d rejected below capacity %d", i, warmPoolCapacity)
		}
	}
	if tunnel.OfferWarmChannel(conn, &fakeChannel{}) {
		t.Fatalf("offer accepted beyond capacity %d", warmPoolCapacity)
	}
}

// TestWarmPool_RemoveClientClosesParkedChannels stops parked channels leaking
// when a connection goes away: each one has a client goroutine blocked on it, and
// closing is what releases them.
func TestWarmPool_RemoveClientClosesParkedChannels(t *testing.T) {
	tunnel := &TunnelState{ID: "t1"}
	conn := fakeConn(1)
	tunnel.AddClient(conn, "10.0.0.1:1")

	parked := []*fakeChannel{{}, {}, {}}
	for _, ch := range parked {
		if !tunnel.OfferWarmChannel(conn, ch) {
			t.Fatal("offer rejected")
		}
	}

	tunnel.RemoveClient(conn)

	for i, ch := range parked {
		if !ch.closed {
			t.Fatalf("parked channel %d was not closed when its connection was removed", i)
		}
	}
}
