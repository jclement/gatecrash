package server

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRegistry_RegisterAndLookup(t *testing.T) {
	r := NewRegistry()

	tunnel := &TunnelState{
		ID:         "web-app",
		Type:       "http",
		Hostnames:  []string{"app.example.com", "www.example.com"},
		ListenPort: 0,
	}
	r.Register(tunnel)

	// Find by ID
	found := r.FindByID("web-app")
	if found == nil {
		t.Fatal("should find by ID")
	}
	if found.ID != "web-app" {
		t.Fatalf("wrong ID: %s", found.ID)
	}

	// Find by hostname
	found = r.FindByHostname("app.example.com")
	if found == nil {
		t.Fatal("should find by hostname app.example.com")
	}
	found = r.FindByHostname("www.example.com")
	if found == nil {
		t.Fatal("should find by hostname www.example.com")
	}

	// Not found
	if r.FindByID("nonexistent") != nil {
		t.Fatal("should not find nonexistent ID")
	}
	if r.FindByHostname("other.com") != nil {
		t.Fatal("should not find nonexistent hostname")
	}
}

func TestRegistry_TCPPortLookup(t *testing.T) {
	r := NewRegistry()

	tunnel := &TunnelState{
		ID:         "database",
		Type:       "tcp",
		ListenPort: 13306,
	}
	r.Register(tunnel)

	found := r.FindByPort(13306)
	if found == nil {
		t.Fatal("should find by port")
	}
	if found.ID != "database" {
		t.Fatalf("wrong ID: %s", found.ID)
	}

	if r.FindByPort(99999) != nil {
		t.Fatal("should not find nonexistent port")
	}
}

func TestRegistry_AllTunnels(t *testing.T) {
	r := NewRegistry()

	r.Register(&TunnelState{ID: "a", Type: "http"})
	r.Register(&TunnelState{ID: "b", Type: "tcp"})
	r.Register(&TunnelState{ID: "c", Type: "http"})

	all := r.AllTunnels()
	if len(all) != 3 {
		t.Fatalf("expected 3 tunnels, got %d", len(all))
	}

	ids := map[string]bool{}
	for _, t := range all {
		ids[t.ID] = true
	}
	for _, id := range []string{"a", "b", "c"} {
		if !ids[id] {
			t.Fatalf("missing tunnel %s", id)
		}
	}
}

func TestTunnelState_MultiClient(t *testing.T) {
	tunnel := &TunnelState{ID: "test", Type: "http"}

	// Initially disconnected
	if tunnel.IsConnected() {
		t.Fatal("should be disconnected initially")
	}
	if tunnel.ClientCount() != 0 {
		t.Fatal("client count should be 0")
	}

	var conn1 fakeConn = 1
	var conn2 fakeConn = 2

	// Add first client
	tunnel.AddClient(conn1, "192.168.1.100:54321")

	if !tunnel.IsConnected() {
		t.Fatal("should be connected after AddClient")
	}
	if tunnel.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", tunnel.ClientCount())
	}
	infos := tunnel.ClientInfos()
	if len(infos) != 1 || infos[0].Addr != "192.168.1.100:54321" {
		t.Fatalf("unexpected client infos: %v", infos)
	}
	if infos[0].ConnectedAt.IsZero() {
		t.Fatal("ConnectedAt should be set")
	}

	// Add second client
	tunnel.AddClient(conn2, "10.0.0.1:12345")

	if tunnel.ClientCount() != 2 {
		t.Fatalf("expected 2 clients, got %d", tunnel.ClientCount())
	}

	// PickConn should return one of the two
	picked := tunnel.PickConn()
	if picked == nil {
		t.Fatal("PickConn should not return nil when clients exist")
	}

	// Remove first client — second should still be connected
	tunnel.RemoveClient(conn1)

	if tunnel.ClientCount() != 1 {
		t.Fatalf("expected 1 client after remove, got %d", tunnel.ClientCount())
	}
	if !tunnel.IsConnected() {
		t.Fatal("should still be connected with one client remaining")
	}

	// Remove second client
	tunnel.RemoveClient(conn2)

	if tunnel.IsConnected() {
		t.Fatal("should be disconnected after removing all clients")
	}
	if tunnel.ClientCount() != 0 {
		t.Fatal("client count should be 0")
	}
	if tunnel.PickConn() != nil {
		t.Fatal("PickConn should return nil when no clients")
	}
}

func TestTunnelMetrics_Atomic(t *testing.T) {
	m := &TunnelMetrics{}

	m.BytesIn.Add(100)
	m.BytesIn.Add(200)
	if m.BytesIn.Load() != 300 {
		t.Fatalf("BytesIn: %d", m.BytesIn.Load())
	}

	m.BytesOut.Add(500)
	if m.BytesOut.Load() != 500 {
		t.Fatalf("BytesOut: %d", m.BytesOut.Load())
	}

	m.RequestCount.Add(1)
	m.RequestCount.Add(1)
	if m.RequestCount.Load() != 2 {
		t.Fatalf("RequestCount: %d", m.RequestCount.Load())
	}

	m.ActiveConns.Add(1)
	m.ActiveConns.Add(1)
	m.ActiveConns.Add(-1)
	if m.ActiveConns.Load() != 1 {
		t.Fatalf("ActiveConns: %d", m.ActiveConns.Load())
	}
}

func TestPickConn_Distribution(t *testing.T) {
	tunnel := &TunnelState{ID: "dist", Type: "http"}

	var conn1 fakeConn = 1
	var conn2 fakeConn = 2
	var conn3 fakeConn = 3

	tunnel.AddClient(conn1, "10.0.0.1:1000")
	tunnel.AddClient(conn2, "10.0.0.2:2000")
	tunnel.AddClient(conn3, "10.0.0.3:3000")

	seen := map[fakeConn]bool{}
	for i := 0; i < 100; i++ {
		c := tunnel.PickConn()
		if c == nil {
			t.Fatal("PickConn returned nil with 3 clients")
		}
		seen[c.(fakeConn)] = true
	}

	for _, fc := range []fakeConn{conn1, conn2, conn3} {
		if !seen[fc] {
			t.Fatalf("connection %d was never picked in 100 iterations", fc)
		}
	}
}

func TestPickConn_SingleClient(t *testing.T) {
	tunnel := &TunnelState{ID: "single", Type: "http"}

	var conn fakeConn = 42
	tunnel.AddClient(conn, "10.0.0.1:1111")

	for i := 0; i < 10; i++ {
		picked := tunnel.PickConn()
		if picked == nil {
			t.Fatal("PickConn returned nil with 1 client")
		}
		if picked.(fakeConn) != conn {
			t.Fatalf("expected conn %d, got %d", conn, picked.(fakeConn))
		}
	}
}

func TestPickConn_Empty(t *testing.T) {
	tunnel := &TunnelState{ID: "empty", Type: "http"}

	if tunnel.PickConn() != nil {
		t.Fatal("PickConn should return nil when no clients connected")
	}
}

func TestRemoveClient_Idempotent(t *testing.T) {
	tunnel := &TunnelState{ID: "idem", Type: "http"}

	var conn fakeConn = 7
	tunnel.AddClient(conn, "10.0.0.1:5555")
	tunnel.RemoveClient(conn)

	// Second removal on already-removed conn should not panic
	tunnel.RemoveClient(conn)

	if tunnel.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", tunnel.ClientCount())
	}
}

func TestAddClient_DuplicateConn(t *testing.T) {
	tunnel := &TunnelState{ID: "dup", Type: "http"}

	var conn fakeConn = 5
	tunnel.AddClient(conn, "10.0.0.1:1111")
	tunnel.AddClient(conn, "10.0.0.1:2222") // same conn, different addr

	if tunnel.ClientCount() != 1 {
		t.Fatalf("expected 1 client after duplicate add, got %d", tunnel.ClientCount())
	}

	infos := tunnel.ClientInfos()
	if len(infos) != 1 {
		t.Fatalf("expected 1 client info, got %d", len(infos))
	}
	if infos[0].Addr != "10.0.0.1:2222" {
		t.Fatalf("expected addr to be overwritten to 10.0.0.1:2222, got %s", infos[0].Addr)
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()

	// Pre-register a tunnel so FindByID has something to find
	r.Register(&TunnelState{ID: "concurrent", Type: "http", Hostnames: []string{"c.example.com"}})

	var wg sync.WaitGroup
	deadline := time.Now().Add(100 * time.Millisecond)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				// Register new tunnels
				r.Register(&TunnelState{
					ID:        fmt.Sprintf("goroutine-%d", id),
					Type:      "http",
					Hostnames: []string{fmt.Sprintf("g%d.example.com", id)},
				})

				// Lookups
				r.FindByID("concurrent")
				r.FindByHostname("c.example.com")
				r.AllTunnels()
			}
		}(i)
	}

	wg.Wait()

	// If we got here without panic or race detector failure, the test passes
	if r.FindByID("concurrent") == nil {
		t.Fatal("original tunnel should still exist")
	}
}
