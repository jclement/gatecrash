package server

import (
	"testing"
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

func TestTunnelState_ConnectionState(t *testing.T) {
	tunnel := &TunnelState{ID: "test", Type: "http"}

	// Initially disconnected
	if tunnel.IsConnected() {
		t.Fatal("should be disconnected initially")
	}
	if tunnel.ClientAddr() != "" {
		t.Fatal("client addr should be empty")
	}

	// Connect (using nil conn for test - just testing state management)
	tunnel.SetConnected(nil, "192.168.1.100:54321")

	if !tunnel.IsConnected() {
		t.Fatal("should be connected after SetConnected")
	}
	if tunnel.ClientAddr() != "192.168.1.100:54321" {
		t.Fatalf("wrong client addr: %s", tunnel.ClientAddr())
	}
	if tunnel.ConnectedAt().IsZero() {
		t.Fatal("connected_at should be set")
	}

	// Disconnect
	tunnel.SetDisconnected()

	if tunnel.IsConnected() {
		t.Fatal("should be disconnected after SetDisconnected")
	}
	if tunnel.ClientAddr() != "" {
		t.Fatal("client addr should be empty after disconnect")
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
