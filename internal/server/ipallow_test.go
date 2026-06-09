package server

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestIPAllowStore_GrantIsGrantedRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_allowlist.json")
	store, err := NewIPAllowStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	if store.IsGranted("t1", net.ParseIP("1.2.3.4")) {
		t.Fatal("expected no grant initially")
	}

	if err := store.Grant("t1", "1.2.3.4", "admin", time.Hour); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !store.IsGranted("t1", net.ParseIP("1.2.3.4")) {
		t.Fatal("expected grant after Grant")
	}
	// Grant is scoped per tunnel.
	if store.IsGranted("t2", net.ParseIP("1.2.3.4")) {
		t.Fatal("grant must not leak across tunnels")
	}

	if err := store.Revoke("t1", "1.2.3.4"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if store.IsGranted("t1", net.ParseIP("1.2.3.4")) {
		t.Fatal("expected no grant after Revoke")
	}
}

func TestIPAllowStore_Expiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_allowlist.json")
	store, _ := NewIPAllowStore(path)

	// Already-expired grant.
	if err := store.Grant("t1", "9.9.9.9", "admin", -time.Minute); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if store.IsGranted("t1", net.ParseIP("9.9.9.9")) {
		t.Fatal("expired grant must not be considered granted")
	}
	if len(store.List("t1")) != 0 {
		t.Fatal("expired grant must not appear in List")
	}
}

func TestIPAllowStore_PersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_allowlist.json")
	store, _ := NewIPAllowStore(path)
	if err := store.Grant("t1", "5.6.7.8", "admin", time.Hour); err != nil {
		t.Fatalf("grant: %v", err)
	}

	reopened, err := NewIPAllowStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !reopened.IsGranted("t1", net.ParseIP("5.6.7.8")) {
		t.Fatal("grant should persist across store reload")
	}
}

func TestStaticIPAllowed(t *testing.T) {
	tun := newTunnelState(TunnelSpec{
		ID:       "t1",
		AllowIPs: []string{"203.0.113.5", "10.0.0.0/8", "garbage", "2001:db8::/32"},
	})

	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.5", true},  // exact IP
		{"203.0.113.6", false}, // neighbor not allowed
		{"10.4.5.6", true},     // inside CIDR
		{"11.0.0.1", false},    // outside CIDR
		{"2001:db8::1", true},  // inside v6 CIDR
		{"2001:dba::1", false}, // outside v6 CIDR
	}
	for _, c := range cases {
		got := tun.StaticIPAllowed(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("StaticIPAllowed(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestSafeTunnelReturnURL(t *testing.T) {
	tun := newTunnelState(TunnelSpec{ID: "t1", Hostnames: []string{"app.example.com"}})

	cases := []struct {
		raw  string
		want string
	}{
		{"https://app.example.com/path?q=1", "https://app.example.com/path?q=1"}, // ok
		{"https://evil.com/path", ""},          // wrong host (open redirect)
		{"http://app.example.com/path", ""},    // not https
		{"/relative", ""},                      // not absolute https
		{"", ""},                               // empty
	}
	for _, c := range cases {
		if got := safeTunnelReturnURL(c.raw, tun); got != c.want {
			t.Errorf("safeTunnelReturnURL(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}
