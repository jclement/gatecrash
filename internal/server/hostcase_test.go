package server

import "testing"

func TestFindByHostname_CaseInsensitive(t *testing.T) {
	r := NewRegistry()
	r.Register(&TunnelState{ID: "a", Type: "http", Hostnames: []string{"App.Example.COM"}})

	for _, h := range []string{"app.example.com", "APP.EXAMPLE.COM", "App.Example.Com"} {
		if r.FindByHostname(h) == nil {
			t.Errorf("FindByHostname(%q) should match regardless of case", h)
		}
	}
	if r.FindByHostname("other.example.com") != nil {
		t.Error("unrelated hostname must not match")
	}
}
