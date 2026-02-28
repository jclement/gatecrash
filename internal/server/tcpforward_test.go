package server

import "testing"

func TestParseAddr(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort uint32
	}{
		{"192.168.1.1:8080", "192.168.1.1", 8080},
		{"127.0.0.1:0", "127.0.0.1", 0},
		{"10.0.0.1:65535", "10.0.0.1", 65535},
		{"[::1]:8080", "::1", 8080},
		{"hostname:3000", "hostname", 3000},
		{"just-a-host", "just-a-host", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port := parseAddr(tt.input)
			if host != tt.wantHost {
				t.Fatalf("host: got %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Fatalf("port: got %d, want %d", port, tt.wantPort)
			}
		})
	}
}
