package main

import (
	"testing"

	"github.com/jclement/gatecrash/internal/client"
)

func TestParseTunnelSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    client.Config
		wantErr bool
	}{
		{
			name: "basic http",
			spec: "server=host:2222,token=web-app:secret,target=localhost:8080",
			want: client.Config{
				ServerAddr: "host:2222",
				Token:      "web-app:secret",
				TargetHost: "localhost",
				TargetPort: 8080,
				TargetTLS:  "",
			},
		},
		{
			name: "https target",
			spec: "server=host:2222,token=api:secret,target=https://localhost:3000",
			want: client.Config{
				ServerAddr: "host:2222",
				Token:      "api:secret",
				TargetHost: "localhost",
				TargetPort: 3000,
				TargetTLS:  "tls",
			},
		},
		{
			name: "https+insecure target",
			spec: "server=host:2222,token=api:secret,target=https+insecure://localhost:3000",
			want: client.Config{
				ServerAddr: "host:2222",
				Token:      "api:secret",
				TargetHost: "localhost",
				TargetPort: 3000,
				TargetTLS:  "tls-insecure",
			},
		},
		{
			name: "with host-key",
			spec: "server=host:2222,token=web:secret,target=localhost:8080,host-key=SHA256:abc123",
			want: client.Config{
				ServerAddr: "host:2222",
				Token:      "web:secret",
				TargetHost: "localhost",
				TargetPort: 8080,
				HostKey:    "SHA256:abc123",
			},
		},
		{
			name:    "missing server",
			spec:    "token=web:secret,target=localhost:8080",
			wantErr: true,
		},
		{
			name:    "missing token",
			spec:    "server=host:2222,target=localhost:8080",
			wantErr: true,
		},
		{
			name:    "missing target",
			spec:    "server=host:2222,token=web:secret",
			wantErr: true,
		},
		{
			name:    "invalid format",
			spec:    "server",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTunnelSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseTunnelSpec(%q) error = %v, wantErr %v", tt.spec, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.ServerAddr != tt.want.ServerAddr {
				t.Errorf("ServerAddr = %q, want %q", got.ServerAddr, tt.want.ServerAddr)
			}
			if got.Token != tt.want.Token {
				t.Errorf("Token = %q, want %q", got.Token, tt.want.Token)
			}
			if got.TargetHost != tt.want.TargetHost {
				t.Errorf("TargetHost = %q, want %q", got.TargetHost, tt.want.TargetHost)
			}
			if got.TargetPort != tt.want.TargetPort {
				t.Errorf("TargetPort = %d, want %d", got.TargetPort, tt.want.TargetPort)
			}
			if got.TargetTLS != tt.want.TargetTLS {
				t.Errorf("TargetTLS = %q, want %q", got.TargetTLS, tt.want.TargetTLS)
			}
			if got.HostKey != tt.want.HostKey {
				t.Errorf("HostKey = %q, want %q", got.HostKey, tt.want.HostKey)
			}
		})
	}
}
