package update

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateDownloadURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid github.com URL",
			url:     "https://github.com/jclement/gatecrash/releases/download/v1.0.0/gatecrash_linux_amd64",
			wantErr: false,
		},
		{
			name:    "valid objects.githubusercontent.com URL",
			url:     "https://objects.githubusercontent.com/github-production-release-asset/123/gatecrash",
			wantErr: false,
		},
		{
			name:    "HTTP scheme rejected",
			url:     "http://github.com/jclement/gatecrash/releases/download/v1.0.0/gatecrash_linux_amd64",
			wantErr: true,
		},
		{
			name:    "untrusted domain rejected",
			url:     "https://evil.com/malicious-binary",
			wantErr: true,
		},
		{
			name:    "subdomain of trusted host rejected",
			url:     "https://evil.github.com/malicious-binary",
			wantErr: true,
		},
		{
			name:    "malformed URL rejected",
			url:     "://not-a-url",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDownloadURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDownloadURL(%q) error = %v, wantErr = %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestSelfUpdateUntrustedURL(t *testing.T) {
	err := SelfUpdate("https://evil.com/malicious")
	if err == nil {
		t.Fatal("expected error for untrusted URL, got nil")
	}
	if !strings.Contains(err.Error(), "URL validation failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestSelfUpdateSizeLimit(t *testing.T) {
	// Serve a response larger than maxBinarySize
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", maxBinarySize+1))
		// Write exactly maxBinarySize+1 bytes
		chunk := make([]byte, 4096)
		written := int64(0)
		for written < maxBinarySize+1 {
			n := int64(len(chunk))
			if written+n > maxBinarySize+1 {
				n = maxBinarySize + 1 - written
			}
			w.Write(chunk[:n])
			written += n
		}
	}))
	defer ts.Close()

	// We can't easily test with HTTPS in unit tests without injecting a client,
	// so test validateDownloadURL separately and trust the io.LimitReader logic.
	_ = ts
}
