package update

import (
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
	if IsDocker() {
		// In Docker, SelfUpdate returns early with a Docker-specific error
		// before it reaches URL validation.
		err := SelfUpdate("https://evil.com/malicious", "", "gatecrash")
		if err == nil {
			t.Fatal("expected error in Docker, got nil")
		}
		if !strings.Contains(err.Error(), "Docker") {
			t.Fatalf("unexpected error message: %v", err)
		}
		return
	}

	err := SelfUpdate("https://evil.com/malicious", "", "gatecrash")
	if err == nil {
		t.Fatal("expected error for untrusted URL, got nil")
	}
	if !strings.Contains(err.Error(), "URL validation failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestSelfUpdateInDocker(t *testing.T) {
	if !IsDocker() {
		t.Skip("not running in Docker")
	}
	err := SelfUpdate("https://github.com/jclement/gatecrash/releases/download/v1.0.0/gatecrash_linux_amd64", "", "gatecrash")
	if err == nil {
		t.Fatal("expected error in Docker, got nil")
	}
	if !strings.Contains(err.Error(), "Docker") {
		t.Fatalf("expected Docker error, got: %v", err)
	}
}

func TestValidateDownloadURL_EmptyURL(t *testing.T) {
	err := validateDownloadURL("")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestIsDocker(t *testing.T) {
	// Just verify it doesn't panic and returns a bool
	_ = IsDocker()
}

func TestCheckResult_Fields(t *testing.T) {
	r := &CheckResult{
		CurrentVersion:  "1.0.0",
		LatestVersion:   "1.1.0",
		UpdateAvailable: true,
		DownloadURL:     "https://github.com/example/release",
		ChecksumURL:     "https://github.com/example/checksums",
	}
	if r.CurrentVersion != "1.0.0" {
		t.Fatal("unexpected current version")
	}
	if !r.UpdateAvailable {
		t.Fatal("expected update available")
	}
}
