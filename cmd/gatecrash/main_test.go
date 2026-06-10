package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientConfig_MissingDefaultIsOK(t *testing.T) {
	fc, err := loadClientConfig(filepath.Join(t.TempDir(), "nope.toml"), false)
	if err != nil {
		t.Fatalf("missing default path should not error: %v", err)
	}
	if fc.Server != "" || len(fc.Targets) != 0 {
		t.Fatalf("expected empty config, got %+v", fc)
	}
}

func TestLoadClientConfig_MissingExplicitIsError(t *testing.T) {
	if _, err := loadClientConfig(filepath.Join(t.TempDir(), "nope.toml"), true); err == nil {
		t.Fatal("explicit missing config should error")
	}
}

func TestLoadClientConfig_Parses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	os.WriteFile(path, []byte(`
server   = "tunnel.example.com:2222"
token    = "web:abc123"
host_key = "SHA256:xyz"
count    = 3
debug    = true
targets  = ["127.0.0.1:8000", "api.example.com=127.0.0.1:9000"]
`), 0o600)

	fc, err := loadClientConfig(path, true)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if fc.Server != "tunnel.example.com:2222" || fc.Token != "web:abc123" || fc.HostKey != "SHA256:xyz" {
		t.Fatalf("scalar fields wrong: %+v", fc)
	}
	if fc.Count != 3 || !fc.Debug {
		t.Fatalf("count/debug wrong: %+v", fc)
	}
	if len(fc.Targets) != 2 || fc.Targets[0] != "127.0.0.1:8000" {
		t.Fatalf("targets wrong: %+v", fc.Targets)
	}
}

func TestResolvePrecedence(t *testing.T) {
	t.Setenv("GATECRASH_TEST_X", "from-env")

	// Explicit flag wins over everything.
	if got := resolveStr(true, "from-flag", "GATECRASH_TEST_X", "from-file", "def"); got != "from-flag" {
		t.Fatalf("flag should win, got %q", got)
	}
	// Env beats file and default when flag not set.
	if got := resolveStr(false, "", "GATECRASH_TEST_X", "from-file", "def"); got != "from-env" {
		t.Fatalf("env should win, got %q", got)
	}
	// File beats default when neither flag nor env set.
	if got := resolveStr(false, "", "GATECRASH_TEST_UNSET", "from-file", "def"); got != "from-file" {
		t.Fatalf("file should win, got %q", got)
	}
	// Default when nothing else.
	if got := resolveStr(false, "", "GATECRASH_TEST_UNSET", "", "def"); got != "def" {
		t.Fatalf("default should win, got %q", got)
	}

	// Int precedence.
	if got := resolveInt(true, 5, "GATECRASH_TEST_UNSET", 2, 1); got != 5 {
		t.Fatalf("int flag should win, got %d", got)
	}
	if got := resolveInt(false, 0, "GATECRASH_TEST_UNSET", 2, 1); got != 2 {
		t.Fatalf("int file should win, got %d", got)
	}
	if got := resolveInt(false, 0, "GATECRASH_TEST_UNSET", 0, 1); got != 1 {
		t.Fatalf("int default should win, got %d", got)
	}
}
