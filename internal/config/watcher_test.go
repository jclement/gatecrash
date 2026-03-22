package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcher_OnChangeAndOnError(t *testing.T) {
	// Create a temporary config file
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")

	cfg, err := GenerateNew()
	if err != nil {
		t.Fatalf("GenerateNew: %v", err)
	}
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	w := NewWatcher(path)
	go w.Start()
	defer w.Stop()

	// Give the watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Modify the file (valid config)
	cfg.Server.SSHPort = 9999
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Wait for change notification
	select {
	case newCfg := <-w.OnChange():
		if newCfg.Server.SSHPort != 9999 {
			t.Fatalf("expected SSHPort 9999, got %d", newCfg.Server.SSHPort)
		}
	case err := <-w.OnError():
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for config change")
	}
}

func TestWatcher_InvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")

	cfg, _ := GenerateNew()
	cfg.Save(path)

	w := NewWatcher(path)
	go w.Start()
	defer w.Stop()

	time.Sleep(100 * time.Millisecond)

	// Write invalid TOML
	os.WriteFile(path, []byte("invalid [[[toml"), 0o644)

	select {
	case <-w.OnError():
		// Expected
	case <-w.OnChange():
		t.Fatal("should not get valid config for invalid TOML")
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for error")
	}
}

func TestWatcher_StopIdempotent(t *testing.T) {
	w := NewWatcher("/nonexistent/path")
	w.Stop()
	w.Stop() // Should not panic
}

func TestWatcher_Channels(t *testing.T) {
	w := NewWatcher("/some/path")
	if w.OnChange() == nil {
		t.Fatal("OnChange channel should not be nil")
	}
	if w.OnError() == nil {
		t.Fatal("OnError channel should not be nil")
	}
}
