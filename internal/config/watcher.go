package config

import (
	"log/slog"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher watches a config file for changes and sends validated configs on a channel.
type Watcher struct {
	path     string
	onChange chan *Config
	onError  chan error
	stop     chan struct{}
	once     sync.Once
}

// NewWatcher creates a new config file watcher.
func NewWatcher(path string) *Watcher {
	return &Watcher{
		path:     path,
		onChange: make(chan *Config, 1),
		onError:  make(chan error, 1),
		stop:     make(chan struct{}),
	}
}

// OnChange returns a channel that receives new valid configs.
func (w *Watcher) OnChange() <-chan *Config {
	return w.onChange
}

// OnError returns a channel that receives config parse errors.
func (w *Watcher) OnError() <-chan error {
	return w.onError
}

// Start begins watching the config file. Must be called in a goroutine.
func (w *Watcher) Start() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("failed to create file watcher", "error", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(w.path); err != nil {
		slog.Error("failed to watch config file", "path", w.path, "error", err)
		return
	}

	slog.Info("watching config file", "path", w.path)

	var debounce *time.Timer

	for {
		select {
		case <-w.stop:
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				// Debounce: wait 100ms for writes to settle
				if debounce != nil {
					debounce.Stop()
				}
				debounce = time.AfterFunc(100*time.Millisecond, func() {
					w.reload()
				})
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Error("file watcher error", "error", err)
		}
	}
}

func (w *Watcher) reload() {
	cfg, err := Load(w.path)
	if err != nil {
		slog.Error("config reload failed (keeping old config)", "error", err)
		// Non-blocking send
		select {
		case w.onError <- err:
		default:
		}
		return
	}

	slog.Info("configuration reloaded", "path", w.path)
	select {
	case w.onChange <- cfg:
	default:
	}
}

// Stop stops watching.
func (w *Watcher) Stop() {
	w.once.Do(func() {
		close(w.stop)
	})
}
