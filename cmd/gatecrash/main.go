package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/charmbracelet/log"
	"golang.org/x/term"

	"github.com/jclement/gatecrash/internal/client"
	"github.com/jclement/gatecrash/internal/config"
	"github.com/jclement/gatecrash/internal/server"
	"github.com/jclement/gatecrash/internal/update"
)

var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "make-config":
		runMakeConfig(os.Args[2:])
	case "update":
		runUpdate(os.Args[2:])
	case "version":
		fmt.Printf("gatecrash %s\n", Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "gatecrash %s — self-hosted tunnel server\n\n", Version)
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  gatecrash server      [flags]   Start the tunnel server\n")
	fmt.Fprintf(os.Stderr, "  gatecrash client      [flags]   Connect a tunnel client\n")
	fmt.Fprintf(os.Stderr, "  gatecrash make-config [flags]   Generate a config file\n")
	fmt.Fprintf(os.Stderr, "  gatecrash update      [flags]   Self-update to latest release\n")
	fmt.Fprintf(os.Stderr, "  gatecrash version               Print version\n")
	fmt.Fprintf(os.Stderr, "  gatecrash help                  Show this help\n")
	fmt.Fprintf(os.Stderr, "\nRun 'gatecrash <command> --help' for command-specific flags.\n")
}

func setupLogging(debug bool) {
	var level slog.Level
	if debug {
		level = slog.LevelDebug
	} else {
		level = slog.LevelInfo
	}

	var handler slog.Handler
	if term.IsTerminal(int(os.Stdout.Fd())) {
		opts := log.Options{
			Level:           log.Level(level),
			ReportTimestamp: true,
		}
		handler = log.NewWithOptions(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	slog.SetDefault(slog.New(handler))
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", envOrDefault("GATECRASH_CONFIG", "/etc/gatecrash/gatecrash.toml"), "path to config file")
	debug := fs.Bool("debug", Version == "dev", "enable debug logging")
	fs.Parse(args)

	setupLogging(*debug)
	slog.Info("gatecrash server starting", "version", Version)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Check for updates in background
	if cfg.Update.Enabled {
		go update.LogIfUpdateAvailable(cfg.Update.GitHubRepo, Version)
	}

	srv := server.New(cfg, *configPath, Version)
	if err := srv.Run(context.Background()); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func runMakeConfig(args []string) {
	fs := flag.NewFlagSet("make-config", flag.ExitOnError)
	output := fs.String("output", "/etc/gatecrash/gatecrash.toml", "output config file path")
	adminHost := fs.String("admin-host", "", "admin panel hostname (enables web admin)")
	acmeEmail := fs.String("acme-email", "", "ACME/Let's Encrypt email for certificate notices")
	force := fs.Bool("force", false, "overwrite existing config file")
	fs.Parse(args)

	// Check if file already exists
	if !*force {
		if _, err := os.Stat(*output); err == nil {
			fmt.Fprintf(os.Stderr, "Config file already exists: %s\nUse --force to overwrite.\n", *output)
			os.Exit(1)
		}
	}

	cfg, err := config.GenerateNew()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate config: %v\n", err)
		os.Exit(1)
	}

	if *adminHost != "" {
		cfg.Server.AdminHost = *adminHost
	}
	if *acmeEmail != "" {
		cfg.TLS.ACMEEmail = *acmeEmail
	}

	// Resolve cert_dir relative to output path
	if !filepath.IsAbs(cfg.TLS.CertDir) {
		cfg.TLS.CertDir = filepath.Join(filepath.Dir(*output), cfg.TLS.CertDir)
	}

	if err := cfg.Save(*output); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Config written to %s\n", *output)
	fmt.Printf("  SSH port: %d\n", cfg.Server.SSHPort)
	if cfg.Server.AdminHost != "" {
		fmt.Printf("  Admin:    https://%s\n", cfg.Server.AdminHost)
	} else {
		fmt.Printf("  Admin:    disabled (set --admin-host to enable)\n")
	}
}

// tunnelFlag is a repeatable --tunnel flag value.
type tunnelFlag []string

func (f *tunnelFlag) String() string { return strings.Join(*f, ", ") }
func (f *tunnelFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	serverAddr := fs.String("server", envOrDefault("GATECRASH_SERVER", ""), "server SSH address (host:port)")
	token := fs.String("token", envOrDefault("GATECRASH_TOKEN", ""), "tunnel token (tunnel_id:secret)")
	target := fs.String("target", envOrDefault("GATECRASH_TARGET", ""), "target service address ([https://|https+insecure://]host:port)")
	hostKey := fs.String("host-key", envOrDefault("GATECRASH_HOST_KEY", ""), "server SSH host key fingerprint (SHA256:...)")
	debug := fs.Bool("debug", Version == "dev", "enable debug logging")
	var tunnels tunnelFlag
	fs.Var(&tunnels, "tunnel", "tunnel spec: server=HOST:PORT,token=ID:SECRET,target=[scheme://]HOST:PORT[,host-key=SHA256:...] (may be repeated for multiple tunnels)")
	fs.Parse(args)

	setupLogging(*debug)

	// Collect all tunnel configs.
	var configs []client.Config

	// Legacy single-tunnel flags (--server / --token / --target).
	if *serverAddr != "" || *token != "" || *target != "" {
		if *serverAddr == "" || *token == "" || *target == "" {
			fmt.Fprintf(os.Stderr, "gatecrash client %s\n\n", Version)
			fmt.Fprintf(os.Stderr, "Usage: gatecrash client --server HOST:PORT --token TOKEN --target [SCHEME://]HOST:PORT\n\n")
			fmt.Fprintf(os.Stderr, "       gatecrash client --tunnel server=HOST:PORT,token=ID:SECRET,target=[SCHEME://]HOST:PORT [--tunnel ...]\n\n")
			fmt.Fprintf(os.Stderr, "Flags:\n")
			fs.PrintDefaults()
			fmt.Fprintf(os.Stderr, "\nEnvironment variables:\n")
			fmt.Fprintf(os.Stderr, "  GATECRASH_SERVER    Server SSH address\n")
			fmt.Fprintf(os.Stderr, "  GATECRASH_TOKEN     Tunnel token\n")
			fmt.Fprintf(os.Stderr, "  GATECRASH_TARGET    Target service address\n")
			fmt.Fprintf(os.Stderr, "  GATECRASH_HOST_KEY  Server SSH host key fingerprint\n")
			os.Exit(1)
		}
		targetHost, targetPort, targetTLS, err := parseTarget(*target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid target address %q: %v\n", *target, err)
			os.Exit(1)
		}
		configs = append(configs, client.Config{
			ServerAddr: *serverAddr,
			Token:      *token,
			TargetHost: targetHost,
			TargetPort: targetPort,
			HostKey:    *hostKey,
			TargetTLS:  targetTLS,
		})
	}

	// --tunnel flags.
	for _, spec := range tunnels {
		cfg, err := parseTunnelSpec(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --tunnel %q: %v\n", spec, err)
			os.Exit(1)
		}
		configs = append(configs, cfg)
	}

	if len(configs) == 0 {
		fmt.Fprintf(os.Stderr, "gatecrash client %s\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage: gatecrash client --server HOST:PORT --token TOKEN --target [SCHEME://]HOST:PORT\n\n")
		fmt.Fprintf(os.Stderr, "       gatecrash client --tunnel server=HOST:PORT,token=ID:SECRET,target=[SCHEME://]HOST:PORT [--tunnel ...]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment variables:\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_SERVER    Server SSH address\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_TOKEN     Tunnel token\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_TARGET    Target service address\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_HOST_KEY  Server SSH host key fingerprint\n")
		os.Exit(1)
	}

	slog.Info("gatecrash client starting", "version", Version, "tunnels", len(configs))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		slog.Info("shutting down")
		cancel()
	}()

	if len(configs) == 1 {
		c := client.New(configs[0], Version)
		if err := c.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("client error", "error", err)
			os.Exit(1)
		}
		return
	}

	// Multiple tunnels: run each concurrently; exit when all finish or ctx done.
	var wg sync.WaitGroup
	for _, cfg := range configs {
		wg.Add(1)
		go func(cfg client.Config) {
			defer wg.Done()
			c := client.New(cfg, Version)
			if err := c.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Error("tunnel error", "server", cfg.ServerAddr, "error", err)
			}
		}(cfg)
	}
	wg.Wait()
}

// parseTunnelSpec parses a --tunnel flag value of the form:
//
//	server=HOST:PORT,token=ID:SECRET,target=[scheme://]HOST:PORT[,host-key=SHA256:...]
func parseTunnelSpec(spec string) (client.Config, error) {
	parts := strings.Split(spec, ",")
	kv := make(map[string]string, len(parts))
	for _, p := range parts {
		idx := strings.IndexByte(p, '=')
		if idx < 0 {
			return client.Config{}, fmt.Errorf("expected key=value, got %q", p)
		}
		kv[strings.TrimSpace(p[:idx])] = strings.TrimSpace(p[idx+1:])
	}

	server, ok := kv["server"]
	if !ok || server == "" {
		return client.Config{}, fmt.Errorf("missing server")
	}
	tok, ok := kv["token"]
	if !ok || tok == "" {
		return client.Config{}, fmt.Errorf("missing token")
	}
	tgt, ok := kv["target"]
	if !ok || tgt == "" {
		return client.Config{}, fmt.Errorf("missing target")
	}

	targetHost, targetPort, targetTLS, err := parseTarget(tgt)
	if err != nil {
		return client.Config{}, fmt.Errorf("invalid target %q: %w", tgt, err)
	}

	return client.Config{
		ServerAddr: server,
		Token:      tok,
		TargetHost: targetHost,
		TargetPort: targetPort,
		HostKey:    kv["host-key"],
		TargetTLS:  targetTLS,
	}, nil
}

func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	fs.Parse(args)

	setupLogging(false)

	if update.IsDocker() {
		fmt.Fprintf(os.Stderr, "Self-update is not supported in Docker containers.\nUpdate your image instead.\n")
		os.Exit(1)
	}

	repo := "jclement/gatecrash"
	slog.Info("checking for updates", "current", Version)

	result, err := update.Check(repo, Version)
	if err != nil {
		slog.Error("update check failed", "error", err)
		os.Exit(1)
	}

	if !result.UpdateAvailable {
		fmt.Printf("Already up to date (v%s).\n", result.CurrentVersion)
		return
	}

	fmt.Printf("Update available: v%s → v%s\n", result.CurrentVersion, result.LatestVersion)

	if result.DownloadURL == "" {
		fmt.Fprintf(os.Stderr, "No binary available for your platform (%s_%s).\nDownload manually from https://github.com/%s/releases\n", runtime.GOOS, runtime.GOARCH, repo)
		os.Exit(1)
	}

	if !*yes {
		fmt.Print("Download and install? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" && answer != "yes" {
			fmt.Println("Cancelled.")
			return
		}
	}

	if err := update.SelfUpdate(result.DownloadURL); err != nil {
		slog.Error("update failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Updated to v%s. Restart gatecrash to use the new version.\n", result.LatestVersion)
}

func parseTarget(addr string) (host string, port int, tlsMode string, err error) {
	// Strip scheme prefix
	switch {
	case strings.HasPrefix(addr, "https+insecure://"):
		addr = strings.TrimPrefix(addr, "https+insecure://")
		tlsMode = "tls-insecure"
	case strings.HasPrefix(addr, "https://"):
		addr = strings.TrimPrefix(addr, "https://")
		tlsMode = "tls"
	case strings.HasPrefix(addr, "http://"):
		addr = strings.TrimPrefix(addr, "http://")
	}

	// Parse host:port
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host = addr[:i]
			port, err = strconv.Atoi(addr[i+1:])
			if err != nil {
				return "", 0, "", fmt.Errorf("invalid port: %w", err)
			}
			return host, port, tlsMode, nil
		}
	}
	return "", 0, "", fmt.Errorf("expected [scheme://]host:port format")
}
