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

func envOrDefaultInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
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

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	serverAddr := fs.String("server", envOrDefault("GATECRASH_SERVER", ""), "server SSH address (host:port)")
	token := fs.String("token", envOrDefault("GATECRASH_TOKEN", ""), "tunnel token (tunnel_id:secret)")
	target := fs.String("target", envOrDefault("GATECRASH_TARGET", ""), "target service address ([https://|https+insecure://]host:port)")
	hostKey := fs.String("host-key", envOrDefault("GATECRASH_HOST_KEY", ""), "server SSH host key fingerprint (SHA256:...)")
	count := fs.Int("count", envOrDefaultInt("GATECRASH_COUNT", 1), "number of tunnel connections for redundancy")
	debug := fs.Bool("debug", Version == "dev", "enable debug logging")
	fs.Parse(args)

	setupLogging(*debug)

	if *serverAddr == "" || *token == "" || *target == "" {
		fmt.Fprintf(os.Stderr, "gatecrash client %s\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage: gatecrash client --server HOST:PORT --token TOKEN --target [SCHEME://]HOST:PORT\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment variables:\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_SERVER    Server SSH address\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_TOKEN     Tunnel token\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_TARGET    Target service address\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_HOST_KEY  Server SSH host key fingerprint\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_COUNT     Number of tunnel connections\n")
		os.Exit(1)
	}

	if *count < 1 || *count > 10 {
		fmt.Fprintf(os.Stderr, "count must be between 1 and 10\n")
		os.Exit(1)
	}

	// Parse target [scheme://]host:port
	targetHost, targetPort, targetTLS, err := parseTarget(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid target address %q: %v\n", *target, err)
		os.Exit(1)
	}

	slog.Info("gatecrash client starting",
		"version", Version,
		"server", *serverAddr,
		"target", *target,
		"count", *count,
	)

	cfg := client.Config{
		ServerAddr: *serverAddr,
		Token:      *token,
		TargetHost: targetHost,
		TargetPort: targetPort,
		HostKey:    *hostKey,
		TargetTLS:  targetTLS,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		slog.Info("shutting down")
		cancel()
	}()

	if *count == 1 {
		c := client.New(cfg, Version)
		if err := c.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("client error", "error", err)
			os.Exit(1)
		}
	} else {
		var wg sync.WaitGroup
		for i := range *count {
			wg.Add(1)
			go func() {
				defer wg.Done()
				slog.Info("starting tunnel instance", "instance", i+1, "of", *count)
				c := client.New(cfg, Version)
				if err := c.Run(ctx); err != nil && ctx.Err() == nil {
					slog.Error("tunnel instance error", "instance", i+1, "error", err)
				}
			}()
		}
		wg.Wait()
	}
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
