package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strconv"
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
	fmt.Fprintf(os.Stderr, "  gatecrash server  [flags]   Start the tunnel server\n")
	fmt.Fprintf(os.Stderr, "  gatecrash client  [flags]   Connect a tunnel client\n")
	fmt.Fprintf(os.Stderr, "  gatecrash update  [flags]   Self-update to latest release\n")
	fmt.Fprintf(os.Stderr, "  gatecrash version           Print version\n")
	fmt.Fprintf(os.Stderr, "  gatecrash help              Show this help\n")
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
	noWebAdmin := fs.Bool("no-web-admin", os.Getenv("GATECRASH_NO_WEB_ADMIN") != "", "disable web admin panel")
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

	srv := server.New(cfg, *configPath, Version, *noWebAdmin)
	if err := srv.Run(context.Background()); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	serverAddr := fs.String("server", envOrDefault("GATECRASH_SERVER", ""), "server SSH address (host:port)")
	token := fs.String("token", envOrDefault("GATECRASH_TOKEN", ""), "tunnel token (tunnel_id:secret)")
	target := fs.String("target", envOrDefault("GATECRASH_TARGET", ""), "target service address (host:port)")
	hostKey := fs.String("host-key", envOrDefault("GATECRASH_HOST_KEY", ""), "server SSH host key fingerprint (SHA256:...)")
	debug := fs.Bool("debug", Version == "dev", "enable debug logging")
	fs.Parse(args)

	setupLogging(*debug)

	if *serverAddr == "" || *token == "" || *target == "" {
		fmt.Fprintf(os.Stderr, "gatecrash client %s\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage: gatecrash client --server HOST:PORT --token TOKEN --target HOST:PORT\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment variables:\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_SERVER    Server SSH address\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_TOKEN     Tunnel token\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_TARGET    Target service address\n")
		fmt.Fprintf(os.Stderr, "  GATECRASH_HOST_KEY  Server SSH host key fingerprint\n")
		os.Exit(1)
	}

	// Parse target host:port
	targetHost, targetPort, err := parseHostPort(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid target address %q: %v\n", *target, err)
		os.Exit(1)
	}

	slog.Info("gatecrash client starting",
		"version", Version,
		"server", *serverAddr,
		"target", *target,
	)

	cfg := client.Config{
		ServerAddr: *serverAddr,
		Token:      *token,
		TargetHost: targetHost,
		TargetPort: targetPort,
		HostKey:    *hostKey,
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

	c := client.New(cfg, Version)
	if err := c.Run(ctx); err != nil && ctx.Err() == nil {
		slog.Error("client error", "error", err)
		os.Exit(1)
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

func parseHostPort(addr string) (string, int, error) {
	// Try to find the last colon for host:port split
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host := addr[:i]
			port, err := strconv.Atoi(addr[i+1:])
			if err != nil {
				return "", 0, fmt.Errorf("invalid port: %w", err)
			}
			return host, port, nil
		}
	}
	return "", 0, fmt.Errorf("expected host:port format")
}
