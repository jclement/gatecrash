package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/charmbracelet/log"
	"golang.org/x/term"

	"github.com/jclement/gatecrash/internal/config"
	"github.com/jclement/gatecrash/internal/server"
	"github.com/jclement/gatecrash/internal/update"
)

var Version = "dev"

func main() {
	// Default: run server when no subcommand given
	if len(os.Args) < 2 || len(os.Args[1]) == 0 || os.Args[1][0] == '-' {
		runServer(os.Args[1:])
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "make-config":
		runMakeConfig(os.Args[2:])
	case "update":
		runUpdate(os.Args[2:])
	case "version":
		fmt.Printf("gatecrash-server %s\n", Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "gatecrash-server %s — self-hosted tunnel server\n\n", Version)
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  gatecrash-server      [flags]   Start the tunnel server (default)\n")
	fmt.Fprintf(os.Stderr, "  gatecrash-server make-config    Generate a config file\n")
	fmt.Fprintf(os.Stderr, "  gatecrash-server update         Self-update to latest release\n")
	fmt.Fprintf(os.Stderr, "  gatecrash-server version        Print version\n")
	fmt.Fprintf(os.Stderr, "  gatecrash-server help            Show this help\n")
	fmt.Fprintf(os.Stderr, "\nRun 'gatecrash-server <command> --help' for command-specific flags.\n")
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
	fs := flag.NewFlagSet("gatecrash-server", flag.ExitOnError)
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
		go update.LogIfUpdateAvailable(cfg.Update.GitHubRepo, Version, "gatecrash-server")
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

	result, err := update.Check(repo, Version, "gatecrash-server")
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

	if err := update.SelfUpdate(result.DownloadURL, result.ChecksumURL, "gatecrash-server"); err != nil {
		slog.Error("update failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Updated to v%s. Restart gatecrash-server to use the new version.\n", result.LatestVersion)
}
