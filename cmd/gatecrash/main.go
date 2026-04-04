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
	"strings"
	"sync"
	"syscall"

	"github.com/charmbracelet/log"
	"golang.org/x/term"

	"github.com/jclement/gatecrash/internal/client"
	"github.com/jclement/gatecrash/internal/update"
)

var Version = "dev"

func main() {
	// Check for subcommands first
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "update":
			runUpdate(os.Args[2:])
			return
		case "version":
			fmt.Printf("gatecrash %s\n", Version)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}

	// Default: run client
	runClient(os.Args[1:])
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "gatecrash %s — tunnel client\n\n", Version)
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  gatecrash [flags]    Connect a tunnel to the server\n")
	fmt.Fprintf(os.Stderr, "  gatecrash update     Self-update to latest release\n")
	fmt.Fprintf(os.Stderr, "  gatecrash version    Print version\n")
	fmt.Fprintf(os.Stderr, "  gatecrash help       Show this help\n")
	fmt.Fprintf(os.Stderr, "\nFlags:\n")
	fmt.Fprintf(os.Stderr, "  --server HOST:PORT   Server SSH address (or GATECRASH_SERVER)\n")
	fmt.Fprintf(os.Stderr, "  --token TOKEN        Tunnel token (or GATECRASH_TOKEN)\n")
	fmt.Fprintf(os.Stderr, "  --target ADDR        Target service address (or GATECRASH_TARGET)\n")
	fmt.Fprintf(os.Stderr, "  --host-key KEY       Server SSH host key fingerprint (or GATECRASH_HOST_KEY)\n")
	fmt.Fprintf(os.Stderr, "  --count N            Number of tunnel connections (or GATECRASH_COUNT)\n")
	fmt.Fprintf(os.Stderr, "  --debug              Enable debug logging\n")
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

func runClient(args []string) {
	fs := flag.NewFlagSet("gatecrash", flag.ExitOnError)
	serverAddr := fs.String("server", envOrDefault("GATECRASH_SERVER", ""), "server SSH address (host:port)")
	token := fs.String("token", envOrDefault("GATECRASH_TOKEN", ""), "tunnel token (tunnel_id:secret)")
	target := fs.String("target", envOrDefault("GATECRASH_TARGET", ""), "target service address ([https://|https+insecure://]host:port)")
	hostKey := fs.String("host-key", envOrDefault("GATECRASH_HOST_KEY", ""), "server SSH host key fingerprint (SHA256:...)")
	count := fs.Int("count", envOrDefaultInt("GATECRASH_COUNT", 1), "number of tunnel connections for redundancy")
	debug := fs.Bool("debug", Version == "dev", "enable debug logging")
	fs.Parse(args)

	setupLogging(*debug)

	if *serverAddr == "" || *token == "" || *target == "" {
		printUsage()
		os.Exit(1)
	}

	if *count < 1 || *count > 10 {
		fmt.Fprintf(os.Stderr, "count must be between 1 and 10\n")
		os.Exit(1)
	}

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

	result, err := update.Check(repo, Version, "gatecrash")
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

	if err := update.SelfUpdate(result.DownloadURL, result.ChecksumURL, "gatecrash"); err != nil {
		slog.Error("update failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Updated to v%s. Restart gatecrash to use the new version.\n", result.LatestVersion)
}

func parseTarget(addr string) (host string, port int, tlsMode string, err error) {
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
