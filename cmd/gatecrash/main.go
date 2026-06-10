package main

import (
	"context"
	"errors"
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

	"github.com/BurntSushi/toml"
	"github.com/charmbracelet/log"
	"golang.org/x/term"

	"github.com/jclement/gatecrash/internal/client"
	"github.com/jclement/gatecrash/internal/update"
)

var Version = "dev"

// defaultClientConfigPath is loaded automatically when present, so a client can
// run as a service from a declarative file instead of a long flag string.
const defaultClientConfigPath = "/etc/gatecrash/client.toml"

// fileConfig mirrors the settings a client.toml may provide. Flags and env vars
// take precedence over the file; the file takes precedence over built-in
// defaults. Targets accept the same "host:port" / "hostname=host:port" forms as
// the --target flag.
type fileConfig struct {
	Server  string   `toml:"server"`
	Token   string   `toml:"token"`
	HostKey string   `toml:"host_key"`
	Count   int      `toml:"count"`
	Debug   bool     `toml:"debug"`
	Targets []string `toml:"targets"`
}

// loadClientConfig reads a client.toml. explicit reports whether --config was
// passed (in which case a missing/unreadable file is a fatal error rather than a
// silently-skipped default).
func loadClientConfig(path string, explicit bool) (fileConfig, error) {
	var fc fileConfig
	if _, err := toml.DecodeFile(path, &fc); err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return fc, nil // default path absent — fine
		}
		return fc, fmt.Errorf("reading config %s: %w", path, err)
	}
	return fc, nil
}

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
	fmt.Fprintf(os.Stderr, "  -c, --config FILE    Load settings from a TOML file (default %s if present)\n", defaultClientConfigPath)
	fmt.Fprintf(os.Stderr, "  --server HOST:PORT   Server SSH address (or GATECRASH_SERVER)\n")
	fmt.Fprintf(os.Stderr, "  --token TOKEN        Tunnel token (or GATECRASH_TOKEN)\n")
	fmt.Fprintf(os.Stderr, "  --target TARGET      Target address (repeatable, or GATECRASH_TARGET)\n")
	fmt.Fprintf(os.Stderr, "  --host-key KEY       Server SSH host key fingerprint (or GATECRASH_HOST_KEY)\n")
	fmt.Fprintf(os.Stderr, "  --count N            Number of tunnel connections (or GATECRASH_COUNT)\n")
	fmt.Fprintf(os.Stderr, "  --debug              Enable debug logging\n")
	fmt.Fprintf(os.Stderr, "\nTargets:\n")
	fmt.Fprintf(os.Stderr, "  --target localhost:8080                  Default target\n")
	fmt.Fprintf(os.Stderr, "  --target git.example.com=forgejo:3000   Route HTTP by hostname\n")
	fmt.Fprintf(os.Stderr, "\n  For HTTP tunnels with multiple hostnames, use multiple --target flags.\n")
	fmt.Fprintf(os.Stderr, "  TCP tunnels use the default target (bare --target host:port).\n")
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

func envBool(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes"
}

// resolveStr applies precedence: explicit flag > env var > config-file value >
// built-in default.
func resolveStr(flagSet bool, flagVal, envKey, fileVal, def string) string {
	if flagSet {
		return flagVal
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	if fileVal != "" {
		return fileVal
	}
	return def
}

func resolveInt(flagSet bool, flagVal int, envKey string, fileVal, def int) int {
	if flagSet {
		return flagVal
	}
	if v := os.Getenv(envKey); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	if fileVal != 0 {
		return fileVal
	}
	return def
}

// targetFlags collects repeatable --target flags.
type targetFlags []string

func (r *targetFlags) String() string { return strings.Join(*r, ", ") }
func (r *targetFlags) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func runClient(args []string) {
	fs := flag.NewFlagSet("gatecrash", flag.ExitOnError)
	// Flags default to empty so we can layer precedence (flag > env > file >
	// built-in default) after parsing; fs.Visit tells us which were set.
	configPath := fs.String("config", "", "path to client.toml (default "+defaultClientConfigPath+" if present)")
	fs.StringVar(configPath, "c", "", "shorthand for --config")
	serverAddr := fs.String("server", "", "server SSH address (host:port)")
	token := fs.String("token", "", "tunnel token (tunnel_id:secret)")
	hostKey := fs.String("host-key", "", "server SSH host key fingerprint (SHA256:...)")
	count := fs.Int("count", 0, "number of tunnel connections for redundancy")
	debug := fs.Bool("debug", false, "enable debug logging")
	var targets targetFlags
	fs.Var(&targets, "target", "target: host:port or hostname=host:port (repeatable)")
	fs.Parse(args)

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// Load the config file: an explicit --config/-c makes a missing file fatal;
	// the default path is loaded only if it exists.
	explicit := set["config"] || set["c"]
	path := *configPath
	if path == "" {
		path = defaultClientConfigPath
	}
	fc, err := loadClientConfig(path, explicit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Resolve each setting by precedence: explicit flag > env var > file > default.
	resolvedServer := resolveStr(set["server"], *serverAddr, "GATECRASH_SERVER", fc.Server, "")
	resolvedToken := resolveStr(set["token"], *token, "GATECRASH_TOKEN", fc.Token, "")
	resolvedHostKey := resolveStr(set["host-key"], *hostKey, "GATECRASH_HOST_KEY", fc.HostKey, "")
	resolvedCount := resolveInt(set["count"], *count, "GATECRASH_COUNT", fc.Count, 1)
	resolvedDebug := *debug || envBool("GATECRASH_DEBUG") || fc.Debug || Version == "dev"

	// Targets: explicit --target wins, else env (comma-separated), else file.
	if len(targets) == 0 {
		if envTarget := os.Getenv("GATECRASH_TARGET"); envTarget != "" {
			for _, t := range strings.Split(envTarget, ",") {
				if t = strings.TrimSpace(t); t != "" {
					targets = append(targets, t)
				}
			}
		} else {
			targets = append(targets, fc.Targets...)
		}
	}

	serverAddr, token, hostKey = &resolvedServer, &resolvedToken, &resolvedHostKey
	count, debug = &resolvedCount, &resolvedDebug

	setupLogging(*debug)

	if *serverAddr == "" || *token == "" || len(targets) == 0 {
		printUsage()
		os.Exit(1)
	}

	if *count < 1 || *count > 10 {
		fmt.Fprintf(os.Stderr, "count must be between 1 and 10\n")
		os.Exit(1)
	}

	// Parse target mappings
	var targetHost string
	var targetPort int
	var targetTLS string
	routeMap := make(map[string]client.RouteTarget)
	for _, r := range targets {
		key, rt, err := parseRoute(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid route %q: %v\n", r, err)
			os.Exit(1)
		}
		if key == "default" {
			// "default=host:port" or bare "host:port" sets the default target
			targetHost = rt.Host
			targetPort = rt.Port
			targetTLS = rt.TLS
		} else {
			routeMap[key] = rt
		}
	}

	slog.Info("gatecrash client starting",
		"version", Version,
		"server", *serverAddr,
		"targets", len(routeMap)+1,
		"count", *count,
	)

	cfg := client.Config{
		ServerAddr: *serverAddr,
		Token:      *token,
		TargetHost: targetHost,
		TargetPort: targetPort,
		HostKey:    *hostKey,
		TargetTLS:  targetTLS,
		Routes:     routeMap,
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

// parseRoute parses a route mapping.
// Formats:
//
//	"host:port"                     → default route (used for TCP and unmatched HTTP)
//	"default=host:port"             → default route (explicit)
//	"hostname=host:port"            → HTTP route by hostname
//	"hostname=[scheme://]host:port" → with TLS scheme
func parseRoute(s string) (key string, rt client.RouteTarget, err error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) == 1 {
		// Bare "host:port" → default
		host, port, tlsMode, err := parseTarget(s)
		if err != nil {
			return "", rt, err
		}
		return "default", client.RouteTarget{Host: host, Port: port, TLS: tlsMode}, nil
	}
	if parts[0] == "" || parts[1] == "" {
		return "", rt, fmt.Errorf("expected [key=]host:port format")
	}
	key = parts[0]
	host, port, tlsMode, err := parseTarget(parts[1])
	if err != nil {
		return "", rt, err
	}
	return key, client.RouteTarget{Host: host, Port: port, TLS: tlsMode}, nil
}
