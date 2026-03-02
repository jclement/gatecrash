package update

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// maxBinarySize caps the download size to 256 MiB to prevent disk exhaustion.
const maxBinarySize = 256 << 20

// trustedDownloadHosts lists the GitHub domains allowed for binary downloads.
var trustedDownloadHosts = []string{
	"github.com",
	"objects.githubusercontent.com",
}

// GitHubRelease represents a GitHub release API response.
type GitHubRelease struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset represents a release asset.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckResult contains the result of a version check.
type CheckResult struct {
	CurrentVersion  string
	LatestVersion   string
	UpdateAvailable bool
	DownloadURL     string
	ChecksumURL     string
}

// Check queries GitHub for the latest release and compares with current version.
func Check(repo, currentVersion string) (*CheckResult, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parsing release: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentClean := strings.TrimPrefix(currentVersion, "v")

	result := &CheckResult{
		CurrentVersion:  currentClean,
		LatestVersion:   latestVersion,
		UpdateAvailable: latestVersion != currentClean && currentClean != "dev",
	}

	// Find matching binary asset and checksums file
	assetName := fmt.Sprintf("gatecrash_%s_%s", runtime.GOOS, runtime.GOARCH)
	for _, a := range release.Assets {
		if a.Name == assetName {
			result.DownloadURL = a.BrowserDownloadURL
		}
		if strings.Contains(a.Name, "checksums") {
			result.ChecksumURL = a.BrowserDownloadURL
		}
	}

	return result, nil
}

// validateDownloadURL ensures the download URL is HTTPS and from a trusted GitHub domain.
func validateDownloadURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid download URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("download URL must use HTTPS, got %q", parsed.Scheme)
	}
	host := parsed.Hostname()
	for _, trusted := range trustedDownloadHosts {
		if host == trusted {
			return nil
		}
	}
	return fmt.Errorf("download URL host %q is not a trusted GitHub domain", host)
}

// SelfUpdate downloads the latest release, verifies its checksum, and replaces the current binary.
func SelfUpdate(downloadURL, checksumURL string) error {
	if IsDocker() {
		return fmt.Errorf("self-update is not supported in Docker containers; update your image instead")
	}

	if err := validateDownloadURL(downloadURL); err != nil {
		return fmt.Errorf("download URL validation failed: %w", err)
	}

	slog.Info("downloading update", "url", downloadURL)

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	// Get current binary path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding executable: %w", err)
	}

	// Write to temp file in OS temp directory to avoid permission issues
	// when the binary's directory (e.g. /usr/local/bin) isn't writable.
	f, err := os.CreateTemp("", "gatecrash-update-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := f.Name()

	// Limit download size to prevent disk exhaustion. Read one extra byte beyond
	// the limit; if we receive that extra byte, the response is too large.
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxBinarySize+1))
	if err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing update: %w", err)
	}
	if n > maxBinarySize {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("download exceeded maximum allowed size of %d bytes", maxBinarySize)
	}
	f.Close()

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("setting permissions: %w", err)
	}

	// Verify checksum if available
	if checksumURL != "" {
		if err := validateDownloadURL(checksumURL); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("checksum URL validation failed: %w", err)
		}
		assetName := fmt.Sprintf("gatecrash_%s_%s", runtime.GOOS, runtime.GOARCH)
		if err := verifyChecksum(tmpPath, checksumURL, assetName); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("checksum verification failed: %w", err)
		}
		slog.Info("checksum verified")
	}

	// Replace binary — try atomic rename first, fall back to copy if
	// the temp dir is on a different filesystem (EXDEV).
	if err := replaceBinary(tmpPath, execPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replacing binary: %w", err)
	}

	slog.Info("update complete", "path", execPath)
	return nil
}

// verifyChecksum downloads the checksums file and verifies the downloaded binary matches.
func verifyChecksum(filePath, checksumURL, assetName string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(checksumURL)
	if err != nil {
		return fmt.Errorf("downloading checksums: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksums download returned %d", resp.StatusCode)
	}

	// Parse checksums file: each line is "hash  filename"
	var expectedHash string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[1] == assetName {
			expectedHash = fields[0]
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading checksums: %w", err)
	}
	if expectedHash == "" {
		return fmt.Errorf("no checksum found for %s", assetName)
	}

	// Hash the downloaded file
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("opening file for checksum: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hashing file: %w", err)
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	if actualHash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	return nil
}

// replaceBinary moves src to dst. If os.Rename fails due to a cross-device
// link, it falls back to reading src and overwriting dst in place.
func replaceBinary(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}

	// Check for cross-device link error
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}

	// Fall back: copy src content into dst (overwrite)
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening temp file: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("opening destination: %w", err)
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copying binary: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing destination: %w", err)
	}

	os.Remove(src)
	return nil
}

// IsDocker returns true if running inside a Docker container.
func IsDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

// LogIfUpdateAvailable checks for updates and logs a warning if one is available.
func LogIfUpdateAvailable(repo, currentVersion string) {
	if currentVersion == "dev" {
		return
	}
	if IsDocker() {
		return
	}

	result, err := Check(repo, currentVersion)
	if err != nil {
		slog.Debug("update check failed", "error", err)
		return
	}

	if result.UpdateAvailable {
		slog.Warn("a newer version is available",
			"current", result.CurrentVersion,
			"latest", result.LatestVersion,
		)
	}
}
