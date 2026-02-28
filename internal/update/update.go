package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

	// Find matching asset
	assetName := fmt.Sprintf("gatecrash_%s_%s", runtime.GOOS, runtime.GOARCH)
	for _, a := range release.Assets {
		if a.Name == assetName {
			result.DownloadURL = a.BrowserDownloadURL
			break
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

// SelfUpdate downloads the latest release and replaces the current binary.
func SelfUpdate(downloadURL string) error {
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

	// Write to temp file in the OS temp directory to avoid permission issues
	// with the binary's directory (e.g. /usr/local/bin may be read-only).
	tmpFile, err := os.CreateTemp("", "gatecrash-update-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Limit download size to prevent disk exhaustion. Read one extra byte beyond
	// the limit; if we receive that extra byte, the response is too large.
	n, err := io.Copy(tmpFile, io.LimitReader(resp.Body, maxBinarySize+1))
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing update: %w", err)
	}
	if n > maxBinarySize {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("download exceeded maximum allowed size of %d bytes", maxBinarySize)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("setting permissions on temp file: %w", err)
	}

	// Replace binary. Try an atomic rename first; if that fails because the
	// temp dir and the binary dir are on different filesystems (cross-device),
	// fall back to creating a temp file in the binary's directory and renaming.
	if err := replaceExecutable(tmpPath, execPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replacing binary: %w", err)
	}

	slog.Info("update complete", "path", execPath)
	return nil
}

// replaceExecutable replaces dst with the contents of src. It tries an atomic
// rename first. If that fails because src and dst are on different filesystems
// (cross-device link error), it falls back to copying src into a temp file
// inside the same directory as dst and then renaming.
func replaceExecutable(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else {
		var linkErr *os.LinkError
		if !errors.As(err, &linkErr) || !errors.Is(linkErr.Err, syscall.EXDEV) {
			return err
		}
	}
	// Rename failed with a cross-device error. Stage the new binary as a temp
	// file in the same directory as dst so the final rename is on-device.
	dstDir := filepath.Dir(dst)
	staged, err := os.CreateTemp(dstDir, ".gatecrash-update-*")
	if err != nil {
		return err
	}
	stagedPath := staged.Name()

	srcFile, err := os.Open(src)
	if err != nil {
		staged.Close()
		os.Remove(stagedPath)
		return err
	}
	_, err = io.Copy(staged, srcFile)
	srcFile.Close()
	staged.Close()
	if err != nil {
		os.Remove(stagedPath)
		return err
	}
	if err := os.Chmod(stagedPath, 0o755); err != nil {
		os.Remove(stagedPath)
		return err
	}
	if err := os.Rename(stagedPath, dst); err != nil {
		os.Remove(stagedPath)
		return err
	}
	if err := os.Remove(src); err != nil {
		slog.Warn("failed to remove temp file after update", "path", src, "error", err)
	}
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
