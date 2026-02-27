package update

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

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

// SelfUpdate downloads the latest release and replaces the current binary.
func SelfUpdate(downloadURL string) error {
	if IsDocker() {
		return fmt.Errorf("self-update is not supported in Docker containers; update your image instead")
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

	// Write to temp file next to the binary
	tmpPath := execPath + ".update"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing update: %w", err)
	}
	f.Close()

	// Replace binary
	if err := os.Rename(tmpPath, execPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replacing binary: %w", err)
	}

	slog.Info("update complete", "path", execPath)
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
