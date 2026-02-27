package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// handleHTTPChannel processes an incoming HTTP request from the server.
func (c *Client) handleHTTPChannel(newCh gossh.NewChannel) {
	// Parse channel extra data
	var data struct {
		RequestID    string
		Method       string
		URI          string
		Host         string
		RemoteAddr   string
		TLS          bool
		PreserveHost bool
	}
	if err := gossh.Unmarshal(newCh.ExtraData(), &data); err != nil {
		slog.Error("failed to parse HTTP channel data", "error", err)
		newCh.Reject(gossh.ConnectionFailed, "invalid channel data")
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		slog.Error("failed to accept HTTP channel", "error", err)
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	start := time.Now()

	// Read the HTTP request from the channel
	req, err := http.ReadRequest(bufio.NewReader(ch))
	if err != nil {
		slog.Error("failed to read request from channel", "error", err)
		writeErrorResponse(ch, http.StatusBadGateway, "failed to read request")
		return
	}
	defer req.Body.Close()

	// Inject standard forwarding headers
	// X-Forwarded-For: append client IP
	if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
		req.Header.Set("X-Forwarded-For", prior+", "+data.RemoteAddr)
	} else {
		req.Header.Set("X-Forwarded-For", data.RemoteAddr)
	}

	if data.TLS {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}

	req.Header.Set("X-Forwarded-Host", data.Host)
	req.Header.Set("X-Real-IP", data.RemoteAddr)
	req.Header.Set("X-Request-Id", data.RequestID)

	// Rewrite the request URL to target the local service
	targetURL := fmt.Sprintf("http://%s%s", c.targetAddr(), data.URI)
	req.URL, _ = url.Parse(targetURL)
	req.RequestURI = "" // Must be empty for http.Client

	// Host header handling
	if data.PreserveHost {
		// Keep original Host header from the public request
		req.Host = data.Host
	} else {
		// Rewrite Host to target address (default)
		req.Host = c.targetAddr()
	}

	// Forward to local target
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Error("target request failed",
			"target", c.targetAddr(),
			"method", data.Method,
			"uri", data.URI,
			"error", err,
		)
		writeErrorResponse(ch, http.StatusBadGateway, "target unreachable")
		return
	}
	defer resp.Body.Close()

	// Write response back through the channel
	if err := resp.Write(ch); err != nil {
		slog.Error("failed to write response to channel", "error", err)
		return
	}

	elapsed := time.Since(start)

	// Compute response size from Content-Length or estimate
	respSize := resp.ContentLength
	if respSize < 0 {
		respSize = 0
	}

	slog.Debug("request",
		"method", data.Method,
		"uri", data.URI,
		"host", data.Host,
		"status", resp.StatusCode,
		"size", respSize,
		"duration", elapsed.Round(time.Millisecond),
		"from", data.RemoteAddr,
	)

	// Log at info level with less detail for non-debug
	if slog.Default().Enabled(context.Background(), slog.LevelInfo) && !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		statusStr := fmt.Sprintf("%d", resp.StatusCode)
		if resp.StatusCode >= 400 {
			statusStr = fmt.Sprintf("%d!", resp.StatusCode)
		}
		slog.Info(fmt.Sprintf("%s %s → %s", data.Method, truncateURI(data.URI), statusStr),
			"host", data.Host,
			"ms", elapsed.Milliseconds(),
		)
	}
}

func writeErrorResponse(w io.Writer, status int, msg string) {
	resp := &http.Response{
		StatusCode: status,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(msg)),
	}
	resp.Write(w)
}

func truncateURI(uri string) string {
	if len(uri) > 60 {
		return uri[:57] + "..."
	}
	return uri
}
