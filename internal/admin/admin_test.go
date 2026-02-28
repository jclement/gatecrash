package admin

import (
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{2684354560, "2.5 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.input)
			if result != tt.expected {
				t.Fatalf("formatBytes(%d) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTunnelView_ByteFormatting(t *testing.T) {
	tv := TunnelView{
		BytesIn:  1048576,
		BytesOut: 2097152,
	}
	if tv.BytesInFmt() != "1.0 MB" {
		t.Fatalf("BytesInFmt: %s", tv.BytesInFmt())
	}
	if tv.BytesOutFmt() != "2.0 MB" {
		t.Fatalf("BytesOutFmt: %s", tv.BytesOutFmt())
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		ago      time.Duration
		expected string
	}{
		{"seconds", 30 * time.Second, "30s"},
		{"one_minute", 1 * time.Minute, "1m"},
		{"minutes", 45 * time.Minute, "45m"},
		{"one_hour", 1 * time.Hour, "1h"},
		{"hours_minutes", 2*time.Hour + 30*time.Minute, "2h 30m"},
		{"exact_hours", 5 * time.Hour, "5h"},
		{"one_day", 24 * time.Hour, "1d"},
		{"days_hours", 3*24*time.Hour + 12*time.Hour, "3d 12h"},
		{"exact_days", 7 * 24 * time.Hour, "7d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			since := time.Now().Add(-tt.ago)
			result := FormatUptime(since)
			if result != tt.expected {
				t.Fatalf("FormatUptime(%v ago) = %q, want %q", tt.ago, result, tt.expected)
			}
		})
	}
}

func TestTunnelView_HostnamesCSV(t *testing.T) {
	tv := TunnelView{Hostnames: []string{"app.example.com", "www.example.com"}}
	if tv.HostnamesCSV() != "app.example.com, www.example.com" {
		t.Fatalf("HostnamesCSV: %s", tv.HostnamesCSV())
	}

	tv2 := TunnelView{Hostnames: []string{"single.com"}}
	if tv2.HostnamesCSV() != "single.com" {
		t.Fatalf("HostnamesCSV single: %s", tv2.HostnamesCSV())
	}

	tv3 := TunnelView{}
	if tv3.HostnamesCSV() != "" {
		t.Fatalf("HostnamesCSV empty: %s", tv3.HostnamesCSV())
	}
}

func TestTunnelView_ClientSummary(t *testing.T) {
	tv := TunnelView{
		Clients: []ClientView{
			{Addr: "192.168.1.1:5000", Uptime: "2h 30m"},
			{Addr: "10.0.0.1:6000", Uptime: "45m"},
		},
	}

	expected := "10.0.0.1:6000 (45m)\n192.168.1.1:5000 (2h 30m)"
	if tv.ClientSummary() != expected {
		t.Fatalf("ClientSummary = %q, want %q", tv.ClientSummary(), expected)
	}

	// Empty
	tv2 := TunnelView{}
	if tv2.ClientSummary() != "" {
		t.Fatalf("ClientSummary empty = %q", tv2.ClientSummary())
	}
}
