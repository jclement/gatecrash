package admin

import "testing"

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
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
