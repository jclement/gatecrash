package server

import (
	"testing"
	"time"
)

// t0 is a fixed base time for deterministic, clock-independent rate tests.
var t0 = time.Unix(1700000000, 0)

func TestBandwidthTracker_EmptyHistory(t *testing.T) {
	bt := newBandwidthTracker(10)
	h := bt.history()
	if len(h) != 0 {
		t.Fatalf("expected empty history, got %d samples", len(h))
	}
}

func TestBandwidthTracker_FirstRecordNoSample(t *testing.T) {
	bt := newBandwidthTracker(10)
	bt.record(100, 200)
	// First record establishes baseline, no rate can be computed yet
	h := bt.history()
	if len(h) != 0 {
		t.Fatalf("expected 0 samples after first record, got %d", len(h))
	}
}

func TestBandwidthTracker_SecondRecordProducesSample(t *testing.T) {
	bt := newBandwidthTracker(10)
	bt.recordAt(t0, 0, 0)
	bt.recordAt(t0.Add(time.Second), 1000, 2000)
	h := bt.history()
	if len(h) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(h))
	}
	if h[0].In <= 0 {
		t.Fatalf("expected positive in rate, got %f", h[0].In)
	}
	if h[0].Out <= 0 {
		t.Fatalf("expected positive out rate, got %f", h[0].Out)
	}
	if h[0].Time == 0 {
		t.Fatal("expected non-zero timestamp")
	}
}

func TestBandwidthTracker_RingBuffer(t *testing.T) {
	bt := newBandwidthTracker(3)

	// Record 5 samples (overflow capacity of 3)
	for i := range 5 {
		bt.recordAt(t0.Add(time.Duration(i)*time.Second), int64(i*100), int64(i*200))
	}

	h := bt.history()
	if len(h) != 3 {
		t.Fatalf("expected 3 samples (ring buffer), got %d", len(h))
	}

	// Latest sample should have the most recent timestamp
	if h[2].Time < h[1].Time {
		t.Fatal("samples should be in chronological order")
	}
}

func TestBandwidthTracker_NegativeRateClamped(t *testing.T) {
	bt := newBandwidthTracker(10)
	bt.recordAt(t0, 1000, 2000)
	// Simulate counter decrease (shouldn't happen, but be defensive)
	bt.recordAt(t0.Add(time.Second), 500, 1000)
	h := bt.history()
	if len(h) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(h))
	}
	if h[0].In < 0 {
		t.Fatalf("negative rate should be clamped to 0, got %f", h[0].In)
	}
	if h[0].Out < 0 {
		t.Fatalf("negative rate should be clamped to 0, got %f", h[0].Out)
	}
}

func TestBandwidthTracker_HistoryIsCopy(t *testing.T) {
	bt := newBandwidthTracker(10)
	bt.recordAt(t0, 0, 0)
	bt.recordAt(t0.Add(time.Second), 100, 200)

	h1 := bt.history()
	h2 := bt.history()

	// Modify h1, ensure h2 is unaffected
	if len(h1) > 0 {
		h1[0].In = 999999
		if h2[0].In == 999999 {
			t.Fatal("history() should return a copy, not a reference")
		}
	}
}

func TestBandwidthTracker_ZeroRates(t *testing.T) {
	bt := newBandwidthTracker(10)
	bt.recordAt(t0, 100, 200)
	bt.recordAt(t0.Add(time.Second), 100, 200) // No change
	h := bt.history()
	if len(h) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(h))
	}
	if h[0].In != 0 {
		t.Fatalf("expected 0 in rate for unchanged data, got %f", h[0].In)
	}
	if h[0].Out != 0 {
		t.Fatalf("expected 0 out rate for unchanged data, got %f", h[0].Out)
	}
}
