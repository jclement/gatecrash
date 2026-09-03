package server

import (
	"testing"
	"time"
)

// TestNextRoundSize_ScalesToTheLink checks the property the adaptive sizing
// exists for: each round costs one message/ack round trip, so a fixed 1 MiB
// round caps the *measurable* rate at roundSize/RTT — about 84 Mbps at 100ms —
// no matter how fast the tunnel really is. Rounds must grow on a fast link.
func TestNextRoundSize_ScalesToTheLink(t *testing.T) {
	// A round that finished far faster than the target must grow.
	got := nextRoundSize(diagRoundSizeInitial, 100*time.Millisecond)
	if got <= diagRoundSizeInitial {
		t.Fatalf("a fast round should grow the next one: got %d, want > %d", got, diagRoundSizeInitial)
	}

	// A round that took about the target should stay near it.
	steady := nextRoundSize(4*1024*1024, diagRoundTarget)
	if steady != 4*1024*1024 {
		t.Fatalf("a round at target should hold its size, got %d", steady)
	}
}

func TestNextRoundSize_ClampedBothWays(t *testing.T) {
	// A very slow link must not shrink below the floor...
	if got := nextRoundSize(diagRoundSizeInitial, 30*time.Second); got != diagRoundSizeInitial {
		t.Fatalf("slow link should clamp to the floor, got %d", got)
	}
	// ...and a very fast one must not grow without bound.
	if got := nextRoundSize(diagRoundSizeMax, time.Microsecond); got != diagRoundSizeMax {
		t.Fatalf("fast link should clamp to the ceiling, got %d", got)
	}
}

// TestNextRoundSize_ZeroElapsedIsSafe guards against a divide-by-zero on a clock
// that reports no elapsed time for a round.
func TestNextRoundSize_ZeroElapsedIsSafe(t *testing.T) {
	if got := nextRoundSize(2*1024*1024, 0); got != 2*1024*1024 {
		t.Fatalf("zero elapsed should leave the size unchanged, got %d", got)
	}
}

// TestNextRoundSize_LiftsTheMeasurementCeiling is the concrete regression: at a
// 100ms round trip the old fixed 1 MiB round could never report more than about
// 84 Mbps. After one adaptation the round must be large enough to measure well
// past that.
func TestNextRoundSize_LiftsTheMeasurementCeiling(t *testing.T) {
	const rtt = 100 * time.Millisecond

	oldCeilingMbps := float64(diagRoundSizeInitial) * 8 / rtt.Seconds() / 1e6
	if oldCeilingMbps > 100 {
		t.Fatalf("sanity: expected the old fixed round to cap near 84 Mbps, got %.0f", oldCeilingMbps)
	}

	// One round finishing in ~rtt means the link is much faster than reported.
	grown := nextRoundSize(diagRoundSizeInitial, rtt)
	newCeilingMbps := float64(grown) * 8 / rtt.Seconds() / 1e6
	if newCeilingMbps <= oldCeilingMbps*4 {
		t.Fatalf("adaptation did not meaningfully lift the ceiling: %.0f -> %.0f Mbps",
			oldCeilingMbps, newCeilingMbps)
	}
}
