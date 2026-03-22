package server

import (
	"sync"
	"time"
)

// bandwidthSample holds a single rate measurement at a point in time.
type bandwidthSample struct {
	Time int64   `json:"t"`  // unix milliseconds
	In   float64 `json:"in"` // bytes/sec
	Out  float64 `json:"out"`
}

// bandwidthTracker samples aggregate tunnel bandwidth at a fixed interval
// and maintains a ring buffer of recent rate measurements.
type bandwidthTracker struct {
	mu      sync.RWMutex
	samples []bandwidthSample
	maxLen  int

	// previous snapshot for rate calculation
	prevIn   int64
	prevOut  int64
	prevTime time.Time
	started  bool
}

func newBandwidthTracker(maxSamples int) *bandwidthTracker {
	return &bandwidthTracker{
		samples: make([]bandwidthSample, 0, maxSamples),
		maxLen:  maxSamples,
	}
}

// record takes current cumulative byte totals, computes rates, and appends a sample.
func (bt *bandwidthTracker) record(totalIn, totalOut int64) {
	now := time.Now()

	bt.mu.Lock()
	defer bt.mu.Unlock()

	if bt.started {
		dt := now.Sub(bt.prevTime).Seconds()
		if dt > 0 {
			rateIn := float64(totalIn-bt.prevIn) / dt
			rateOut := float64(totalOut-bt.prevOut) / dt
			if rateIn < 0 {
				rateIn = 0
			}
			if rateOut < 0 {
				rateOut = 0
			}

			s := bandwidthSample{
				Time: now.UnixMilli(),
				In:   rateIn,
				Out:  rateOut,
			}
			if len(bt.samples) >= bt.maxLen {
				// Shift left by one
				copy(bt.samples, bt.samples[1:])
				bt.samples[len(bt.samples)-1] = s
			} else {
				bt.samples = append(bt.samples, s)
			}
		}
	}

	bt.prevIn = totalIn
	bt.prevOut = totalOut
	bt.prevTime = now
	bt.started = true
}

// history returns a copy of all samples.
func (bt *bandwidthTracker) history() []bandwidthSample {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	out := make([]bandwidthSample, len(bt.samples))
	copy(out, bt.samples)
	return out
}
