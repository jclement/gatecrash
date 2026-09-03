package server

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// diagEvent is a single NDJSON event streamed to the browser during a diagnostic.
type diagEvent struct {
	Phase string  `json:"phase"`           // "latency", "download", "upload", "done", "error"
	Seq   int     `json:"seq,omitempty"`   // ping sequence number
	Ms    float64 `json:"ms,omitempty"`    // latency or elapsed time
	Bytes int64   `json:"bytes,omitempty"` // bytes transferred so far
	Mbps  float64 `json:"mbps,omitempty"`  // current throughput
	Error string  `json:"error,omitempty"`
}

const (
	diagPingCount = 20
	// diagRoundSizeInitial is the first round's size. Each round costs one
	// message/ack round trip, so a fixed small round caps the measurable rate at
	// roundSize/RTT regardless of the real link — at 1 MiB and 100ms RTT that is
	// ~84 Mbps, which the tunnel can exceed. Start small to probe, then adapt.
	diagRoundSizeInitial = 1 * 1024 * 1024
	diagRoundSizeMax     = 32 * 1024 * 1024
	// diagRoundTarget is how long one round should ideally take. Sizing rounds to
	// this keeps the per-round ack a small fraction of the round on any link.
	diagRoundTarget   = time.Second
	diagThroughputDur = 10 * time.Second
)

// nextRoundSize scales the next transfer round so it takes roughly
// diagRoundTarget at the rate just measured, keeping the per-round
// acknowledgement from dominating the result on a fast link while not
// overshooting the overall budget on a slow one.
func nextRoundSize(current int, elapsed time.Duration) int {
	if elapsed <= 0 {
		return current
	}
	scaled := float64(current) * (float64(diagRoundTarget) / float64(elapsed))
	next := int(scaled)
	if next < diagRoundSizeInitial {
		next = diagRoundSizeInitial
	}
	if next > diagRoundSizeMax {
		next = diagRoundSizeMax
	}
	return next
}

type eventWriter func(e diagEvent)

// runDiagnosticStream opens a diagnostic channel and streams results via emit.
func (s *Server) runDiagnosticStream(conn gossh.Conn, emit eventWriter) {
	ch, reqs, err := openChannelTimeout(conn, protocol.ChannelDiagnostic, nil, channelOpenTimeout)
	if err != nil {
		emit(diagEvent{Phase: "error", Error: "client does not support diagnostics (upgrade client)"})
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	// Enforce an overall deadline so a disconnected client can't block this HTTP
	// handler goroutine forever. SSH channels do NOT implement SetDeadline, so we
	// close the channel after the cap — that unblocks any pending Read/Write. The
	// full diagnostic takes ~20s (latency pings + 10s download + 10s upload), so
	// 90s is generous.
	diagDone := make(chan struct{})
	defer close(diagDone)
	go func() {
		select {
		case <-diagDone:
		case <-time.After(90 * time.Second):
			ch.Close()
		}
	}()

	// --- Latency phase ---
	for i := 0; i < diagPingCount; i++ {
		ping := protocol.DiagMessage{Type: protocol.DiagPing, Seq: i}
		start := time.Now()
		if err := writeDiagMsg(ch, &ping); err != nil {
			emit(diagEvent{Phase: "error", Error: fmt.Sprintf("latency test failed: %v", err)})
			return
		}
		pong, err := readDiagMsg(ch)
		if err != nil {
			emit(diagEvent{Phase: "error", Error: fmt.Sprintf("latency test failed: %v", err)})
			return
		}
		if pong.Type != protocol.DiagPong || pong.Seq != i {
			emit(diagEvent{Phase: "error", Error: "unexpected ping response"})
			return
		}
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		emit(diagEvent{Phase: "latency", Seq: i, Ms: ms})
	}

	// --- Download phase (server → client), multiple rounds ---
	if err := runStreamDownload(ch, emit); err != nil {
		emit(diagEvent{Phase: "error", Error: fmt.Sprintf("download test failed: %v", err)})
		return
	}

	// --- Upload phase (client → server), multiple rounds ---
	if err := runStreamUpload(ch, emit); err != nil {
		emit(diagEvent{Phase: "error", Error: fmt.Sprintf("upload test failed: %v", err)})
		return
	}

	emit(diagEvent{Phase: "done"})
}

// runStreamDownload runs multiple rounds of server→client transfers.
// Each round: send DiagMessage{download, size=N}, write N raw bytes, read ack.
// Size=0 signals end.
func runStreamDownload(ch gossh.Channel, emit eventWriter) error {
	buf := make([]byte, 32*1024)
	rand.Read(buf)

	start := time.Now()
	deadline := start.Add(diagThroughputDur)
	var totalBytes int64
	roundSize := diagRoundSizeInitial

	for time.Now().Before(deadline) {
		// Tell client about this round
		msg := protocol.DiagMessage{Type: protocol.DiagDownload, Size: roundSize}
		if err := writeDiagMsg(ch, &msg); err != nil {
			return err
		}

		// Send the round's payload
		roundStart := time.Now()
		remaining := roundSize
		for remaining > 0 {
			n := len(buf)
			if n > remaining {
				n = remaining
			}
			written, err := ch.Write(buf[:n])
			if err != nil {
				return err
			}
			remaining -= written
		}

		// Wait for ack
		ack, err := readDiagMsg(ch)
		if err != nil {
			return err
		}
		if ack.Type != protocol.DiagResult {
			return fmt.Errorf("unexpected ack: %s", ack.Type)
		}

		roundElapsed := time.Since(roundStart)
		totalBytes += int64(roundSize)
		roundMs := float64(roundElapsed.Microseconds()) / 1000.0
		mbps := float64(roundSize) * 8.0 / (roundMs / 1000.0) / 1e6
		roundSize = nextRoundSize(roundSize, roundElapsed)

		emit(diagEvent{
			Phase: "download",
			Bytes: totalBytes,
			Ms:    float64(time.Since(start).Milliseconds()),
			Mbps:  mbps,
		})
	}

	// Signal end of download
	end := protocol.DiagMessage{Type: protocol.DiagDownload, Size: 0}
	return writeDiagMsg(ch, &end)
}

// runStreamUpload runs multiple rounds of client→server transfers.
// Each round: send DiagMessage{upload, size=N}, read ack, read N raw bytes.
// Size=0 signals end.
func runStreamUpload(ch gossh.Channel, emit eventWriter) error {
	buf := make([]byte, 32*1024)

	start := time.Now()
	deadline := start.Add(diagThroughputDur)
	var totalBytes int64
	roundSize := diagRoundSizeInitial

	for time.Now().Before(deadline) {
		// Tell client to send a round
		msg := protocol.DiagMessage{Type: protocol.DiagUpload, Size: roundSize}
		if err := writeDiagMsg(ch, &msg); err != nil {
			return err
		}

		// Wait for ack (client sends this before the payload)
		ack, err := readDiagMsg(ch)
		if err != nil {
			return err
		}
		if ack.Type != protocol.DiagResult {
			return fmt.Errorf("unexpected ack: %s", ack.Type)
		}

		// Read the round's payload
		roundStart := time.Now()
		remaining := roundSize
		for remaining > 0 {
			n := len(buf)
			if n > remaining {
				n = remaining
			}
			nr, err := ch.Read(buf[:n])
			if err != nil {
				return err
			}
			remaining -= nr
		}

		roundElapsed := time.Since(roundStart)
		totalBytes += int64(roundSize)
		roundMs := float64(roundElapsed.Microseconds()) / 1000.0
		mbps := float64(roundSize) * 8.0 / (roundMs / 1000.0) / 1e6
		roundSize = nextRoundSize(roundSize, roundElapsed)

		emit(diagEvent{
			Phase: "upload",
			Bytes: totalBytes,
			Ms:    float64(time.Since(start).Milliseconds()),
			Mbps:  mbps,
		})
	}

	// Signal end of upload
	end := protocol.DiagMessage{Type: protocol.DiagUpload, Size: 0}
	return writeDiagMsg(ch, &end)
}

func readDiagMsg(r io.Reader) (*protocol.DiagMessage, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > 4096 {
		return nil, fmt.Errorf("diagnostic message too large: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var msg protocol.DiagMessage
	if err := json.Unmarshal(buf, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func writeDiagMsg(w io.Writer, msg *protocol.DiagMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
