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
	diagPingCount     = 20
	diagRoundSize     = 1 * 1024 * 1024 // 1 MiB per transfer round
	diagThroughputDur = 10 * time.Second
)

type eventWriter func(e diagEvent)

// runDiagnosticStream opens a diagnostic channel and streams results via emit.
func (s *Server) runDiagnosticStream(conn gossh.Conn, emit eventWriter) {
	ch, reqs, err := conn.OpenChannel(protocol.ChannelDiagnostic, nil)
	if err != nil {
		emit(diagEvent{Phase: "error", Error: "client does not support diagnostics (upgrade client)"})
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	// Set an overall deadline so a disconnected client can't block this
	// HTTP handler goroutine forever. The full diagnostic takes ~20s
	// (latency pings + 10s download + 10s upload), so 60s is generous.
	type deadliner interface {
		SetDeadline(t time.Time) error
	}
	if dl, ok := ch.(deadliner); ok {
		dl.SetDeadline(time.Now().Add(60 * time.Second))
	}

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

	for time.Now().Before(deadline) {
		// Tell client about this round
		msg := protocol.DiagMessage{Type: protocol.DiagDownload, Size: diagRoundSize}
		if err := writeDiagMsg(ch, &msg); err != nil {
			return err
		}

		// Send the round's payload
		roundStart := time.Now()
		remaining := diagRoundSize
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

		totalBytes += int64(diagRoundSize)
		roundMs := float64(time.Since(roundStart).Microseconds()) / 1000.0
		mbps := float64(diagRoundSize) * 8.0 / (roundMs / 1000.0) / 1e6

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

	for time.Now().Before(deadline) {
		// Tell client to send a round
		msg := protocol.DiagMessage{Type: protocol.DiagUpload, Size: diagRoundSize}
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
		remaining := diagRoundSize
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

		totalBytes += int64(diagRoundSize)
		roundMs := float64(time.Since(roundStart).Microseconds()) / 1000.0
		mbps := float64(diagRoundSize) * 8.0 / (roundMs / 1000.0) / 1e6

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
