package client

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

// handleDiagnosticChannel responds to server-initiated diagnostic tests.
// Protocol: length-prefixed JSON messages, with raw byte transfers between messages.
//
// Latency: server sends ping → client sends pong (repeated)
// Download round: server sends {download, size=N} → server writes N raw bytes →
//
//	client reads N bytes → client sends {result}
//
// Download end: server sends {download, size=0}
// Upload round: server sends {upload, size=N} → client sends {result} →
//
//	client writes N raw bytes
//
// Upload end: server sends {upload, size=0}
func (c *Client) handleDiagnosticChannel(newCh gossh.NewChannel) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		slog.Error("failed to accept diagnostic channel", "error", err)
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	for {
		msg, err := readDiagMsg(ch)
		if err != nil {
			return // channel closed
		}

		switch msg.Type {
		case protocol.DiagPing:
			pong := protocol.DiagMessage{Type: protocol.DiagPong, Seq: msg.Seq}
			if err := writeDiagMsg(ch, &pong); err != nil {
				return
			}

		case protocol.DiagDownload:
			if msg.Size == 0 {
				continue // end of download phase
			}
			// Server is about to send msg.Size raw bytes; read them.
			if _, err := io.CopyN(io.Discard, ch, int64(msg.Size)); err != nil {
				return
			}
			ack := protocol.DiagMessage{Type: protocol.DiagResult, Size: msg.Size}
			if err := writeDiagMsg(ch, &ack); err != nil {
				return
			}

		case protocol.DiagUpload:
			if msg.Size == 0 {
				continue // end of upload phase
			}
			// Server wants us to send msg.Size raw bytes.
			ack := protocol.DiagMessage{Type: protocol.DiagResult, Size: msg.Size}
			if err := writeDiagMsg(ch, &ack); err != nil {
				return
			}
			if err := sendPayload(ch, msg.Size); err != nil {
				return
			}
		}
	}
}

func sendPayload(w io.Writer, size int) error {
	buf := make([]byte, 32*1024)
	rand.Read(buf)
	remaining := size
	for remaining > 0 {
		n := len(buf)
		if n > remaining {
			n = remaining
		}
		written, err := w.Write(buf[:n])
		if err != nil {
			return err
		}
		remaining -= written
	}
	return nil
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
