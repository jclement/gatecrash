package client

import (
	"io"
	"log/slog"
	"net"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// handleDirectTCPIP handles a direct-tcpip channel for TCP forwarding.
func (c *Client) handleDirectTCPIP(newCh gossh.NewChannel) {
	var data struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := gossh.Unmarshal(newCh.ExtraData(), &data); err != nil {
		slog.Error("failed to parse direct-tcpip data", "error", err)
		newCh.Reject(gossh.ConnectionFailed, "invalid channel data")
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		slog.Error("failed to accept direct-tcpip channel", "error", err)
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	// Connect to local target
	target := c.targetAddr()
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		slog.Error("failed to connect to target",
			"target", target,
			"origin", data.OriginAddr,
			"error", err,
		)
		return
	}
	defer conn.Close()

	slog.Info("tcp forward",
		"target", target,
		"origin", data.OriginAddr,
	)

	// Bidirectional pipe
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(ch, conn)
		if cw, ok := ch.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, ch)
		done <- struct{}{}
	}()
	<-done
}
