package client

import (
	"bufio"
	"context"
	"log/slog"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jclement/gatecrash/internal/protocol"
)

const (
	// warmPoolSize is how many channels the client keeps pre-opened and parked at
	// the server. Each one lets a request skip the CHANNEL_OPEN/CONFIRMATION
	// exchange, which costs a full round trip before any request byte can move.
	// A parked channel is cheap — a struct and a blocked goroutine on each side —
	// so this only needs to cover concurrent requests in flight, not throughput.
	warmPoolSize = 8

	// warmRetryDelay backs off before replacing a channel that closed without ever
	// carrying a request. That happens transiently while the server is still
	// registering the connection (it registers on the control channel, which races
	// the first warm opens) and permanently once the connection is going away.
	// Without the delay, either case would spin opening channels as fast as it can.
	warmRetryDelay = 250 * time.Millisecond
)

// maintainWarmPool keeps up to warmPoolSize channels pre-opened at the server for
// the lifetime of conn.
//
// Opening these IS how the client announces it supports them: a server that
// understands the type parks them and leases one per request, and a server that
// does not rejects the first one with UnknownChannelType, which is a clean,
// connection-preserving negotiation failure that we treat as "this server wants
// on-demand channels" and stop. Either way every request still works, so there is
// no probe request and nothing to version-gate.
func (c *Client) maintainWarmPool(ctx context.Context, conn *gossh.Client, connDone <-chan struct{}) {
	slots := make(chan struct{}, warmPoolSize)
	var unsupportedOnce sync.Once

	for {
		// Take a slot, so at most warmPoolSize channels are outstanding.
		select {
		case <-ctx.Done():
			return
		case <-connDone:
			return
		case slots <- struct{}{}:
		}

		ch, reqs, err := conn.OpenChannel(protocol.ChannelHTTPWarm, nil)
		if err != nil {
			<-slots
			// Expected against an older server, and against a dying connection.
			// Either way, stop offering: the on-demand path covers every request.
			unsupportedOnce.Do(func() {
				slog.Debug("server is not accepting pre-opened channels; "+
					"falling back to opening a channel per request", "error", err)
			})
			return
		}

		go func() {
			defer func() { <-slots }()
			go gossh.DiscardRequests(reqs)
			if !c.handleWarmChannel(ch) {
				// Closed without being used. Pause before replacing it so a
				// server that is not yet ready — or a connection on its way
				// out — cannot turn this into a hot loop.
				select {
				case <-ctx.Done():
				case <-connDone:
				case <-time.After(warmRetryDelay):
				}
			}
		}()
	}
}

// handleWarmChannel parks on a pre-opened channel until the server leases it for
// a request, then serves that request. It reports whether the channel was
// actually used, which is what tells the pool whether replacing it immediately is
// safe.
//
// The channel carries exactly one request and is then closed, matching the
// lifetime of an on-demand channel. Reusing it for a second request would save
// nothing further (the open cost is already gone) while making a single HTTP
// framing error desynchronise every later request on that channel.
func (c *Client) handleWarmChannel(ch gossh.Channel) bool {
	defer ch.Close()

	// Blocks until the server writes a prelude, which is the normal resting state
	// of a parked channel. An error here means the channel or connection went
	// away before it was used, not that a request failed.
	br := bufio.NewReader(ch)
	data, err := protocol.ReadHTTPPrelude(br)
	if err != nil {
		return false
	}

	// br may already hold request bytes read alongside the prelude, so it — not
	// the raw channel — has to be what the request is parsed from.
	c.serveTunneledRequest(ch, br, *data)
	return true
}
