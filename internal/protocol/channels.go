package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	gossh "golang.org/x/crypto/ssh"
)

// SSH channel type constants.
const (
	// ChannelHTTP is a custom channel type for forwarding HTTP requests.
	// The server opens this channel toward the client for each incoming request.
	ChannelHTTP = "gatecrash-http"

	// ChannelDirectTCPIP is the standard SSH direct-tcpip channel (RFC 4254 Section 7.2).
	// Used for raw TCP port forwarding.
	ChannelDirectTCPIP = "direct-tcpip"

	// ChannelControl is a long-lived channel for heartbeat and metadata exchange.
	// Opened by the client immediately after SSH connection.
	ChannelControl = "gatecrash-control"

	// ChannelDiagnostic is opened by the server toward the client to run
	// latency and throughput diagnostics on the tunnel link itself.
	ChannelDiagnostic = "gatecrash-diagnostic"

	// ChannelHTTPWarm is a pre-opened HTTP forwarding channel. The CLIENT opens
	// these toward the server ahead of any request and parks them; the server
	// leases one when a request arrives, so the request does not pay the
	// CHANNEL_OPEN/CONFIRMATION round trip that ChannelHTTP costs.
	//
	// The client opening them IS the capability announcement: a server that
	// receives none simply never has one to lease and uses ChannelHTTP exactly as
	// before, and a client talking to a server that does not know this type gets
	// a clean UnknownChannelType rejection and stops offering them. Neither side
	// needs a version check or a probe request.
	//
	// Because the channel is opened before the request exists, the per-request
	// metadata that ChannelHTTP carries in the open's ExtraData is instead sent
	// as a prelude on the channel itself (see WriteHTTPPrelude). The name is
	// versioned so an incompatible framing change becomes a new type rather than
	// a silent misparse.
	ChannelHTTPWarm = "gatecrash-http-warm-v1"
)

// maxPreludeLen bounds a prelude length prefix so a corrupt or hostile value
// cannot make the reader allocate arbitrarily.
const maxPreludeLen = 64 * 1024

// WriteHTTPPrelude sends the per-request metadata that precedes the HTTP request
// on a warm channel, as a 4-byte big-endian length followed by the SSH-encoded
// struct. It is written as one Write so it costs a single SSH packet, and the
// caller writes the HTTP request immediately after.
func WriteHTTPPrelude(w io.Writer, d *HTTPChannelData) error {
	body := gossh.Marshal(*d)
	if len(body) > maxPreludeLen {
		return fmt.Errorf("prelude too large: %d bytes", len(body))
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(body)))
	copy(buf[4:], body)
	_, err := w.Write(buf)
	return err
}

// ReadHTTPPrelude reads the metadata written by WriteHTTPPrelude. It blocks
// until the server leases the channel, which is the normal state of a parked
// warm channel, so callers should treat an error here as the connection going
// away rather than as a request failure.
func ReadHTTPPrelude(r io.Reader) (*HTTPChannelData, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxPreludeLen {
		return nil, fmt.Errorf("invalid prelude length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var d HTTPChannelData
	if err := gossh.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("decode prelude: %w", err)
	}
	return &d, nil
}

// HTTPChannelData is sent as extra data when the server opens a gatecrash-http channel.
type HTTPChannelData struct {
	RequestID    string
	Method       string
	URI          string
	Host         string
	RemoteAddr   string
	TLS          bool
	PreserveHost bool
}

// DirectTCPIPData is the standard SSH direct-tcpip extra data (RFC 4254).
type DirectTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// ControlMessage is exchanged over the control channel as JSON with a 4-byte length prefix.
type ControlMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Control message types.
const (
	ControlHeartbeat       = "heartbeat"
	ControlClientInfo      = "client_info"
	ControlUpdateAvailable = "update_available"
)

// ClientInfo is sent by the client on the control channel after connecting.
type ClientInfo struct {
	Version  string `json:"version"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
}

// Diagnostic message types exchanged over ChannelDiagnostic as length-prefixed JSON.
const (
	DiagPing     = "ping"
	DiagPong     = "pong"
	DiagDownload = "download" // server tells client to read N bytes of payload
	DiagUpload   = "upload"   // server tells client to send N bytes of payload
	DiagResult   = "result"   // client confirms completion
)

// DiagMessage is a single diagnostic command/response.
type DiagMessage struct {
	Type string `json:"type"`
	Size int    `json:"size,omitempty"` // payload size for download/upload
	Seq  int    `json:"seq,omitempty"`  // sequence number for ping/pong
}
