package protocol

import "encoding/json"

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
)

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
