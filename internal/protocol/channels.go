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
	ControlHeartbeatAck    = "heartbeat_ack"
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
