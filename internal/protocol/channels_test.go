package protocol

import (
	"encoding/json"
	"testing"
)

func TestChannelConstants(t *testing.T) {
	// Verify channel type strings are stable (clients and servers depend on these).
	if ChannelHTTP != "gatecrash-http" {
		t.Fatalf("ChannelHTTP = %q, want %q", ChannelHTTP, "gatecrash-http")
	}
	if ChannelDirectTCPIP != "direct-tcpip" {
		t.Fatalf("ChannelDirectTCPIP = %q, want %q", ChannelDirectTCPIP, "direct-tcpip")
	}
	if ChannelControl != "gatecrash-control" {
		t.Fatalf("ChannelControl = %q, want %q", ChannelControl, "gatecrash-control")
	}
}

func TestControlMessageTypes(t *testing.T) {
	if ControlHeartbeat != "heartbeat" {
		t.Fatalf("ControlHeartbeat = %q", ControlHeartbeat)
	}
	if ControlClientInfo != "client_info" {
		t.Fatalf("ControlClientInfo = %q", ControlClientInfo)
	}
	if ControlUpdateAvailable != "update_available" {
		t.Fatalf("ControlUpdateAvailable = %q", ControlUpdateAvailable)
	}
}

func TestControlMessageJSON(t *testing.T) {
	msg := ControlMessage{
		Type: ControlHeartbeat,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ControlMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Type != ControlHeartbeat {
		t.Fatalf("type = %q, want %q", decoded.Type, ControlHeartbeat)
	}
	if decoded.Data != nil {
		t.Fatalf("data should be nil for heartbeat, got %s", decoded.Data)
	}
}

func TestControlMessageWithData(t *testing.T) {
	info := ClientInfo{
		Version:  "1.0.0",
		OS:       "linux",
		Arch:     "amd64",
		Hostname: "myhost",
	}
	infoJSON, _ := json.Marshal(info)

	msg := ControlMessage{
		Type: ControlClientInfo,
		Data: infoJSON,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ControlMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var decodedInfo ClientInfo
	if err := json.Unmarshal(decoded.Data, &decodedInfo); err != nil {
		t.Fatalf("unmarshal client info: %v", err)
	}
	if decodedInfo.Version != "1.0.0" {
		t.Fatalf("version = %q", decodedInfo.Version)
	}
	if decodedInfo.Hostname != "myhost" {
		t.Fatalf("hostname = %q", decodedInfo.Hostname)
	}
}

func TestClientInfoJSON(t *testing.T) {
	info := ClientInfo{
		Version:  "dev",
		OS:       "darwin",
		Arch:     "arm64",
		Hostname: "macbook",
	}
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ClientInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded != info {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, info)
	}
}

func TestHTTPChannelDataFields(t *testing.T) {
	d := HTTPChannelData{
		RequestID:    "abc-123",
		Method:       "POST",
		URI:          "/api/data",
		Host:         "example.com",
		RemoteAddr:   "1.2.3.4",
		TLS:          true,
		PreserveHost: true,
	}
	if d.RequestID != "abc-123" {
		t.Fatalf("RequestID = %q", d.RequestID)
	}
	if d.Method != "POST" {
		t.Fatalf("Method = %q", d.Method)
	}
	if !d.TLS {
		t.Fatal("TLS should be true")
	}
	if !d.PreserveHost {
		t.Fatal("PreserveHost should be true")
	}
}

func TestDirectTCPIPDataFields(t *testing.T) {
	d := DirectTCPIPData{
		DestAddr:   "127.0.0.1",
		DestPort:   3306,
		OriginAddr: "192.168.1.1",
		OriginPort: 54321,
	}
	if d.DestPort != 3306 {
		t.Fatalf("DestPort = %d", d.DestPort)
	}
	if d.OriginAddr != "192.168.1.1" {
		t.Fatalf("OriginAddr = %q", d.OriginAddr)
	}
}
