package server

import (
	"testing"
)

func TestParseSNIFromHandshake(t *testing.T) {
	// Minimal valid ClientHello with SNI extension for "example.com"
	hello := buildClientHello("example.com")

	sni, err := parseSNIFromHandshake(hello)
	if err != nil {
		t.Fatalf("parseSNIFromHandshake: %v", err)
	}
	if sni != "example.com" {
		t.Fatalf("expected example.com, got %q", sni)
	}
}

func TestParseSNIFromHandshake_NoSNI(t *testing.T) {
	// ClientHello without extensions
	hello := buildClientHelloNoExtensions()

	sni, err := parseSNIFromHandshake(hello)
	if err != nil {
		t.Fatalf("parseSNIFromHandshake: %v", err)
	}
	if sni != "" {
		t.Fatalf("expected empty SNI, got %q", sni)
	}
}

func TestParseSNIFromHandshake_TooShort(t *testing.T) {
	_, err := parseSNIFromHandshake([]byte{0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestParseSNIFromHandshake_NotClientHello(t *testing.T) {
	data := make([]byte, 50)
	data[0] = 0x02 // ServerHello, not ClientHello
	_, err := parseSNIFromHandshake(data)
	if err == nil {
		t.Fatal("expected error for non-ClientHello")
	}
}

func TestParseSNIExtension(t *testing.T) {
	// SNI extension data: list_len(2) + type(1) + name_len(2) + name
	hostname := "test.example.com"
	nameLen := len(hostname)
	listLen := 3 + nameLen // type(1) + nameLen(2) + name

	data := []byte{
		byte(listLen >> 8), byte(listLen), // server name list length
		0x00,                              // host_name type
		byte(nameLen >> 8), byte(nameLen), // host name length
	}
	data = append(data, []byte(hostname)...)

	sni, err := parseSNIExtension(data)
	if err != nil {
		t.Fatalf("parseSNIExtension: %v", err)
	}
	if sni != hostname {
		t.Fatalf("expected %q, got %q", hostname, sni)
	}
}

func TestParseSNIExtension_Empty(t *testing.T) {
	sni, _ := parseSNIExtension([]byte{})
	if sni != "" {
		t.Fatalf("expected empty, got %q", sni)
	}

	sni, _ = parseSNIExtension([]byte{0x00})
	if sni != "" {
		t.Fatalf("expected empty for single byte, got %q", sni)
	}
}

// buildClientHello constructs a minimal TLS ClientHello handshake with SNI.
func buildClientHello(hostname string) []byte {
	// Build SNI extension
	nameBytes := []byte(hostname)
	nameLen := len(nameBytes)
	listLen := 3 + nameLen

	sniExt := []byte{
		0x00, 0x00, // extension type: SNI
	}
	sniPayload := []byte{
		byte(listLen >> 8), byte(listLen),
		0x00, // host_name
		byte(nameLen >> 8), byte(nameLen),
	}
	sniPayload = append(sniPayload, nameBytes...)

	sniExtLen := len(sniPayload)
	sniExt = append(sniExt, byte(sniExtLen>>8), byte(sniExtLen))
	sniExt = append(sniExt, sniPayload...)

	// Extensions total length
	extLen := len(sniExt)

	// Build ClientHello body
	body := []byte{
		0x03, 0x03, // client version TLS 1.2
	}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session ID length = 0
	body = append(body, 0x00, 0x02, 0x00, 0x2f) // cipher suites: 1 suite
	body = append(body, 0x01, 0x00)              // compression: 1 method (null)
	body = append(body, byte(extLen>>8), byte(extLen))
	body = append(body, sniExt...)

	// Handshake header
	bodyLen := len(body)
	handshake := []byte{
		0x01, // ClientHello
		byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen),
	}
	handshake = append(handshake, body...)

	return handshake
}

// buildClientHelloNoExtensions constructs a ClientHello without extensions.
func buildClientHelloNoExtensions() []byte {
	body := []byte{
		0x03, 0x03, // client version
	}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session ID length
	body = append(body, 0x00, 0x02, 0x00, 0x2f) // cipher suites
	body = append(body, 0x01, 0x00)              // compression

	bodyLen := len(body)
	handshake := []byte{
		0x01,
		byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen),
	}
	handshake = append(handshake, body...)
	return handshake
}
