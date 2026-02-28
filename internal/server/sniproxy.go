package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
)

// sniListener wraps a raw TCP listener. On Accept it peeks at the TLS
// ClientHello to extract the SNI. If the SNI matches a passthrough tunnel the
// connection is forwarded directly (raw bytes) and Accept loops again. Otherwise
// the TLS handshake is completed and the resulting tls.Conn is returned to the
// caller (http.Serve).
type sniListener struct {
	inner     net.Listener
	tlsConfig *tls.Config
	server    *Server
}

func (s *Server) newSNIListener(inner net.Listener) net.Listener {
	return &sniListener{
		inner:     inner,
		tlsConfig: s.tlsConfig,
		server:    s,
	}
}

func (l *sniListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}

		br := bufio.NewReader(conn)
		sni, err := peekClientHelloSNI(br)
		if err != nil {
			slog.Debug("SNI peek failed, completing TLS handshake anyway", "remote", conn.RemoteAddr(), "error", err)
		}

		pc := &prefixConn{Conn: conn, reader: br}

		if sni != "" {
			tunnel := l.server.registry.FindByHostname(sni)
			if tunnel != nil && tunnel.TLSPassthrough {
				slog.Debug("TLS passthrough", "sni", sni, "tunnel", tunnel.ID, "remote", conn.RemoteAddr())
				go l.server.handleTCPConn(pc, tunnel)
				continue // don't return this conn to http.Serve
			}
		}

		// Normal TLS termination
		tlsConn := tls.Server(pc, l.tlsConfig)
		return tlsConn, nil
	}
}

func (l *sniListener) Close() error   { return l.inner.Close() }
func (l *sniListener) Addr() net.Addr { return l.inner.Addr() }

// prefixConn wraps a net.Conn with a bufio.Reader so that bytes already
// peeked (buffered) are replayed transparently on the first Read calls.
type prefixConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// peekClientHelloSNI peeks at a TLS ClientHello and extracts the SNI server
// name without consuming data from the reader. Returns "" if SNI is absent.
func peekClientHelloSNI(reader *bufio.Reader) (string, error) {
	// TLS record header: 1 byte type + 2 bytes version + 2 bytes length
	header, err := reader.Peek(5)
	if err != nil {
		return "", fmt.Errorf("peek TLS header: %w", err)
	}

	// Must be a TLS handshake record (type 22)
	if header[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake (type %d)", header[0])
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384 {
		return "", fmt.Errorf("TLS record too large: %d", recordLen)
	}

	// Peek the entire TLS record
	all, err := reader.Peek(5 + recordLen)
	if err != nil {
		return "", fmt.Errorf("peek TLS record: %w", err)
	}

	data := all[5:] // skip record header
	return parseSNIFromHandshake(data)
}

// parseSNIFromHandshake parses a ClientHello handshake message to extract
// the SNI server_name extension value.
func parseSNIFromHandshake(data []byte) (string, error) {
	if len(data) < 42 {
		return "", fmt.Errorf("handshake too short")
	}

	// Handshake header: 1 byte type + 3 bytes length
	if data[0] != 0x01 { // ClientHello
		return "", fmt.Errorf("not a ClientHello (type %d)", data[0])
	}

	// Skip handshake header (4), client version (2), random (32)
	pos := 4 + 2 + 32

	if pos >= len(data) {
		return "", fmt.Errorf("truncated at session ID")
	}

	// Session ID (1 byte length + variable)
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(data) {
		return "", fmt.Errorf("truncated at cipher suites")
	}

	// Cipher suites (2 byte length + variable)
	cipherLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherLen

	if pos+1 > len(data) {
		return "", fmt.Errorf("truncated at compression")
	}

	// Compression methods (1 byte length + variable)
	compLen := int(data[pos])
	pos += 1 + compLen

	if pos+2 > len(data) {
		// No extensions
		return "", nil
	}

	// Extensions (2 byte length + variable)
	extLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	end := pos + extLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extDataLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extDataLen > end {
			break
		}

		// SNI extension type = 0x0000
		if extType == 0 {
			return parseSNIExtension(data[pos : pos+extDataLen])
		}

		pos += extDataLen
	}

	return "", nil
}

// parseSNIExtension extracts the host_name from an SNI extension payload.
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", nil
	}

	// Server name list length
	listLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if listLen > len(data) {
		listLen = len(data)
	}
	data = data[:listLen]

	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[3:]

		if nameLen > len(data) {
			break
		}

		// host_name type = 0
		if nameType == 0 {
			return string(data[:nameLen]), nil
		}

		data = data[nameLen:]
	}

	return "", nil
}

// Verify interface compliance
var _ net.Listener = (*sniListener)(nil)
var _ io.Reader = (*prefixConn)(nil)
