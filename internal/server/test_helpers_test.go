package server

import (
	"net"

	gossh "golang.org/x/crypto/ssh"
)

// fakeConn implements ssh.Conn for testing. The int value provides identity.
type fakeConn int

func (f fakeConn) OpenChannel(name string, data []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	return nil, nil, nil
}
func (f fakeConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, nil
}
func (f fakeConn) Close() error          { return nil }
func (f fakeConn) Wait() error           { return nil }
func (f fakeConn) LocalAddr() net.Addr   { return nil }
func (f fakeConn) RemoteAddr() net.Addr  { return nil }
func (f fakeConn) SessionID() []byte     { return nil }
func (f fakeConn) ClientVersion() []byte { return nil }
func (f fakeConn) ServerVersion() []byte { return nil }
func (f fakeConn) User() string          { return "" }
