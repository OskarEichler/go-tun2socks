package core

import (
	"net"
)

// TCPConnHandler handles TCP connections comming from TUN.
type TCPConnHandler interface {
	// Handle handles the conn for target.
	Handle(conn net.Conn, target *net.TCPAddr) error
}

// UDPConnHandler handles UDP connections coming from TUN. The core admits
// 1024 concurrent associations/connecting workers and 8 MiB of pending payloads.
// Per-association queues hold at most 64 packets and 256 KiB. Queue pressure
// drops packets while retaining the association for later traffic. Handlers own
// session expiry and call UDPConn.Close when an association ends.
type UDPConnHandler interface {
	// Connect connects the proxy server. Note that target can be nil.
	Connect(conn UDPConn, target *net.UDPAddr) error

	// ReceiveTo receives copied TUN data outside the lwIP lock, in FIFO order.
	// A bounded queue drops packets on overload.
	ReceiveTo(conn UDPConn, data []byte, addr *net.UDPAddr) error
}

var tcpConnHandler TCPConnHandler
var udpConnHandler UDPConnHandler

func RegisterTCPConnHandler(h TCPConnHandler) {
	tcpConnHandler = h
}

func RegisterUDPConnHandler(h UDPConnHandler) {
	udpConnHandler = h
}
