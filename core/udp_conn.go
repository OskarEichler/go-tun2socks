package core

/*
#cgo CFLAGS: -I./c/include
#include "lwip/udp.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"
)

// These limits bound connecting handlers, queued packets and queued payloads
// across the process. UDP overload drops packets so the peer can recover.
const (
	maxUDPConnections  = 1024
	maxUDPPendingBytes = 8 << 20
	maxUDPQueuePackets = 64
	maxUDPQueueBytes   = 256 << 10
)

var udpAdmission struct {
	sync.Mutex
	connections int
	bytes       int
}

type udpConnState uint

const (
	udpConnecting udpConnState = iota
	udpConnected
	udpClosed
)

type udpPacket struct {
	data []byte
	addr *net.UDPAddr
}

type udpConn struct {
	sync.Mutex
	pcb          *C.struct_udp_pcb
	handler      UDPConnHandler
	localAddr    *net.UDPAddr
	localIP      C.ip_addr_t
	localPort    C.u16_t
	state        udpConnState
	pending      chan *udpPacket
	pendingBytes int
	done         chan struct{}
}

// Caller holds lwipMutex. Publish before starting Connect so a fast failure
// cannot leave a closed connection in the map.
func newUDPConn(pcb *C.struct_udp_pcb, handler UDPConnHandler, localIP C.ip_addr_t, localPort C.u16_t, localAddr, remoteAddr *net.UDPAddr) (UDPConn, error) {
	udpAdmission.Lock()
	if udpAdmission.connections >= maxUDPConnections {
		udpAdmission.Unlock()
		return nil, errors.New("UDP connection limit reached")
	}
	udpAdmission.connections++
	udpAdmission.Unlock()

	conn := &udpConn{
		pcb: pcb, handler: handler, localAddr: localAddr,
		localIP: localIP, localPort: localPort, state: udpConnecting,
		pending: make(chan *udpPacket, maxUDPQueuePackets),
		done:    make(chan struct{}),
	}
	udpConns.Store(udpConnId{src: localAddr.String()}, conn)
	go conn.run(remoteAddr)
	return conn, nil
}

func (conn *udpConn) run(remoteAddr *net.UDPAddr) {
	defer func() {
		conn.Close()
		udpAdmission.Lock()
		udpAdmission.connections--
		udpAdmission.Unlock()
	}()
	if err := conn.handler.Connect(conn, remoteAddr); err != nil {
		return
	}
	conn.Lock()
	if conn.state == udpClosed {
		conn.Unlock()
		return
	}
	conn.state = udpConnected
	conn.Unlock()

	for {
		select {
		case <-conn.done:
			return
		case pkt := <-conn.pending:
			conn.Lock()
			closed := conn.state == udpClosed
			conn.Unlock()
			if !closed {
				// A send error applies to this packet. Handlers own association
				// expiry and may call Close when their session has ended.
				conn.handler.ReceiveTo(conn, pkt.data, pkt.addr)
			}
			conn.releasePacket(pkt)
			if closed {
				return
			}
		}
	}
}

func (conn *udpConn) LocalAddr() *net.UDPAddr { return conn.localAddr }

// ReceiveTo copies borrowed lwIP data only after both local and aggregate
// admission succeed. The worker invokes all handlers outside lwipMutex.
func (conn *udpConn) ReceiveTo(data []byte, addr *net.UDPAddr) error {
	conn.Lock()
	defer conn.Unlock()
	if conn.state == udpClosed {
		return errors.New("connection closed")
	}
	if len(conn.pending) == cap(conn.pending) || len(data) > maxUDPQueueBytes-conn.pendingBytes {
		return nil
	}
	udpAdmission.Lock()
	if len(data) > maxUDPPendingBytes-udpAdmission.bytes {
		udpAdmission.Unlock()
		return nil
	}
	udpAdmission.bytes += len(data)
	udpAdmission.Unlock()
	conn.pendingBytes += len(data)
	peer := *addr
	peer.IP = append(net.IP(nil), addr.IP...)
	conn.pending <- &udpPacket{data: append([]byte(nil), data...), addr: &peer}
	return nil
}

func (conn *udpConn) releasePacket(pkt *udpPacket) {
	conn.Lock()
	defer conn.Unlock()
	conn.releasePacketLocked(pkt)
}

func (conn *udpConn) releasePacketLocked(pkt *udpPacket) {
	conn.pendingBytes -= len(pkt.data)
	udpAdmission.Lock()
	udpAdmission.bytes -= len(pkt.data)
	udpAdmission.Unlock()
}

func (conn *udpConn) WriteFrom(data []byte, addr *net.UDPAddr) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	// The native pbuf length includes the IP and UDP headers.
	headerLen := 40
	if conn.localAddr.IP.To4() != nil {
		headerLen = 20
	}
	if addr == nil || addr.Port < 0 || addr.Port > 65535 || len(data) > 65535-headerLen-8 {
		return 0, errors.New("invalid UDP response address or length")
	}
	lwipMutex.Lock()
	defer lwipMutex.Unlock()
	conn.Lock()
	defer conn.Unlock()
	if conn.state == udpClosed {
		return 0, errors.New("connection closed")
	}
	remoteIP := C.struct_ip_addr{}
	if err := ipAddrATON(addr.IP.String(), &remoteIP); err != nil {
		return 0, err
	}
	buf := C.pbuf_alloc_reference(unsafe.Pointer(&data[0]), C.u16_t(len(data)), C.PBUF_ROM)
	if buf == nil {
		return 0, errors.New("cannot allocate native UDP buffer")
	}
	defer C.pbuf_free(buf)
	if err := C.udp_sendto(conn.pcb, buf, &conn.localIP, conn.localPort, &remoteIP, C.u16_t(addr.Port)); err != C.ERR_OK {
		return 0, fmt.Errorf("native UDP send failed: %d", int(err))
	}
	return len(data), nil
}

func (conn *udpConn) Close() error {
	lwipMutex.Lock()
	defer lwipMutex.Unlock()
	conn.closeLocked()
	return nil
}

func (conn *udpConn) closeLocked() {
	conn.Lock()
	defer conn.Unlock()
	if conn.state == udpClosed {
		return
	}
	conn.state = udpClosed
	close(conn.done)
	id := udpConnId{src: conn.localAddr.String()}
	if current, ok := udpConns.Load(id); ok && current == conn {
		udpConns.Delete(id)
	}
	for {
		select {
		case pkt := <-conn.pending:
			conn.releasePacketLocked(pkt)
		default:
			return
		}
	}
}
