package socks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/core"
)

// max IP packet size - min IP header size - min UDP header size - min SOCKS5 header size
const maxUdpPayloadSize = 65535 - 20 - 8 - 7

type udpHandler struct {
	sync.Mutex

	proxyHost   string
	proxyPort   uint16
	udpConns    map[core.UDPConn]*net.UDPConn
	tcpConns    map[core.UDPConn]net.Conn
	remoteAddrs map[core.UDPConn]*net.UDPAddr // UDP relay server addresses
	timeout     time.Duration
}

func NewUDPHandler(proxyHost string, proxyPort uint16, timeout time.Duration) core.UDPConnHandler {
	return &udpHandler{
		proxyHost:   proxyHost,
		proxyPort:   proxyPort,
		udpConns:    make(map[core.UDPConn]*net.UDPConn, 8),
		tcpConns:    make(map[core.UDPConn]net.Conn, 8),
		remoteAddrs: make(map[core.UDPConn]*net.UDPAddr, 8),
		timeout:     timeout,
	}
}

func (h *udpHandler) handleTCP(conn core.UDPConn, c net.Conn) {
	buf := core.NewBytes(core.BufSize)

	defer func() {
		h.Close(conn)
		core.FreeBytes(buf)
	}()

	for {
		c.SetDeadline(time.Time{})
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

func (h *udpHandler) fetchUDPInput(conn core.UDPConn, input *net.UDPConn) {
	buf := make([]byte, 65535)

	defer func() {
		h.Close(conn)
	}()

	for {
		input.SetDeadline(time.Now().Add(h.timeout))
		n, err := input.Read(buf)
		if err != nil {
			return
		}
		addr, payload, err := parseUDPResponse(buf[:n])
		if err != nil {
			continue
		}
		resolvedAddr, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			continue
		}
		_, err = conn.WriteFrom(payload, resolvedAddr)
		if err != nil {
			log.Warnf("write local failed: %v", err)
			return
		}
	}
}

func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		return h.connectInternal(conn, "")
	}
	return h.connectInternal(conn, target.String())
}

const udpHandshakeTimeout = 4 * time.Second

// A UDP association uses one negotiated TCP control connection and a
// connected UDP socket whose kernel receive filter pins the relay endpoint.
func (h *udpHandler) connectInternal(conn core.UDPConn, dest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), udpHandshakeTimeout)
	defer cancel()
	dialer := net.Dialer{}
	c, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(h.proxyHost, strconv.Itoa(int(h.proxyPort))))
	if err != nil {
		return err
	}
	var pc *net.UDPConn
	published := false
	defer func() {
		if !published {
			c.Close()
			if pc != nil {
				pc.Close()
			}
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.Copy(c, bytes.NewReader([]byte{5, 1, 0})); err != nil {
		return err
	}
	buf := make([]byte, MaxAddrLen)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 5 || buf[1] != 0 {
		return errors.New("SOCKS proxy did not accept no-authentication method")
	}
	if _, err := io.Copy(c, bytes.NewReader([]byte{5, socks5UDPAssociate, 0, 1, 0, 0, 0, 0, 0, 0})); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, buf[:3]); err != nil {
		return err
	}
	if buf[0] != 5 || buf[1] != 0 || buf[2] != 0 {
		return errors.New("invalid SOCKS UDP association response")
	}
	remoteAddr, err := readAddr(c, buf)
	if err != nil {
		return err
	}
	// readAddr also supports historical extended address flags for other
	// callers. A standard UDP association accepts only RFC 1928 types.
	if remoteAddr[0] != socks5IP4 && remoteAddr[0] != socks5IP6 && remoteAddr[0] != socks5Domain {
		return errors.New("unsupported SOCKS relay address type")
	}
	if remoteAddr[0] == socks5Domain && remoteAddr[1] == 0 {
		return errors.New("empty SOCKS relay domain")
	}
	relay, err := resolveUDPRelay(ctx, remoteAddr)
	if err != nil {
		return err
	}
	if relay.Port == 0 {
		return errors.New("invalid SOCKS relay address")
	}
	if relay.IP.IsUnspecified() {
		peer := c.RemoteAddr().(*net.TCPAddr)
		relay.IP = append(net.IP(nil), peer.IP...)
		relay.Zone = peer.Zone
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pc, err = net.DialUDP("udp", nil, relay)
	if err != nil {
		return err
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return err
	}
	h.Lock()
	h.tcpConns[conn], h.udpConns[conn], h.remoteAddrs[conn] = c, pc, relay
	h.Unlock()
	published = true
	go h.handleTCP(conn, c)
	go h.fetchUDPInput(conn, pc)
	log.Infof("new proxy connection to %v", dest)
	return nil
}

func resolveUDPRelay(ctx context.Context, addr Addr) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, errors.New("SOCKS relay has no address")
		}
		ip = addresses[0].IP
		for _, candidate := range addresses {
			if candidate.IP.To4() != nil {
				ip = candidate.IP
				break
			}
		}
	}
	return &net.UDPAddr{IP: ip, Port: number}, nil
}

func parseUDPResponse(packet []byte) (Addr, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, nil, errors.New("invalid SOCKS UDP framing")
	}
	switch packet[3] {
	case socks5IP4, socks5IP6:
	case socks5Domain:
		if len(packet) < 5 || packet[4] == 0 {
			return nil, nil, errors.New("invalid SOCKS UDP domain")
		}
	default:
		return nil, nil, errors.New("unsupported SOCKS UDP address type")
	}
	addr := SplitAddr(packet[3:])
	if addr == nil {
		return nil, nil, errors.New("short SOCKS UDP address")
	}
	return addr, packet[3+len(addr):], nil
}

func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) error {
	h.Lock()
	pc, ok1 := h.udpConns[conn]
	_, ok2 := h.remoteAddrs[conn]
	h.Unlock()

	if ok1 && ok2 {
		address := ParseAddr(addr.String())
		if address == nil {
			return errors.New("invalid SOCKS UDP destination")
		}
		buf := append([]byte{0, 0, 0}, address...)
		buf = append(buf, data[:]...)
		_, err := pc.Write(buf)
		if err != nil {
			h.Close(conn)
			return errors.New(fmt.Sprintf("write remote failed: %v", err))
		}
		return nil
	} else {
		h.Close(conn)
		return errors.New(fmt.Sprintf("proxy connection %v->%v does not exists", conn.LocalAddr(), addr))
	}
}

func (h *udpHandler) Close(conn core.UDPConn) {
	conn.Close()

	h.Lock()
	defer h.Unlock()

	if c, ok := h.tcpConns[conn]; ok {
		c.Close()
		delete(h.tcpConns, conn)
	}
	if pc, ok := h.udpConns[conn]; ok {
		pc.Close()
		delete(h.udpConns, conn)
	}
	delete(h.remoteAddrs, conn)
}
