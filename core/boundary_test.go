package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIPHeaderValidation(t *testing.T) {
	for _, version := range []ipver{ipv4, ipv6} {
		minimum := 20
		if version == ipv6 {
			minimum = 40
		}
		for size := 0; size < minimum; size++ {
			p := make([]byte, size)
			if size > 0 {
				p[0] = byte(version << 4)
			}
			if _, err := peekNextProto(version, p); err == nil {
				t.Fatalf("accepted truncated IPv%d header of %d bytes", version, size)
			}
		}
	}
	for _, ihl := range []byte{5, 6, 15} {
		p := make([]byte, int(ihl)*4+8)
		p[0], p[9] = 0x40|ihl, 17
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		if got, err := peekNextProto(ipv4, p); got != proto_udp || err != nil {
			t.Fatalf("valid IPv4 options rejected: %d, %v", got, err)
		}
		p[0] = 0x44
		if _, err := peekNextProto(ipv4, p); err == nil {
			t.Fatal("accepted invalid IHL")
		}
	}
	p := make([]byte, 48)
	p[0], p[6] = 0x60, 17
	binary.BigEndian.PutUint16(p[4:6], 8)
	if got, err := peekNextProto(ipv6, p); got != proto_udp || err != nil {
		t.Fatalf("valid IPv6 rejected: %d %v", got, err)
	}
	binary.BigEndian.PutUint16(p[4:6], 9)
	if _, err := peekNextProto(ipv6, p); err == nil {
		t.Fatal("accepted truncated IPv6 payload")
	}
	if _, err := peekNextProto(ipv4, make([]byte, 65536)); err == nil {
		t.Fatal("accepted native length overflow")
	}
}

type boundaryUDPHandler struct {
	connect func(UDPConn, *net.UDPAddr) error
	receive func(UDPConn, []byte, *net.UDPAddr) error
}

func (h boundaryUDPHandler) Connect(c UDPConn, a *net.UDPAddr) error {
	if h.connect != nil {
		return h.connect(c, a)
	}
	return nil
}
func (h boundaryUDPHandler) ReceiveTo(c UDPConn, p []byte, a *net.UDPAddr) error {
	if h.receive != nil {
		return h.receive(c, p, a)
	}
	return nil
}

func udpBoundaryPacket(port uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], []byte{172, 16, 5, 1})
	copy(p[16:20], []byte{198, 51, 100, 1})
	binary.BigEndian.PutUint16(p[20:], port)
	binary.BigEndian.PutUint16(p[22:], 53)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

func waitUDPIdle(t *testing.T) {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		udpAdmission.Lock()
		conns, size := udpAdmission.connections, udpAdmission.bytes
		udpAdmission.Unlock()
		if conns == 0 && size == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("UDP admission was not released")
}

func boundaryUDPStack(t *testing.T, h UDPConnHandler) LWIPStack {
	t.Helper()
	waitUDPIdle(t)
	RegisterUDPConnHandler(h)
	s := NewLWIPStack()
	t.Cleanup(func() { s.Close(); waitUDPIdle(t) })
	return s
}

func TestUDPSynchronousResponseAndClose(t *testing.T) {
	output := make(chan []byte, 4)
	RegisterOutputFn(func(p []byte) (int, error) {
		output <- append([]byte(nil), p...)
		return len(p), nil
	})
	errs := make(chan error, 1)
	s := boundaryUDPStack(t, boundaryUDPHandler{receive: func(c UDPConn, p []byte, a *net.UDPAddr) error {
		_, err := c.WriteFrom(p, a)
		errs <- err
		return err
	}})
	if _, err := s.Write(udpBoundaryPacket(31000, []byte("ordinary DNS response"))); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errs:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("synchronous UDP response deadlocked")
	}
	select {
	case packet := <-output:
		if !bytes.Contains(packet, []byte("ordinary DNS response")) {
			t.Fatal("response payload missing")
		}
	case <-time.After(time.Second):
		t.Fatal("no native UDP output")
	}
	s.Close()
	s.Close()
	if _, err := s.Write(udpBoundaryPacket(31001, []byte{1})); err == nil {
		t.Fatal("closed stack accepted input")
	}
}

func TestUDPConnectionAndByteAdmission(t *testing.T) {
	release := make(chan struct{})
	s := boundaryUDPStack(t, boundaryUDPHandler{connect: func(UDPConn, *net.UDPAddr) error {
		<-release
		return errors.New("done")
	}})
	defer close(release)
	payload := make([]byte, 8192)
	for i := 0; i < maxUDPConnections+1; i++ {
		if _, err := s.Write(udpBoundaryPacket(uint16(32000+i), payload)); err != nil {
			t.Fatal(err)
		}
	}
	udpAdmission.Lock()
	conns, size := udpAdmission.connections, udpAdmission.bytes
	udpAdmission.Unlock()
	if conns != maxUDPConnections || size != maxUDPPendingBytes {
		t.Fatalf("admission = %d sessions / %d bytes", conns, size)
	}
	s.Write(udpBoundaryPacket(32000, payload))
	udpAdmission.Lock()
	after := udpAdmission.bytes
	udpAdmission.Unlock()
	if after != size {
		t.Fatal("aggregate byte limit exceeded")
	}
	s.Close()
	udpAdmission.Lock()
	conns, size = udpAdmission.connections, udpAdmission.bytes
	udpAdmission.Unlock()
	if conns != maxUDPConnections || size != 0 {
		t.Fatalf("closed connecting workers = %d sessions / %d bytes", conns, size)
	}
}

func TestUDPCloseDuringConnectAndReplacement(t *testing.T) {
	release := make(chan struct{})
	first := make(chan UDPConn, 1)
	var calls int32
	var releaseOnce sync.Once
	s := boundaryUDPStack(t, boundaryUDPHandler{connect: func(c UDPConn, _ *net.UDPAddr) error {
		first <- c
		<-release
		return nil
	}, receive: func(UDPConn, []byte, *net.UDPAddr) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}})
	defer releaseOnce.Do(func() { close(release) })
	s.Write(udpBoundaryPacket(35000, []byte{1}))
	old := <-first
	old.Close()
	s.Write(udpBoundaryPacket(35000, []byte{2}))
	current := <-first
	old.Close()
	id := udpConnId{src: old.LocalAddr().String()}
	stored, ok := udpConns.Load(id)
	if !ok || stored != current {
		t.Fatal("stale close removed replacement")
	}
	current.Close()
	// Close must win over successful Connect completion.
	releaseOnce.Do(func() { close(release) })
	waitUDPIdle(t)
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatal("closed connection dispatched queued data")
	}
}

func TestTCPAbortIsIdempotent(t *testing.T) {
	p := newReceiveTestPeer(t, nil)
	p.conn.Abort()
	p.conn.Abort()
	if _, ok := tcpConns.Load(p.conn.(*tcpConn).connKey); ok {
		t.Fatal("aborted TCP connection retained callback identity")
	}
}

func TestUDPTransientSendErrorKeepsAssociation(t *testing.T) {
	output := make(chan []byte, 4)
	RegisterOutputFn(func(p []byte) (int, error) { output <- append([]byte(nil), p...); return len(p), nil })
	first := make(chan UDPConn, 1)
	var calls int32
	s := boundaryUDPStack(t, boundaryUDPHandler{receive: func(c UDPConn, p []byte, a *net.UDPAddr) error {
		if atomic.AddInt32(&calls, 1) == 1 {
			first <- c
			return errors.New("transient send failure")
		}
		_, err := c.WriteFrom(p, a)
		return err
	}})
	s.Write(udpBoundaryPacket(36000, []byte("first")))
	c := <-first
	s.Write(udpBoundaryPacket(36000, []byte("retry")))
	select {
	case p := <-output:
		if !bytes.Contains(p, []byte("retry")) {
			t.Fatal("retry reply missing")
		}
	case <-time.After(time.Second):
		t.Fatal("transient error poisoned response association")
	}
	stored, ok := udpConns.Load(udpConnId{src: c.LocalAddr().String()})
	if !ok || stored != c {
		t.Fatal("transient error replaced association identity")
	}
}

func TestUDPRepliesSerializeWithInputAndClose(t *testing.T) {
	RegisterOutputFn(func(p []byte) (int, error) { return len(p), nil })
	accepted := make(chan UDPConn, 1)
	s := boundaryUDPStack(t, boundaryUDPHandler{connect: func(c UDPConn, _ *net.UDPAddr) error { accepted <- c; return nil }})
	s.Write(udpBoundaryPacket(37000, []byte{1}))
	c := <-accepted
	var wg sync.WaitGroup
	wg.Add(4)
	for i := 0; i < 3; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.WriteFrom([]byte{1}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53})
			}
		}()
	}
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			s.Write(udpBoundaryPacket(37000, []byte{1}))
		}
	}()
	s.Close()
	wg.Wait()
	if _, err := c.WriteFrom([]byte{1}, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53}); err == nil {
		t.Fatal("closed UDP conn sent through released PCB")
	}
}
