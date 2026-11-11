package socks

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eycorsican/go-tun2socks/core"
)

type replyConn struct {
	core.UDPConn
	got chan []byte
}

func (c *replyConn) LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 31000}
}
func (c *replyConn) Close() error { return nil }
func (c *replyConn) WriteFrom(p []byte, _ *net.UDPAddr) (int, error) {
	c.got <- append([]byte(nil), p...)
	return len(p), nil
}

func TestSOCKSUDPFraming(t *testing.T) {
	valid := append([]byte{0, 0, 0}, ParseAddr("127.0.0.1:53")...)
	valid = append(valid, []byte("answer")...)
	addr, payload, err := parseUDPResponse(valid)
	if err != nil || addr.String() != "127.0.0.1:53" || !bytes.Equal(payload, []byte("answer")) {
		t.Fatalf("valid response: %v %q %v", addr, payload, err)
	}
	for _, packet := range [][]byte{
		nil, {0, 0, 0}, {1, 0, 0, 1}, {0, 1, 0, 1}, {0, 0, 1, 1},
		{0, 0, 0, 9, 127, 0, 0, 1, 0, 53}, {0, 0, 0, 3, 0, 0, 53}, {0, 0, 0, 1, 127},
	} {
		if _, _, err := parseUDPResponse(packet); err == nil {
			t.Fatalf("accepted invalid framing %v", packet)
		}
	}
}

func TestSOCKSUDPRelayPeerAndWildcardBind(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	control, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	stop := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(stop) })
	serverErr := make(chan error, 1)
	go func() {
		c, err := control.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 10)
		if _, err = io.ReadFull(c, buf[:3]); err == nil {
			_, err = c.Write([]byte{5, 0})
		}
		if err == nil {
			_, err = io.ReadFull(c, buf)
		}
		if err == nil {
			reply := append([]byte{5, 0, 0}, ParseAddr((&net.UDPAddr{IP: net.IPv4zero, Port: relay.LocalAddr().(*net.UDPAddr).Port}).String())...)
			_, err = c.Write(reply)
		}
		serverErr <- err
		<-stop
	}()
	a := control.Addr().(*net.TCPAddr)
	h := NewUDPHandler("127.0.0.1", uint16(a.Port), time.Second).(*udpHandler)
	c := &replyConn{got: make(chan []byte, 4)}
	if err = h.Connect(c, nil); err != nil {
		t.Fatal(err)
	}
	defer h.Close(c)
	if err = <-serverErr; err != nil {
		t.Fatal(err)
	}
	if err = h.ReceiveTo(c, []byte("query"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 128)
	relay.SetReadDeadline(time.Now().Add(time.Second))
	_, peer, err := relay.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	frame := append([]byte{0, 0, 0}, ParseAddr("127.0.0.1:53")...)
	other.WriteToUDP(append(append([]byte(nil), frame...), []byte("wrong peer")...), peer)
	relay.WriteToUDP(append(append([]byte(nil), frame...), []byte("answer")...), peer)
	select {
	case got := <-c.got:
		if string(got) != "answer" {
			t.Fatalf("forwarded %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("legitimate relay response missing")
	}
}

func TestSOCKSHandshakeTimeoutClosesControl(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(udpHandshakeTimeout + 2*time.Second))
		header := make([]byte, 3)
		if _, err = io.ReadFull(c, header); err == nil {
			_, err = c.Read(make([]byte, 1))
		}
		closed <- err
	}()
	h := NewUDPHandler("127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port), time.Second).(*udpHandler)
	c := &replyConn{got: make(chan []byte, 1)}
	start := time.Now()
	if err = h.Connect(c, nil); err == nil {
		t.Fatal("handshake without reply succeeded")
	}
	if time.Since(start) > udpHandshakeTimeout+time.Second {
		t.Fatal("handshake exceeded deadline")
	}
	if err = <-closed; err != io.EOF {
		t.Fatalf("failed handshake left TCP open: %v", err)
	}
	if len(h.tcpConns) != 0 || len(h.udpConns) != 0 {
		t.Fatal("failed association was published")
	}
}

func TestSOCKSRelayResolutionUsesDeadline(t *testing.T) {
	old := net.DefaultResolver
	defer func() { net.DefaultResolver = old }()
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := resolveUDPRelay(ctx, ParseAddr("relay.invalid:1234")); err == nil {
		t.Fatal("unresolved relay succeeded")
	}
	if ctx.Err() == nil {
		t.Fatal("resolver did not observe handshake deadline")
	}
}
