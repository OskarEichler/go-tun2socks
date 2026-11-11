package redirect

import (
	"net"
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

func TestRedirectUDPRestrictsPeer(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	h := NewUDPHandler(relay.LocalAddr().String(), time.Second).(*udpHandler)
	c := &replyConn{got: make(chan []byte, 4)}
	if err = h.Connect(c, nil); err != nil {
		t.Fatal(err)
	}
	defer h.Close(c)
	if err = h.ReceiveTo(c, []byte("query"), nil); err != nil {
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
	other.WriteToUDP([]byte("wrong peer"), peer)
	relay.WriteToUDP([]byte("answer"), peer)
	select {
	case p := <-c.got:
		if string(p) != "answer" {
			t.Fatalf("forwarded %q", p)
		}
	case <-time.After(time.Second):
		t.Fatal("legitimate response missing")
	}
}
