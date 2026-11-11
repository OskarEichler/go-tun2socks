package dnsfallback

import (
	"net"
	"testing"

	"github.com/eycorsican/go-tun2socks/core"
)

type completedDNS struct {
	core.UDPConn
	response []byte
	closed   bool
}

func (c *completedDNS) WriteFrom(p []byte, _ *net.UDPAddr) (int, error) {
	c.response = append([]byte(nil), p...)
	return len(p), nil
}
func (c *completedDNS) Close() error { c.closed = true; return nil }

func TestTruncatedDNSCompletesAssociation(t *testing.T) {
	c := &completedDNS{}
	query := make([]byte, 12)
	query[5] = 1
	h := NewUDPHandler()
	if err := h.ReceiveTo(c, query, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	if !c.closed || len(c.response) != 12 || c.response[2]&0x82 != 0x82 {
		t.Fatal("DNS response did not finish its association")
	}
}
