package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type receiveTestHandler struct {
	accepted chan net.Conn
	release  chan struct{}
	err      error
}

func (h *receiveTestHandler) Handle(c net.Conn, _ *net.TCPAddr) error {
	h.accepted <- c
	<-h.release
	return h.err
}

type receiveTestPeer struct {
	t       *testing.T
	stack   LWIPStack
	conn    TCPConn
	output  chan []byte
	seq     uint32
	ack     uint32
	release func()
	closed  bool
}

// Drive the actual lwIP callbacks, including refused_data and window accounting.
// These tests must be serial: the stack and registered callbacks are global.
func newReceiveTestPeer(t *testing.T, dialErr error) *receiveTestPeer {
	t.Helper()
	h := &receiveTestHandler{make(chan net.Conn, 1), make(chan struct{}), dialErr}
	RegisterTCPConnHandler(h)
	p := &receiveTestPeer{t: t, output: make(chan []byte, 256), seq: 100}
	RegisterOutputFn(func(b []byte) (int, error) {
		p.output <- append([]byte(nil), b...)
		return len(b), nil
	})
	p.stack = NewLWIPStack()
	var once sync.Once
	p.release = func() { once.Do(func() { close(h.release) }) }
	t.Cleanup(func() {
		p.release()
		if !p.closed {
			p.stack.Close()
		}
	})
	p.send(2, nil)
	select {
	case syn := <-p.output:
		header := int(syn[0]&15) * 4
		p.ack = binary.BigEndian.Uint32(syn[header+4:]) + 1
	case <-time.After(time.Second):
		t.Fatal("no SYN-ACK")
	}
	p.send(16, nil)
	select {
	case c := <-h.accepted:
		p.conn = c.(TCPConn)
	case <-time.After(time.Second):
		t.Fatal("handler did not receive connection")
	}
	return p
}

func (p *receiveTestPeer) send(flags byte, data []byte) {
	p.t.Helper()
	b := make([]byte, 40+len(data))
	b[0], b[8], b[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[12:16], []byte{172, 16, 9, 1})
	copy(b[16:20], []byte{198, 51, 100, 1})
	tcp := b[20:]
	binary.BigEndian.PutUint16(tcp, 40001)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], p.seq)
	binary.BigEndian.PutUint32(tcp[8:], p.ack)
	tcp[12], tcp[13] = 5<<4, flags
	binary.BigEndian.PutUint16(tcp[14:], 32768)
	copy(tcp[20:], data)
	// Input checksum verification is disabled in this library's lwipopts.h.
	done := make(chan error, 1)
	go func() { _, err := p.stack.Write(b); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			p.t.Fatal(err)
		}
	case <-time.After(time.Second):
		p.t.Fatal("packet input blocked on an unread connection")
	}
	p.seq += uint32(len(data))
	if flags&3 != 0 {
		p.seq++
	}
}

func (p *receiveTestPeer) read(want []byte) {
	p.t.Helper()
	done := make(chan error, 1)
	go func() {
		got := make([]byte, len(want))
		_, err := io.ReadFull(p.conn, got)
		if err == nil && !bytes.Equal(got, want) {
			err = errors.New("received bytes out of order or corrupted")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			p.t.Fatal(err)
		}
	case <-time.After(180 * time.Millisecond):
		p.t.Fatal("early segments were not delivered without retransmission")
	}
}

func TestTCPBuffersDataWhileDialing(t *testing.T) {
	for _, tc := range []struct {
		name string
		fin  bool
	}{{"segmented", false}, {"fin", true}} {
		t.Run(tc.name, func(t *testing.T) {
			p := newReceiveTestPeer(t, nil)
			first, tail := bytes.Repeat([]byte{'A'}, 1460), bytes.Repeat([]byte{'B'}, 34)
			p.send(24, first)
			flags := byte(24)
			if tc.fin {
				flags |= 1
			}
			p.send(flags, tail)
			p.release()
			p.read(append(first, tail...))
			if tc.fin {
				if _, err := p.conn.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("read after buffered FIN = %v, want EOF", err)
				}
			}
		})
	}
}

func TestTCPReceiveWindowAndRingWrap(t *testing.T) {
	p := newReceiveTestPeer(t, nil)
	payload := make([]byte, 65536)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	send := func(start, end int) {
		for start < end {
			n := end - start
			if n > 1460 {
				n = 1460
			}
			p.send(24, payload[start:start+n])
			start += n
		}
	}
	send(0, 32768)
	deadline := time.After(time.Second)
	for {
		select {
		case ack := <-p.output:
			header := int(ack[0]&15) * 4
			if binary.BigEndian.Uint32(ack[header+8:]) == p.seq && binary.BigEndian.Uint16(ack[header+14:]) == 0 {
				goto full
			}
		case <-deadline:
			t.Fatal("unread receive window did not close at 32 KiB")
		}
	}
full:
	p.release()
	p.read(payload[:10000])
	// Refill before draining to exercise a wrap with unread bytes in the ring.
	send(32768, 42768)
	p.read(payload[10000:42768])
	send(42768, len(payload))
	p.read(payload[42768:])
}

func TestTCPReceiveCloseUnblocksReader(t *testing.T) {
	for _, mode := range []string{"reset", "dial-error", "close-read", "abort", "stack-close"} {
		t.Run(mode, func(t *testing.T) {
			var dialErr error
			if mode == "dial-error" {
				dialErr = errors.New("simulated dial failure")
			}
			p := newReceiveTestPeer(t, dialErr)
			done := make(chan error, 1)
			go func() { _, err := p.conn.Read(make([]byte, 1)); done <- err }()
			switch mode {
			case "reset":
				p.send(20, nil)
			case "dial-error":
				p.release()
			case "close-read":
				p.conn.CloseRead()
			case "abort":
				p.conn.Abort()
			case "stack-close":
				p.stack.Close()
				// Unmodified Close is not idempotent; avoid a second stack close.
				p.closed = true
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("reader closed without an error")
				}
			case <-time.After(time.Second):
				t.Fatal("reader did not unblock")
			}
		})
	}
}

func TestTCPReceiveCloseDiscardsBufferedData(t *testing.T) {
	for _, mode := range []string{"reset", "close-read", "abort"} {
		t.Run(mode, func(t *testing.T) {
			p := newReceiveTestPeer(t, nil)
			p.send(24, []byte("buffered while dialing"))
			switch mode {
			case "reset":
				p.send(20, nil)
			case "close-read":
				p.conn.CloseRead()
			case "abort":
				p.conn.Abort()
			}
			if n, err := p.conn.Read(make([]byte, 32)); n != 0 || err == nil {
				t.Fatalf("read after %s = %d, %v; want no bytes and a close error", mode, n, err)
			}
		})
	}
}
