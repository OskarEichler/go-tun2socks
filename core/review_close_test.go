package core

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestReviewCloseWriteSendsFINBeforeReceiveDrain(t *testing.T) {
	p := newReceiveTestPeer(t, nil)
	p.release()
	data := []byte("final buffered input")
	p.send(25, data)
	if err := p.conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case packet := <-p.output:
			tcp := packet[int(packet[0]&15)*4:]
			if tcp[13]&4 != 0 {
				t.Fatal("reset during graceful close")
			}
			if tcp[13]&1 != 0 {
				p.read(data)
				return
			}
		default:
			t.Fatal("CloseWrite returned without sending FIN while unread data remained")
		}
	}
}

type reviewNotifyUnlock struct {
	sync.Locker
	unlocked chan struct{}
	once sync.Once
}

func (l *reviewNotifyUnlock) Unlock() {
	l.Locker.Unlock()
	l.once.Do(func() { close(l.unlocked) })
}

func TestReviewShutdownWakesBlockedWrite(t *testing.T) {
	for _, mode := range []string{"passive-close", "active-close", "abort"} {
		t.Run(mode, func(t *testing.T) {
			p := newReceiveTestPeerWithWindow(t, nil, 0)
			p.release()
			if mode == "passive-close" {
				p.send(17, nil)
			}
			filled := make(chan error, 1)
			go func() {
				n, err := p.conn.Write(make([]byte, 32768))
				if n != 32768 && err == nil {
					err = io.ErrShortWrite
				}
				filled <- err
			}()
			select {
			case err := <-filled:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("failed to fill lwIP send queue")
			}
			conn := p.conn.(*tcpConn)
			lock := &reviewNotifyUnlock{Locker: conn.canWrite.L, unlocked: make(chan struct{})}
			conn.canWrite.L = lock
			done := make(chan error, 1)
			go func() {
				_, err := conn.Write([]byte{1})
				done <- err
			}()
			select {
			case <-lock.unlocked:
			case <-time.After(time.Second):
				t.Fatal("writer did not reach wait")
			}
			switch mode {
			case "passive-close", "active-close":
				if err := p.conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			case "abort":
				p.conn.Abort()
			}
			select {
			case err := <-done:
				if !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("Write returned %v, want closed pipe", err)
				}
			case <-time.After(250 * time.Millisecond):
				// Release a stranded goroutine before cleaning up the harness.
				conn.canWrite.Broadcast()
				t.Fatal("shutdown left Write blocked")
			}
		})
	}
}
