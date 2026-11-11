package core

import (
	"errors"
	"io"
	"sync"
)

var errTCPReceivePipeFull = errors.New("TCP receive pipe full")

// tcpReceivePipe separates the lwIP producer from the potentially slow reader.
// The producer copies data before lwIP frees its packet. It never waits for a
// reader or for capacity. The caller returns TCP window credit after reading.
// One limit-sized payload array is allocated on first nonempty accepted input
// and reused until the pipe is discarded or finished input has drained.
type tcpReceivePipe struct {
	mu    sync.Mutex
	ready sync.Cond
	limit int
	buf   []byte
	head  int
	size  int
	err   error
}

func newTCPReceivePipe(limit int) *tcpReceivePipe {
	p := &tcpReceivePipe{limit: limit}
	p.ready.L = &p.mu
	return p
}

func (p *tcpReceivePipe) tryWrite(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	if len(data) > p.limit-p.size {
		return errTCPReceivePipeFull
	}
	if len(data) == 0 {
		return nil
	}

	if p.buf == nil {
		p.buf = make([]byte, p.limit)
	}

	tail := (p.head + p.size) % len(p.buf)
	n := copy(p.buf[tail:], data)
	copy(p.buf, data[n:])
	p.size += len(data)
	p.ready.Signal()
	return nil
}

// copyTo copies the oldest len(dst) bytes without consuming them. Caller holds mu.
func (p *tcpReceivePipe) copyTo(dst []byte) {
	n := copy(dst, p.buf[p.head:])
	copy(dst[n:], p.buf)
}

func (p *tcpReceivePipe) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.size == 0 && p.err == nil {
		p.ready.Wait()
	}
	if p.size == 0 {
		return 0, p.err
	}
	n := len(dst)
	if n > p.size {
		n = p.size
	}
	p.copyTo(dst[:n])
	p.head = (p.head + n) % len(p.buf)
	p.size -= n
	if p.size == 0 && p.err != nil {
		p.buf, p.head = nil, 0
	} else if p.size > 0 {
		p.ready.Signal()
	}
	return n, nil
}

func (p *tcpReceivePipe) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = io.EOF
	}
	if p.size == 0 {
		p.buf, p.head = nil, 0
	}
	p.ready.Broadcast()
}

// discard closes the read side and returns the number of unread bytes abandoned.
func (p *tcpReceivePipe) discard() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.size
	p.buf, p.head, p.size = nil, 0, 0
	p.err = io.ErrClosedPipe
	p.ready.Broadcast()
	return n
}
