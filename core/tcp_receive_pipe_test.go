package core

import (
	"bytes"
	"io"
	"testing"
)

func TestTCPReceivePipeGrowthAndCapacity(t *testing.T) {
	const limit = 32768
	p := newTCPReceivePipe(limit)
	if len(p.buf) != 0 {
		t.Fatal("allocated payload storage before receiving data")
	}
	write := func(data []byte) {
		t.Helper()
		if err := p.tryWrite(data); err != nil {
			t.Fatal(err)
		}
	}
	read := func(want []byte) {
		t.Helper()
		buf := make([]byte, len(want))
		if n, err := io.ReadFull(p, buf); err != nil || !bytes.Equal(buf, want) {
			t.Fatalf("read %d bytes, err=%v, data matches=%v", n, err, bytes.Equal(buf, want))
		}
	}

	first := bytes.Repeat([]byte{1}, 1460)
	write(first)
	write(bytes.Repeat([]byte{2}, 34))
	if len(p.buf) != 2048 {
		t.Fatalf("1494 buffered bytes reserved %d bytes, want 2048", len(p.buf))
	}
	read(first)
	// Wrap before growing so both parts of the ring must be preserved.
	wrapped := bytes.Repeat([]byte{3}, 900)
	write(wrapped)
	remaining := bytes.Repeat([]byte{4}, limit-34-len(wrapped))
	write(remaining)
	if len(p.buf) != limit || p.tryWrite([]byte{5}) != errTCPReceivePipeFull {
		t.Fatal("pipe did not refuse input at its limit")
	}
	p.finish()
	read(bytes.Repeat([]byte{2}, 34))
	read(wrapped)
	read(remaining)
	if n, err := p.Read(make([]byte, 1)); n != 0 || err != io.EOF || len(p.buf) != 0 {
		t.Fatalf("drained pipe returned %d, %v and kept %d bytes allocated", n, err, len(p.buf))
	}
}
