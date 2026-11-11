package core

import (
	"bytes"
	"io"
	"testing"
)

func TestTCPReceivePipeLazyAllocationAndCapacity(t *testing.T) {
	const limit = 32768
	p := newTCPReceivePipe(limit)
	if len(p.buf) != 0 {
		t.Fatal("allocated payload storage before receiving data")
	}
	if err := p.tryWrite(nil); err != nil || len(p.buf) != 0 {
		t.Fatal("empty input allocated receive storage")
	}
	if err := p.tryWrite(make([]byte, limit+1)); err != errTCPReceivePipeFull || len(p.buf) != 0 {
		t.Fatal("oversized input allocated receive storage")
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
	if len(p.buf) != limit {
		t.Fatalf("first input reserved %d bytes, want %d", len(p.buf), limit)
	}
	storage := &p.buf[0]
	write(bytes.Repeat([]byte{2}, 34))
	read(first)
	// Fill the queue with a nonzero head, then read across the ring boundary.
	wrapped := bytes.Repeat([]byte{3}, 900)
	write(wrapped)
	remaining := bytes.Repeat([]byte{4}, limit-34-len(wrapped))
	write(remaining)
	if len(p.buf) != limit || p.tryWrite([]byte{5}) != errTCPReceivePipeFull {
		t.Fatal("pipe did not refuse input at its limit")
	}
	if &p.buf[0] != storage {
		t.Fatal("receive storage changed after the first input")
	}
	p.finish()
	read(bytes.Repeat([]byte{2}, 34))
	read(wrapped)
	read(remaining)
	if n, err := p.Read(make([]byte, 1)); n != 0 || err != io.EOF || len(p.buf) != 0 {
		t.Fatalf("drained pipe returned %d, %v and kept %d bytes allocated", n, err, len(p.buf))
	}
	if err := p.tryWrite([]byte{6}); err != io.EOF || len(p.buf) != 0 {
		t.Fatal("finished pipe accepted input or allocated receive storage again")
	}
}

func TestTCPReceivePipeSteadyStateAllocations(t *testing.T) {
	p := newTCPReceivePipe(32768)
	payload, output := make([]byte, 1460), make([]byte, 1460)
	var writeErr, readErr error
	var n int
	allocations := testing.AllocsPerRun(100, func() {
		writeErr = p.tryWrite(payload)
		n, readErr = p.Read(output)
	})
	if writeErr != nil || readErr != nil || n != len(payload) {
		t.Fatalf("round trip: write=%v, read=%d/%v", writeErr, n, readErr)
	}
	if allocations != 0 {
		t.Fatalf("steady-state allocations per write/read = %v, want 0", allocations)
	}
}

func BenchmarkTCPReceivePipe(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{{"small-flow", 1494}, {"full-window", 32768}} {
		b.Run(tc.name, func(b *testing.B) {
			payload, output := make([]byte, tc.size), make([]byte, tc.size)
			b.ReportAllocs()
			b.SetBytes(int64(tc.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p := newTCPReceivePipe(32768)
				for start := 0; start < len(payload); {
					end := start + 1460
					if end > len(payload) {
						end = len(payload)
					}
					if err := p.tryWrite(payload[start:end]); err != nil {
						b.Fatal(err)
					}
					start = end
				}
				if n, err := p.Read(output); n != len(payload) || err != nil {
					b.Fatalf("read = %d, %v", n, err)
				}
				p.finish()
			}
		})
	}
}
