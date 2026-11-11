# TCP data flow and backpressure

This document first describes the original receive path at
[`301549c`](https://github.com/OutlineFoundation/go-tun2socks/tree/301549c435ff1ca8fc353bee3763ae639c727b89),
then the buffered path and the contracts that must survive changes to it.
The scope is the TCP receive pipe and its native integration. UDP has a
separate queue and overload policy.

## Entry points and ownership

The application registers a TCP handler, UDP handler and output function, then
feeds IP packets to `LWIPStack.Write`. Registration and the connection maps are
process-global; stack instances are not independent network namespaces.
Configure callbacks before starting packet processing.

| Owner | Responsibility |
| --- | --- |
| `lwipStack` / `lwipMutex` | Serialize native input, timeout dispatch, TCP/UDP native sends and teardown. |
| `tcpConn` | Associate the native PCB with a Go connection; own connection state, native receive credit, write-side flow control and close/abort handling. |
| `tcpReceivePipe` | Own copied receive bytes, capacity, FIFO order, reader wakeups and EOF/discard state. |
| TCP handler | Establish the remote transport and relay bytes through `TCPConn.Read` / `Write`; close each direction when done. |
| Output function | Consume or copy an outgoing IP packet before returning. |

`TCPConn.LocalAddr` is the client/TUN endpoint; `RemoteAddr` is the requested
destination. `Read` consumes client input; `Write` generates packets toward the
client. `newTCPConn` calls the handler in a goroutine so dialing does not itself
hold the native lock. A successful handler completion changes `tcpConnecting`
only if the connection has not already advanced to another state.

## Original receive path

```text
LWIPStack.Write
  -> input acquires lwipMutex
  -> native IP/TCP input
  -> tcpRecvFn
  -> tcpConn.Receive
  -> synchronous io.Pipe.Write
  -> handler's TCPConn.Read
```

All native TCP callbacks execute under `lwipMutex`. The original
`tcpConn.receiveCheck` rejects data during `tcpConnecting` with `ERR_CONN`,
before reaching the pipe. lwIP keeps refused input in `pcb.refused_data`.
When it remains refused, `tcp_in.c` can drop later data segments for TCP retry.
For example, a 1,460-byte segment followed by 34 bytes during dialing can require
a retransmission even after the remote transport becomes ready. The original
packet path is not an unbounded early-data queue.

After connecting, `Receive` writes synchronously to `io.Pipe`, then calls
`tcp_recved` for the consumed bytes. If the consumer is slow, the pipe write
waits inside the native callback while holding `lwipMutex`. Other connections'
input and native timeout dispatch require the same lock. This extends a
connection's backpressure to the shared stack.

The original EOF path also checks connection state before reading the pipe.
Buffering must make EOF mean that the queued bytes have drained, rather than
returning EOF merely because FIN has changed the connection state.

## Buffered receive path

```text
LWIPStack.Write holds lwipMutex
  -> native TCP input -> tcpRecvFn -> tcpConn.Receive
  -> receivePipe.tryWrite copies borrowed bytes, then returns

handler's TCPConn.Read
  -> receivePipe.Read copies into the caller's slice
  -> release the pipe mutex
  -> acquire lwipMutex, check PCB lifetime, return tcp_recved credit
```

Data is accepted in `tcpConnecting`, `tcpConnected` and `tcpWriteClosed`.
Acceptance is all-or-nothing for a callback. The pipe does not wait for a reader
or for capacity; it holds its mutex only around queue operations. The producer
copies bytes before `tcpRecvFn` frees its pbuf or temporary flattening buffer.
The pipe cannot retain a borrowed slice into native packet memory.

The queue limit comes from `C.TCP_WND`, currently 32 KiB in
[`lwipopts.h`](../core/c/custom/lwipopts.h). Copying into the queue does not return
receive credit. Only consuming bytes through `TCPConn.Read` returns credit, under
the native lock and while the PCB is still live. Unread input therefore closes
the advertised receive window and pauses that TCP sender.

If the pipe cannot accept a callback, `Receive` returns `LWIP_ERR_CONN`.
`tcpRecvFn` returns native `ERR_CONN` without freeing that pbuf; lwIP retains it
for retry. The callback accepts no partial payload and does not acknowledge and
silently discard application bytes. TCP can still drop/retransmit packets that
fall outside its window or arrive while refused data remains.

### Receive-buffer allocation policy

Each connection owns its pipe state and ring; rings are not shared across
connections. Payload storage is lazy: no receive data means no ring array.
The first nonempty input that fits allocates one `TCP_WND`-sized array, currently
32 KiB. Empty or rejected oversized input does not allocate that array. All
subsequent reads, writes and ring wrap reuse the same storage; there is no
growth, compaction or replacement array. After closure releases the array,
further writes return the stored terminal error and cannot allocate it again.

This allocates payload storage once per connection, in exchange for reserving
more memory for small flows. A 1,460 + 34 byte handshake now reserves
32 KiB as soon as its first segment arrives; the earlier growth policy initially
reserved 2 KiB for that case. A connection that never receives data still
allocates no payload array. Filling the entire window no longer allocates or
copies intermediate growth arrays. The per-connection pipe/condition state is
additional to this one payload allocation.

Retained ring payload is bounded by `N * TCP_WND` for `N` connections, in addition
to connection state, native packet buffers and consumer-owned buffers. Releasing
the array reference makes it eligible for GC; it is not a synchronous release to
the operating system. This is not an aggregate TCP memory limit or a claim that
the whole packet path is allocation-free. The existing chained-pbuf path can
borrow/allocate scratch space to flatten native packets.

## Lock and wait contracts

| Operation | Locks and waiting |
| --- | --- |
| Native TCP callbacks | Enter with `lwipMutex`; connection state and pipe mutations take their own short-lived mutexes. |
| Pipe `Read` | Wait for data/closure using the pipe condition variable, which releases the pipe mutex while waiting. It holds no native lock. |
| Return receive credit | Release the pipe mutex before acquiring `lwipMutex`, then inspect connection state before touching the PCB. |
| TCP `Write` | Hold `lwipMutex` for native sends; the write condition releases that mutex while waiting for send capacity. |
| Close / abort | Acquire `lwipMutex` before connection and pipe locks; detach callbacks before releasing callback identity or native ownership. |

Do not hold the pipe mutex while acquiring `lwipMutex`: native callbacks and
shutdown acquire them in the opposite order. A pipe reader can finish copying
just before concurrent close/reset; the receive-credit lifetime check prevents
using a released PCB in that case.

The output callback also runs synchronously under the native lock. It must
consume/copy borrowed bytes before returning and must not reenter stack or
connection operations that acquire `lwipMutex`. It can itself block native
progress; receive buffering does not remove that separate output boundary.
An embedding application must unblock any waiting output callback before
waiting for stack shutdown. The Outline SDK does this by closing its device
completion channel before `stack.Close`.

## Lifecycle and the two directions

| Event | Receive queue and native lifetime |
| --- | --- |
| Peer FIN, including while dialing | Finish the pipe; retain queued bytes until they drain, then return EOF. The response direction can remain open. |
| `CloseWrite` | End response writes and send FIN. Preserve receive bytes; when both directions have ended, hand native closing to lwIP without turning unread Go-buffered bytes into a reset. |
| `CloseRead` | Discard unread input, wake readers with a closed-pipe error, and return credit for the discarded bytes if the PCB is live. |
| Reset / handler dial error / abort | Discard input and wake readers/writers. On explicit abort, detach the native error callback and argument before freeing the callback key. |
| `Close` | Discard the read direction, then close the write direction; repeated calls reuse the first close result. |
| Stack `Close` | Cancel timer dispatch, abort TCP connections and remove listening PCBs under the native lock. |

The pipe owns buffered EOF independently of native PCB lifetime. After native
ownership ends, already accepted bytes can still drain from the Go pipe; reads
must then skip native receive-credit calls. `release` finishes the pipe and
wakes writers; reset/abort discard before release. The pipe drops its array
reference on discard or once finished input has drained.

## Consumer-side buffering alternatives

A plain `bufio.Reader` does not actively drain `io.Pipe`. An active bounded
consumer buffer can drain it until that buffer fills, at which point the
original synchronous producer can again wait under `lwipMutex`. Neither alone
changes the original `tcpConnecting` rejection. The Outline SDK starts its
relay reader after dialing the remote transport.

A different buffered-pipe implementation is viable if it accepts permitted
early data, returns without waiting for consumer capacity under the native
lock, bounds memory, accounts for window credit, and preserves the close/EOF
contracts above. `tcpReceivePipe` encapsulates those producer/consumer semantics.

## Verification

Run the receive-pipe and packet-driven tests together:

```sh
go test -vet=off -race -count=5 -timeout=60s ./core
go test -vet=off -race -count=1 -timeout=60s ./...
go test -vet=off -run '^$' -bench '^BenchmarkTCPReceivePipe$' -benchmem ./core
```

`tcp_receive_test.go` drives native callbacks with segmented early data, a full
32 KiB advertised window, reopening and ordered ring wrap, FIN, reset and reader
shutdown. `review_close_test.go` checks FIN with unread data and blocked-writer
wakeups. `tcp_receive_pipe_test.go` checks lazy allocation, storage reuse,
zero steady-state write/read allocations, capacity, ring wrap and buffered EOF;
its small-flow/full-window benchmarks report per-connection allocation costs.
The library commands disable vet because the existing `string(int)` conversion
in `core/errors.go` is reported by current Go vet. Consumer integration should
also be checked with the actual SDK handler and application module replacement.
