package core

/*
#cgo CFLAGS: -I./c/include
#include "lwip/tcp.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
	"unsafe"
)

type tcpConnState uint

const (
	// tcpNewConn is the initial state.
	tcpNewConn tcpConnState = iota

	// tcpConnecting indicates the handler is still connecting remote host.
	tcpConnecting

	// tcpConnected indicates the connection has been established, handler
	// may write data to TUN, and read data from TUN.
	tcpConnected

	// tcpWriteClosed indicates the handler has closed the writing side
	// of the connection, no more data will send to TUN, but handler can still
	// read data from TUN.
	tcpWriteClosed

	// tcpReceiveClosed indicates lwIP has received a FIN segment from
	// local peer, the reading side is closed, no more data can be read
	// from TUN, but handler can still write data to TUN.
	tcpReceiveClosed

	// tcpClosing indicates both reading side and writing side are closed,
	// resources deallocation will be triggered at any time in lwIP callbacks.
	tcpClosing

	// tcpAborting indicates the connection is aborting, resources deallocation
	// will be triggered at any time in lwIP callbacks.
	tcpAborting

	// tcpClosed indicates the connection has been closed, resources were freed.
	tcpClosed

	// tcpErrord indicates an fatal error occured on the connection, resources
	// were freed.
	tcpErrored
)

type tcpConn struct {
	sync.Mutex

	pcb           *C.struct_tcp_pcb
	handler       TCPConnHandler
	remoteAddr    *net.TCPAddr
	localAddr     *net.TCPAddr
	connKeyArg    unsafe.Pointer
	connKey       uint32
	canWrite      *sync.Cond // Condition variable to implement TCP backpressure.
	state         tcpConnState
	receiveMu     sync.Mutex
	canRead       *sync.Cond
	receiveBuffer []byte
	receiveHead   int
	receiveSize   int
	receiveErr    error
	closeOnce     sync.Once
	closeErr      error
}

func newTCPConn(pcb *C.struct_tcp_pcb, handler TCPConnHandler) (TCPConn, error) {
	connKeyArg := newConnKeyArg()
	connKey := rand.Uint32()
	setConnKeyVal(unsafe.Pointer(connKeyArg), connKey)

	// Pass the key as arg for subsequent tcp callbacks.
	C.tcp_arg(pcb, unsafe.Pointer(connKeyArg))

	// Register callbacks.
	setTCPRecvCallback(pcb)
	setTCPSentCallback(pcb)
	setTCPErrCallback(pcb)
	setTCPPollCallback(pcb, C.u8_t(TCP_POLL_INTERVAL))

	conn := &tcpConn{
		pcb:        pcb,
		handler:    handler,
		localAddr:  ParseTCPAddr(ipAddrNTOA(pcb.remote_ip), uint16(pcb.remote_port)),
		remoteAddr: ParseTCPAddr(ipAddrNTOA(pcb.local_ip), uint16(pcb.local_port)),
		connKeyArg: connKeyArg,
		connKey:    connKey,
		canWrite:   sync.NewCond(&sync.Mutex{}),
		state:      tcpNewConn,
	}

	conn.canRead = sync.NewCond(&conn.receiveMu)

	// Associate conn with key and save to the global map.
	tcpConns.Store(connKey, conn)

	// Connecting remote host could take some time, do it in another goroutine
	// to prevent blocking the lwip thread.
	conn.Lock()
	conn.state = tcpConnecting
	conn.Unlock()
	go func() {
		err := handler.Handle(TCPConn(conn), conn.remoteAddr)
		if err != nil {
			conn.Abort()
		} else {
			conn.Lock()
			if conn.state != tcpConnecting {
				conn.Unlock()
				return
			}
			conn.state = tcpConnected
			conn.Unlock()
		}
	}()

	return conn, NewLWIPError(LWIP_ERR_OK)
}

func (conn *tcpConn) RemoteAddr() net.Addr {
	return conn.remoteAddr
}

func (conn *tcpConn) LocalAddr() net.Addr {
	return conn.localAddr
}

func (conn *tcpConn) SetDeadline(t time.Time) error {
	return nil
}
func (conn *tcpConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (conn *tcpConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (conn *tcpConn) receiveCheck() error {
	conn.Lock()
	defer conn.Unlock()

	switch conn.state {
	case tcpNewConn:
		fallthrough
	case tcpConnecting:
		fallthrough
	case tcpConnected:
		fallthrough
	case tcpWriteClosed:
		return nil
	case tcpAborting:
		fallthrough
	case tcpClosed:
		fallthrough
	case tcpReceiveClosed:
		fallthrough
	case tcpClosing:
		return NewLWIPError(LWIP_ERR_CLSD)
	case tcpErrored:
		return NewLWIPError(LWIP_ERR_CLSD)
	default:
		panic("unexpected error")
	}
}

func (conn *tcpConn) Receive(data []byte) error {
	if err := conn.receiveCheck(); err != nil {
		return err
	}
	// Never block the lwIP thread on proxy dialing or socket writes. In particular,
	// refusing the first segment while dialing makes lwIP drop subsequent segments.
	// Keep at most the advertised receive window, and reopen it only when Read drains it.
	conn.receiveMu.Lock()
	defer conn.receiveMu.Unlock()
	if conn.receiveErr != nil {
		return NewLWIPError(LWIP_ERR_CLSD)
	}
	if len(data) > int(C.TCP_WND)-conn.receiveSize {
		return NewLWIPError(LWIP_ERR_CONN)
	}
	if len(data) > 0 {
		if conn.receiveBuffer == nil {
			conn.receiveBuffer = make([]byte, int(C.TCP_WND))
		}
		tail := (conn.receiveHead + conn.receiveSize) % len(conn.receiveBuffer)
		n := copy(conn.receiveBuffer[tail:], data)
		copy(conn.receiveBuffer, data[n:])
		conn.receiveSize += len(data)
		conn.canRead.Broadcast()
	}
	return NewLWIPError(LWIP_ERR_OK)
}

func (conn *tcpConn) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	conn.receiveMu.Lock()
	for conn.receiveSize == 0 && conn.receiveErr == nil {
		conn.canRead.Wait()
	}
	if conn.receiveSize == 0 {
		err := conn.receiveErr
		conn.receiveMu.Unlock()
		return 0, err
	}
	n := len(data)
	if n > conn.receiveSize {
		n = conn.receiveSize
	}
	first := copy(data[:n], conn.receiveBuffer[conn.receiveHead:])
	copy(data[first:n], conn.receiveBuffer[:n-first])
	conn.receiveHead = (conn.receiveHead + n) % len(conn.receiveBuffer)
	conn.receiveSize -= n
	conn.receiveMu.Unlock()

	// Packet callbacks take lwipMutex before conn.Mutex. Release receiveMu first,
	// and check the state under lwipMutex: a reset may already have freed the PCB.
	lwipMutex.Lock()
	conn.Lock()
	alive := conn.state < tcpAborting
	conn.Unlock()
	if alive {
		C.tcp_recved(conn.pcb, C.u16_t(n))
		C.tcp_output(conn.pcb)
	}
	lwipMutex.Unlock()
	return n, nil
}

func (conn *tcpConn) finishRead(err error, discard bool) {
	conn.receiveMu.Lock()
	defer conn.receiveMu.Unlock()
	if discard {
		conn.receiveSize = 0
		conn.receiveBuffer = nil
	}
	if conn.receiveErr == nil || discard {
		conn.receiveErr = err
	}
	conn.canRead.Broadcast()
}

// writeInternal enqueues data to snd_buf, and treats ERR_MEM returned by tcp_write not an error,
// but instead tells the caller that data is not successfully enqueued, and should try
// again another time. By calling this function, the lwIP thread is assumed to be already
// locked by the caller.
func (conn *tcpConn) writeInternal(data []byte) (int, error) {
	err := C.tcp_write(conn.pcb, unsafe.Pointer(&data[0]), C.u16_t(len(data)), C.TCP_WRITE_FLAG_COPY)
	if err == C.ERR_OK {
		C.tcp_output(conn.pcb)
		return len(data), nil
	} else if err == C.ERR_MEM {
		return 0, nil
	}
	return 0, fmt.Errorf("tcp_write failed (%v)", int(err))
}

func (conn *tcpConn) writeCheck() error {
	conn.Lock()
	defer conn.Unlock()

	switch conn.state {
	case tcpConnecting:
		fallthrough
	case tcpConnected:
		fallthrough
	case tcpReceiveClosed:
		return nil
	case tcpWriteClosed:
		fallthrough
	case tcpClosing:
		fallthrough
	case tcpClosed:
		fallthrough
	case tcpErrored:
		fallthrough
	case tcpAborting:
		return io.ErrClosedPipe
	default:
		panic("unexpected error")
	}
	return nil
}

func (conn *tcpConn) Write(data []byte) (int, error) {
	totalWritten := 0

	conn.canWrite.L.Lock()
	defer conn.canWrite.L.Unlock()

	for len(data) > 0 {
		if err := conn.writeCheck(); err != nil {
			return totalWritten, err
		}

		lwipMutex.Lock()
		toWrite := len(data)
		if toWrite > int(conn.pcb.snd_buf) {
			// Write at most the size of the LWIP buffer.
			toWrite = int(conn.pcb.snd_buf)
		}
		if toWrite > 0 {
			written, err := conn.writeInternal(data[0:toWrite])
			totalWritten += written
			if err != nil {
				lwipMutex.Unlock()
				return totalWritten, err
			}
			data = data[written:len(data)]
		}
		lwipMutex.Unlock()
		if len(data) == 0 {
			break // Don't block if all the data has been written.
		}
		conn.canWrite.Wait()
	}

	return totalWritten, nil
}

func (conn *tcpConn) CloseWrite() error {
	conn.Lock()
	if conn.state >= tcpClosing || conn.state == tcpWriteClosed {
		conn.Unlock()
		return nil
	}
	if conn.state == tcpReceiveClosed {
		conn.state = tcpClosing
	} else {
		conn.state = tcpWriteClosed
	}
	conn.Unlock()

	lwipMutex.Lock()
	// FIXME Handle tcp_shutdown error.
	C.tcp_shutdown(conn.pcb, 0, 1)
	lwipMutex.Unlock()

	return nil
}

func (conn *tcpConn) CloseRead() error {
	conn.finishRead(io.ErrClosedPipe, true)
	return nil
}

func (conn *tcpConn) Sent(len uint16) error {
	// Some packets are acknowledged by local client, check if any pending data to send.
	return conn.checkState()
}

func (conn *tcpConn) checkClosing() error {
	conn.Lock()
	defer conn.Unlock()

	if conn.state == tcpClosing {
		conn.closeInternal()
		return NewLWIPError(LWIP_ERR_OK)
	}
	return nil
}

func (conn *tcpConn) checkAborting() error {
	conn.Lock()
	defer conn.Unlock()

	if conn.state == tcpAborting {
		conn.abortInternal()
		return NewLWIPError(LWIP_ERR_ABRT)
	}
	return nil
}

func (conn *tcpConn) isClosed() bool {
	conn.Lock()
	defer conn.Unlock()

	return conn.state == tcpClosed
}

func (conn *tcpConn) checkState() error {
	if conn.isClosed() {
		return nil
	}

	err := conn.checkClosing()
	if err != nil {
		return err
	}

	err = conn.checkAborting()
	if err != nil {
		return err
	}

	// Signal the writer to try writting.
	conn.canWrite.Broadcast()

	return NewLWIPError(LWIP_ERR_OK)
}

func (conn *tcpConn) Close() error {
	conn.closeOnce.Do(conn.close)
	return conn.closeErr
}

func (conn *tcpConn) close() {
	err := conn.CloseRead()
	if err != nil {
		conn.closeErr = err
	}
	err = conn.CloseWrite()
	if err != nil {
		conn.closeErr = err
	}
}

func (conn *tcpConn) setLocalClosed() error {
	conn.Lock()
	defer conn.Unlock()

	if conn.state >= tcpClosing || conn.state == tcpReceiveClosed {
		return nil
	}

	// Deliver buffered bytes before EOF, including a FIN received while dialing.
	conn.finishRead(io.EOF, false)

	if conn.state == tcpWriteClosed {
		conn.state = tcpClosing
	} else {
		conn.state = tcpReceiveClosed
	}
	conn.canWrite.Broadcast()
	return nil
}

// Never call this function outside of the lwIP thread.
func (conn *tcpConn) closeInternal() error {
	C.tcp_arg(conn.pcb, nil)
	C.tcp_recv(conn.pcb, nil)
	C.tcp_sent(conn.pcb, nil)
	C.tcp_err(conn.pcb, nil)
	C.tcp_poll(conn.pcb, nil, 0)

	conn.release()

	// FIXME Handle error.
	err := C.tcp_close(conn.pcb)
	if err == C.ERR_OK {
		return nil
	} else {
		return errors.New(fmt.Sprintf("close TCP connection failed, lwip error code %d", int(err)))
	}
}

// Never call this function outside of the lwIP thread since it calls
// tcp_abort() and in that case we must return ERR_ABRT to lwIP.
func (conn *tcpConn) abortInternal() {
	conn.finishRead(io.ErrClosedPipe, true)
	conn.release()
	C.tcp_abort(conn.pcb)
}

func (conn *tcpConn) Abort() {
	conn.Lock()
	// If it's in tcpErrored state, the pcb was already freed.
	if conn.state < tcpAborting {
		conn.state = tcpAborting
	}
	conn.Unlock()

	lwipMutex.Lock()
	conn.checkState()
	lwipMutex.Unlock()
}

func (conn *tcpConn) Err(err error) {
	conn.Lock()
	defer conn.Unlock()

	conn.finishRead(io.ErrClosedPipe, true)
	conn.release()
	conn.state = tcpErrored
	conn.canWrite.Broadcast()
}

func (conn *tcpConn) LocalClosed() error {
	conn.setLocalClosed()
	return conn.checkState()
}

func (conn *tcpConn) release() {
	if _, found := tcpConns.Load(conn.connKey); found {
		freeConnKeyArg(conn.connKeyArg)
		tcpConns.Delete(conn.connKey)
	}
	conn.finishRead(io.EOF, false)
	conn.state = tcpClosed
}

func (conn *tcpConn) Poll() error {
	return conn.checkState()
}
