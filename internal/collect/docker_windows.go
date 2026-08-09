//go:build windows

package collect

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// dialLocal opens the Docker engine's named pipe.
//
// Windows has no dialer for named pipes in the standard library, and the usual
// answer — Microsoft/go-winio — would be a ninth direct dependency in a tool
// whose whole subject is dependency risk. A named pipe opens with the ordinary
// file API, so os.OpenFile reaches it and the result only needs the net.Conn
// methods bolted on.
func dialLocal(_ context.Context, network, address string) (net.Conn, error) {
	if network != "npipe" {
		return nil, fmt.Errorf("collect: unsupported docker transport %q", network)
	}
	file, err := os.OpenFile(address, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err := setByteMode(file); err != nil {
		file.Close()
		return nil, err
	}
	return pipeConn{file}, nil
}

// Named pipe read modes (winbase.h). Byte mode plus wait is the zero value, but
// naming it is the difference between a constant and a mystery.
const (
	pipeReadModeByte = 0x0
	pipeWait         = 0x0
)

var (
	kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procSetNamedPipeHandleState = kernel32.NewProc("SetNamedPipeHandleState")
)

// setByteMode switches the pipe out of message mode.
//
// Docker's engine pipe is created in message mode, where a read returns one
// whole message or fails with ERROR_MORE_DATA. HTTP is a byte stream and does
// not survive that: the request goes out, the response never comes back, and
// the only symptom is a client timeout — which is exactly what this looked like
// before the call was here.
//
// Declared against kernel32 directly rather than pulling in x/sys/windows. The
// direct-dependency budget is full, and this is fifteen lines of stdlib.
func setByteMode(file *os.File) error {
	mode := uint32(pipeReadModeByte | pipeWait)
	ret, _, err := procSetNamedPipeHandleState.Call(
		file.Fd(), uintptr(unsafe.Pointer(&mode)), 0, 0)
	if ret == 0 {
		return fmt.Errorf("collect: could not set docker pipe to byte mode: %w", err)
	}
	return nil
}

// pipeConn adapts a named pipe handle to net.Conn.
//
// ponytail: deadline calls are accepted and ignored. A pipe opened without
// overlapping I/O cannot support them, and reporting the error would make
// net/http give up on a connection that works perfectly well. The ceiling is
// that a wedged Docker engine cannot be timed out at the socket — http.Client's
// own timeout still fires and closes the connection, which is the behaviour
// that matters. Swap in a proper overlapped-I/O pipe if that ever proves
// insufficient.
type pipeConn struct{ *os.File }

func (pipeConn) LocalAddr() net.Addr              { return pipeAddr{} }
func (pipeConn) RemoteAddr() net.Addr             { return pipeAddr{} }
func (pipeConn) SetDeadline(time.Time) error      { return nil }
func (pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (pipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "npipe" }
func (pipeAddr) String() string  { return "docker" }
