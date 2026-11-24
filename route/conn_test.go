package route

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// tcpPair returns a connected pair of real TCP connections, so that CloseWrite
// produces a half-closed connection the way a proxied session does. net.Pipe is
// not usable here: it has no CloseWrite, so connectionCopy would close the whole
// connection instead.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, aErr := listener.Accept()
		accepted <- result{conn, aErr}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() {
		client.Close()
		server.conn.Close()
	})
	return client, server.conn
}

// TestConnectionCopyReportsHalfClose checks that onClose fires once the remote
// end is done, even while the client keeps its own side of the connection open.
// Waiting for both directions leaves such connections unreported until TCP
// keepalive expires, which leaks active user tracker entries.
func TestConnectionCopyReportsHalfClose(t *testing.T) {
	t.Parallel()

	inboundClient, inboundServer := tcpPair(t)
	outboundServer, remote := tcpPair(t)

	manager := NewConnectionManager(logger.NOP())
	closed := make(chan error, 4)
	onClose := N.OnceClose(func(err error) {
		closed <- err
	})

	var done atomic.Bool
	ctx := context.Background()
	go manager.connectionCopy(ctx, inboundServer, outboundServer, false, &done, onClose)
	go manager.connectionCopy(ctx, outboundServer, inboundServer, true, &done, onClose)

	// The remote answered and is done, while the client still holds its socket.
	if _, err := remote.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := remote.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("onClose was not called after the remote closed its side")
	}

	if _, err := inboundClient.Read(make([]byte, 8)); err != nil {
		t.Fatal("client should still have received the response: ", err)
	}
}

// TestConnectionCopyReportsCloseOnce checks that a connection whose both
// directions end still reports exactly one close, so the refcount kept per user
// by the active user trackers cannot drift.
func TestConnectionCopyReportsCloseOnce(t *testing.T) {
	t.Parallel()

	inboundClient, inboundServer := tcpPair(t)
	outboundServer, remote := tcpPair(t)

	manager := NewConnectionManager(logger.NOP())
	var closeCount atomic.Int32
	closed := make(chan struct{}, 4)
	onClose := N.CloseHandlerFunc(func(err error) {
		closeCount.Add(1)
		closed <- struct{}{}
	})

	var done atomic.Bool
	ctx := context.Background()
	go manager.connectionCopy(ctx, inboundServer, outboundServer, false, &done, onClose)
	go manager.connectionCopy(ctx, outboundServer, inboundServer, true, &done, onClose)

	inboundClient.Close()
	remote.Close()

	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("onClose was not called after both sides closed")
	}

	time.Sleep(100 * time.Millisecond)
	if count := closeCount.Load(); count != 1 {
		t.Fatal("expected exactly one close report, got ", count)
	}
}

type recordingConn struct {
	net.Conn
	writes chan int
}

func (c *recordingConn) Write(data []byte) (int, error) {
	c.writes <- len(data)
	return c.Conn.Write(data)
}

func TestConnectionCopyCheckedKeepsInitialWrite(t *testing.T) {
	t.Parallel()

	client, inbound := net.Pipe()
	target, outbound := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		inbound.Close()
		target.Close()
		outbound.Close()
	})
	target.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("ordinary traffic"), 64)
	go func() { _, _ = client.Write(payload) }()

	observed := &recordingConn{Conn: outbound, writes: make(chan int, 2)}
	manager := NewConnectionManager(logger.NOP())
	var done atomic.Bool
	go manager.connectionCopyChecked(context.Background(), inbound, observed, &done, func(error) {})

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(target, received); err != nil {
		t.Fatal(err)
	}
	if size := <-observed.writes; size != len(payload) || !bytes.Equal(payload, received) {
		t.Fatalf("first write was split or lost: %d bytes, expected %d", size, len(payload))
	}
}
