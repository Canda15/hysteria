package server

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

// stubUDPConn records written packets. ReadFrom fails immediately, so the
// receive loop exits right away (writes on the stub keep working).
type stubUDPConn struct {
	written [][]byte
}

func (c *stubUDPConn) WriteTo(b []byte, addr string) (int, error) {
	c.written = append(c.written, append([]byte{}, b...))
	return len(b), nil
}

func (c *stubUDPConn) ReadFrom(b []byte) (int, string, error) {
	return 0, "", errors.New("closed")
}

func (c *stubUDPConn) Close() error { return nil }

// stubSniffIO implements udpIO and udpStreamHookCap with a sniffing session
// that never completes — to exercise the resource bounds.
type stubSniffIO struct {
	conn *stubUDPConn
}

func (s *stubSniffIO) ReceiveMessage() (*protocol.UDPMessage, error) {
	return nil, errors.New("n/a")
}

func (s *stubSniffIO) SendMessage([]byte, *protocol.UDPMessage) error { return nil }

func (s *stubSniffIO) Hook(data []byte, reqAddr *string) error { return nil }

func (s *stubSniffIO) UDP(reqAddr string) (UDPConn, error) { return s.conn, nil }

func (s *stubSniffIO) CheckUDP(reqAddr string) error { return nil }

func (s *stubSniffIO) OpenUDPStream(firstData []byte, reqAddr string) UDPsniffSession {
	return &stubSniffSession{reqAddr: reqAddr}
}

// stubSniffSession never completes and always reports the original address.
type stubSniffSession struct {
	reqAddr string
}

func (s *stubSniffSession) Feed(data []byte) {}

func (s *stubSniffSession) Done() bool { return false }

func (s *stubSniffSession) Addr() string { return s.reqAddr }

func TestUDPSniffResourceBounds(t *testing.T) {
	conn := &stubUDPConn{}
	io := &stubSniffIO{conn: conn}
	e := newUDPSessionEntry(1, io,
		func(addr string, data []byte) (UDPConn, string, error) { return io.UDP(addr) },
		func(error) {},
	)

	// Feed exactly the datagram-count bound worth of messages. The sniffer
	// never completes, so hitting the bound must abandon sniffing, dial the
	// original address and flush all buffered messages in order.
	for i := 0; i < udpSniffMaxDatagrams; i++ {
		m := &protocol.UDPMessage{
			SessionID: 1,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      "1.2.3.4:443",
			Data:      []byte{byte(i)},
		}
		_, err := e.Feed(m)
		require.NoError(t, err)
	}

	require.Len(t, conn.written, udpSniffMaxDatagrams)
	for i, w := range conn.written {
		require.Equal(t, []byte{byte(i)}, w)
	}
	// No server name was found, so the original address must be kept: no
	// address override, and the sniffing session is released.
	require.Empty(t, e.OverrideAddr)
	require.Nil(t, e.sniffSession)
}
