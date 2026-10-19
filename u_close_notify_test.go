package tls

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
)

type countingConn struct {
	net.Conn
	written atomic.Int64
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written.Add(int64(n))
	return n, err
}

// Close sends a close_notify record unless OmitCloseNotify is set, in which
// case the TCP connection just ends, the way Chromium's does.
func TestOmitCloseNotify(t *testing.T) {
	for _, tc := range []struct {
		name      string
		omit      bool
		wantBytes bool
	}{
		{"alert sent", false, true},
		{"alert omitted", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := localPipe(t)
			server := Server(s, testConfig.Clone())
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				if server.Handshake() == nil {
					io.Copy(io.Discard, server)
				}
				s.Close()
			}()

			conn := &countingConn{Conn: c}
			clientConfig := testConfig.Clone()
			clientConfig.OmitCloseNotify = tc.omit
			client := Client(conn, clientConfig)
			if err := client.Handshake(); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			before := conn.written.Load()
			client.Close()
			<-serverDone

			if wrote := conn.written.Load() - before; (wrote > 0) != tc.wantBytes {
				t.Errorf("Close wrote %d bytes, want an alert record: %v", wrote, tc.wantBytes)
			}
		})
	}
}
