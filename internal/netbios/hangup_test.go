package netbios

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// hangupConn serves a fixed prefix and then reports the peer having gone away,
// letting each truncation point in a frame be reproduced exactly.
type hangupConn struct {
	data []byte
	pos  int
}

func (c *hangupConn) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.pos:])
	c.pos += n
	return n, nil
}

func (c *hangupConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *hangupConn) Close() error                       { return nil }
func (c *hangupConn) LocalAddr() net.Addr                { return nil }
func (c *hangupConn) RemoteAddr() net.Addr               { return nil }
func (c *hangupConn) SetDeadline(t time.Time) error      { return nil }
func (c *hangupConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *hangupConn) SetWriteDeadline(t time.Time) error { return nil }

// A peer that disappears mid-frame must be classifiable however far through the
// frame it got. io.ReadFull reports a boundary-aligned close as io.EOF and a
// mid-read close as io.ErrUnexpectedEOF; both are the same event, and a caller
// deciding "redial" versus "give up" must not have to tell them apart.
func TestReadPacketClassifiesEveryHangupShape(t *testing.T) {
	// A well-formed session message header announcing 64 bytes of payload.
	header := []byte{0x00, 0x00, 0x00, 0x40}

	tests := []struct {
		name string
		data []byte
	}{
		// io.EOF from ReadFull: nothing at all arrived.
		{"nothing sent", nil},
		// io.ErrUnexpectedEOF: header truncated part-way.
		{"partial header 1 byte", header[:1]},
		{"partial header 3 bytes", header[:3]},
		// io.EOF: header complete, payload never started.
		{"header only, no payload", header},
		// io.ErrUnexpectedEOF: died mid-payload — the likeliest shape, since a
		// large read spends nearly all its wire time here.
		{"partial payload", append(append([]byte{}, header...), make([]byte, 20)...)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{conn: &hangupConn{data: tc.data}}

			_, err := s.ReadPacket()
			if err == nil {
				t.Fatal("ReadPacket() succeeded on a truncated frame")
			}
			if !errors.Is(err, ErrConnectionClosed) {
				t.Errorf("errors.Is(err, ErrConnectionClosed) = false for %v", err)
			}
			// This is the property a consumer actually depends on to decide
			// between redialling and treating the failure as permanent.
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("errors.Is(err, net.ErrClosed) = false for %v; a hangup would be misread as permanent", err)
			}
			if errors.Is(err, io.EOF) {
				t.Errorf("errors.Is(err, io.EOF) = true for %v; a mid-frame hangup must not read as end of data", err)
			}
		})
	}
}

func TestIsHangup(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"eof", io.EOF, true},
		{"unexpected eof", io.ErrUnexpectedEOF, true},
		{"wrapped eof", errors.Join(errors.New("x"), io.EOF), true},
		{"nil", nil, false},
		{"other", errors.New("boom"), false},
		{"closed", net.ErrClosed, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHangup(tc.err); got != tc.want {
				t.Errorf("isHangup(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
