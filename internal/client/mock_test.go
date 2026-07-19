package client

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/macourteau/smb1client/internal/ntlm"
	"github.com/macourteau/smb1client/internal/smb1"
)

// mockConn is a mock net.Conn for testing.
type mockConn struct {
	readCh   chan []byte // Channel for sending data to Read()
	writeBuf []byte      // Buffer for capturing written data
	readBuf  []byte      // Current buffer being read from
	readPos  int         // Current position in readBuf
	closed   bool
	mu       sync.Mutex
}

// getMockConn extracts the mockConn from a connection for testing.
func getMockConn(c *Conn) *mockConn {
	// Access the underlying TCP connection from the NetBIOS session
	return c.netbiosConn.Conn().(*mockConn)
}

func newMockConn() *mockConn {
	return &mockConn{
		readCh: make(chan []byte, 10), // Buffered channel
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, io.EOF
	}

	// If we have data in the buffer, read from it
	if m.readPos < len(m.readBuf) {
		n = copy(b, m.readBuf[m.readPos:])
		m.readPos += n
		return n, nil
	}

	// Unlock for the blocking read
	m.mu.Unlock()

	// Block until new data is available or connection is closed
	data := <-m.readCh
	m.mu.Lock()
	if data == nil {
		return 0, io.EOF
	}
	m.readBuf = data
	m.readPos = 0
	n = copy(b, m.readBuf)
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, errors.New("connection closed")
	}

	m.writeBuf = append(m.writeBuf, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		// Send nil to wake up any blocked readers
		select {
		case m.readCh <- nil:
		default:
		}
	}
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *mockConn) addResponse(header *smb1.Header, params, data []byte) {
	packet, _ := smb1.EncodePacket(header, params, data)

	// Add NetBIOS header
	netbiosHeader := make([]byte, 4)
	netbiosHeader[0] = 0x00 // SESSION_MESSAGE
	length := len(packet)
	netbiosHeader[1] = byte(length >> 16)
	netbiosHeader[2] = byte(length >> 8)
	netbiosHeader[3] = byte(length)

	// Combine header and packet
	fullPacket := append(netbiosHeader, packet...)

	// Send to read channel
	m.readCh <- fullPacket
}

// mockInitiator is a mock Initiator for testing.
type mockInitiator struct {
	negotiateMsg    []byte
	authenticateMsg []byte
	negotiateErr    error
	authenticateErr error
	session         *ntlm.Session
}

func newMockInitiator() *mockInitiator {
	return &mockInitiator{
		negotiateMsg:    []byte("NTLMSSP\x00negotiate"),
		authenticateMsg: []byte("NTLMSSP\x00authenticate"),
		session:         &ntlm.Session{},
	}
}

func (m *mockInitiator) Negotiate() ([]byte, error) {
	return m.negotiateMsg, m.negotiateErr
}

func (m *mockInitiator) Authenticate(challengeMsg []byte) ([]byte, error) {
	return m.authenticateMsg, m.authenticateErr
}

func (m *mockInitiator) Session() *ntlm.Session {
	return m.session
}

// setupTestConn creates a test connection with capabilities set.
func setupTestConn() *Conn {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)

	// Set negotiated parameters
	c.maxBufferSize = 4356
	c.maxMpxCount = 50
	c.sessionKey = 0
	c.capabilities = smb1.CAP_UNICODE | smb1.CAP_NT_SMBS

	return c
}
