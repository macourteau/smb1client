package netbios

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/logging"
)

// mockConn is a mock implementation of net.Conn for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func newMockConn() *mockConn {
	return &mockConn{
		readBuf:  new(bytes.Buffer),
		writeBuf: new(bytes.Buffer),
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.closed {
		return 0, errors.New("connection closed")
	}
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 445}
}

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// Helper to write a NetBIOS header to the mock connection
func writeNetBIOSHeader(buf *bytes.Buffer, msgType byte, length uint32) {
	buf.WriteByte(msgType)
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))
}

func TestNewSession(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	if session == nil {
		t.Fatal("NewSession returned nil")
	}

	if session.conn != conn {
		t.Error("Session does not wrap the provided connection")
	}
}

func TestSessionClose(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	err := session.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !conn.closed {
		t.Error("Close did not close the underlying connection")
	}

	// Close on nil conn should not panic
	session2 := &Session{conn: nil}
	if err := session2.Close(); err != nil {
		t.Errorf("Close with nil conn returned error: %v", err)
	}
}

func TestReadPacket_SessionMessage(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "small message",
			data:    []byte("Hello, SMB!"),
			wantErr: false,
		},
		{
			name:    "zero-length message",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "large message (1KB)",
			data:    bytes.Repeat([]byte("X"), 1024),
			wantErr: false,
		},
		{
			name:    "large message (64KB)",
			data:    bytes.Repeat([]byte("Y"), 65536),
			wantErr: false,
		},
		{
			name:    "maximum size message (131,072 bytes)",
			data:    bytes.Repeat([]byte("Z"), MaxMessageSize),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConn()
			session := NewSession(conn)

			// Write NetBIOS header
			writeNetBIOSHeader(conn.readBuf, MessageTypeSessionMessage, uint32(len(tt.data)))
			// Write data
			conn.readBuf.Write(tt.data)

			// Read packet
			got, err := session.ReadPacket()
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if !bytes.Equal(got, tt.data) {
					t.Errorf("ReadPacket() data mismatch: got %d bytes, want %d bytes", len(got), len(tt.data))
				}
			}
		})
	}
}

func TestReadPacket_KeepAlive(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Write a keep-alive message (type 0x85, length 0)
	writeNetBIOSHeader(conn.readBuf, MessageTypeSessionKeepAlive, 0)

	data, err := session.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket() failed: %v", err)
	}

	if len(data) != 0 {
		t.Errorf("Keep-alive should return empty data, got %d bytes", len(data))
	}
}

func TestReadPacket_KeepAliveInvalidLength(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Write a keep-alive message with non-zero length (invalid)
	writeNetBIOSHeader(conn.readBuf, MessageTypeSessionKeepAlive, 10)
	conn.readBuf.Write(make([]byte, 10))

	_, err := session.ReadPacket()
	if err == nil {
		t.Fatal("ReadPacket() should fail for keep-alive with non-zero length")
	}
}

func TestReadPacket_UnknownMessageType(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Write message with unknown type
	writeNetBIOSHeader(conn.readBuf, 0xFF, 10)
	conn.readBuf.Write(make([]byte, 10))

	_, err := session.ReadPacket()
	if err == nil {
		t.Fatal("ReadPacket() should fail for unknown message type")
	}
}

func TestReadPacket_MessageTooLarge(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Write message with length > MaxMessageSize
	// Use full 24-bit range (0xFFFFFF) which exceeds 17-bit limit
	conn.readBuf.WriteByte(MessageTypeSessionMessage)
	conn.readBuf.WriteByte(0xFF)
	conn.readBuf.WriteByte(0xFF)
	conn.readBuf.WriteByte(0xFF)

	_, err := session.ReadPacket()
	if err == nil {
		t.Fatal("ReadPacket() should fail for message exceeding MaxMessageSize")
	}
}

func TestReadPacket_ConnectionClosed(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Close connection before reading
	conn.Close()

	_, err := session.ReadPacket()
	if err == nil {
		t.Fatal("ReadPacket() should fail when connection is closed")
	}
}

func TestReadPacket_IncompleteHeader(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Write only 2 bytes of 4-byte header
	conn.readBuf.Write([]byte{0x00, 0x00})

	_, err := session.ReadPacket()
	if err == nil {
		t.Fatal("ReadPacket() should fail for incomplete header")
	}
}

func TestReadPacket_IncompleteData(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Write header indicating 100 bytes
	writeNetBIOSHeader(conn.readBuf, MessageTypeSessionMessage, 100)
	// But only write 50 bytes
	conn.readBuf.Write(make([]byte, 50))

	_, err := session.ReadPacket()
	if err == nil {
		t.Fatal("ReadPacket() should fail for incomplete data")
	}
}

func TestReadPacketContext_Cancellation(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Write a valid message
	data := []byte("test data")
	writeNetBIOSHeader(conn.readBuf, MessageTypeSessionMessage, uint32(len(data)))
	conn.readBuf.Write(data)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := session.ReadPacketContext(ctx)
	if err != context.Canceled {
		t.Errorf("ReadPacketContext() with cancelled context should return context.Canceled, got %v", err)
	}
}

func TestReadPacketContext_Timeout(t *testing.T) {
	// Note: This test verifies that context is checked, but with a mock connection
	// that returns EOF immediately, we can't test true blocking behavior.
	// Real timeout behavior would be tested in integration tests with actual network connections.

	conn := newMockConn()
	session := NewSession(conn)

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Wait for context to expire
	<-ctx.Done()

	// Read should fail immediately since context is already expired
	_, err := session.ReadPacketContext(ctx)
	if err == nil {
		t.Fatal("ReadPacketContext() should fail with expired context")
	}

	// Error should be either DeadlineExceeded or connection closed (due to mock limitations)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrConnectionClosed) {
		t.Logf("Note: got error %v, this is acceptable for mock connection", err)
	}
}

func TestWritePacket_SessionMessage(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "small message",
			data:    []byte("Hello, SMB!"),
			wantErr: false,
		},
		{
			name:    "zero-length message",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "large message (1KB)",
			data:    bytes.Repeat([]byte("X"), 1024),
			wantErr: false,
		},
		{
			name:    "large message (64KB)",
			data:    bytes.Repeat([]byte("Y"), 65536),
			wantErr: false,
		},
		{
			name:    "maximum size message (131,072 bytes)",
			data:    bytes.Repeat([]byte("Z"), MaxMessageSize),
			wantErr: false,
		},
		{
			name:    "message exceeds maximum size",
			data:    bytes.Repeat([]byte("A"), MaxMessageSize+1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConn()
			session := NewSession(conn)

			err := session.WritePacket(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("WritePacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify written data
			written := conn.writeBuf.Bytes()
			if len(written) != 4+len(tt.data) {
				t.Errorf("WritePacket() wrote %d bytes, expected %d", len(written), 4+len(tt.data))
				return
			}

			// Verify header
			if written[0] != MessageTypeSessionMessage {
				t.Errorf("Wrong message type: got 0x%02x, want 0x%02x", written[0], MessageTypeSessionMessage)
			}

			// Verify length
			length := uint32(written[1])<<16 | uint32(written[2])<<8 | uint32(written[3])
			if length != uint32(len(tt.data)) {
				t.Errorf("Wrong length in header: got %d, want %d", length, len(tt.data))
			}

			// Verify data
			if !bytes.Equal(written[4:], tt.data) {
				t.Error("Data mismatch in written packet")
			}
		})
	}
}

func TestWritePacketContext_Cancellation(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := session.WritePacketContext(ctx, []byte("test"))
	if err != context.Canceled {
		t.Errorf("WritePacketContext() with cancelled context should return context.Canceled, got %v", err)
	}
}

func TestWritePacket_ClosedConnection(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	// Close connection
	conn.Close()

	err := session.WritePacket([]byte("test"))
	if err == nil {
		t.Fatal("WritePacket() should fail when connection is closed")
	}
}

func TestRoundTrip(t *testing.T) {
	// Test reading what was written
	tests := [][]byte{
		[]byte("Short message"),
		[]byte(""),
		bytes.Repeat([]byte("Medium message "), 100),
		bytes.Repeat([]byte("X"), 65536),
	}

	for _, data := range tests {
		t.Run("", func(t *testing.T) {
			conn := newMockConn()
			session := NewSession(conn)

			// Write packet
			if err := session.WritePacket(data); err != nil {
				t.Fatalf("WritePacket() failed: %v", err)
			}

			// Copy written data to read buffer
			conn.readBuf = bytes.NewBuffer(conn.writeBuf.Bytes())

			// Read packet
			got, err := session.ReadPacket()
			if err != nil {
				t.Fatalf("ReadPacket() failed: %v", err)
			}

			if !bytes.Equal(got, data) {
				t.Errorf("Round-trip data mismatch: got %d bytes, want %d bytes", len(got), len(data))
			}
		})
	}
}

func TestSessionAccessors(t *testing.T) {
	conn := newMockConn()
	session := NewSession(conn)

	if session.Conn() != conn {
		t.Error("Conn() did not return the underlying connection")
	}

	if session.LocalAddr() == nil {
		t.Error("LocalAddr() returned nil")
	}

	if session.RemoteAddr() == nil {
		t.Error("RemoteAddr() returned nil")
	}

	localAddr := session.LocalAddr().String()
	if localAddr == "" {
		t.Error("LocalAddr() returned empty string")
	}

	remoteAddr := session.RemoteAddr().String()
	if remoteAddr == "" {
		t.Error("RemoteAddr() returned empty string")
	}
}

func TestMaxMessageSizeConstant(t *testing.T) {
	// Verify MaxMessageSize is 2^17
	expected := 1 << 17
	if MaxMessageSize != expected {
		t.Errorf("MaxMessageSize = %d, want %d (2^17)", MaxMessageSize, expected)
	}
}

func TestMessageTypeConstants(t *testing.T) {
	// Verify message type constants match RFC 1001/1002
	tests := []struct {
		name     string
		got      byte
		expected byte
	}{
		{"SESSION_MESSAGE", MessageTypeSessionMessage, 0x00},
		{"SESSION_REQUEST", MessageTypeSessionRequest, 0x81},
		{"POSITIVE_RESPONSE", MessageTypePositiveResponse, 0x82},
		{"NEGATIVE_RESPONSE", MessageTypeNegativeResponse, 0x83},
		{"RETARGET_RESPONSE", MessageTypeRetargetResponse, 0x84},
		{"SESSION_KEEP_ALIVE", MessageTypeSessionKeepAlive, 0x85},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = 0x%02x, want 0x%02x", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestReadPacket_17BitLengthField(t *testing.T) {
	// Test that we correctly handle the 17-bit length field
	// Maximum valid value is 0x1FFFF (131,071)
	tests := []struct {
		name      string
		length    uint32
		shouldErr bool
	}{
		{"zero length", 0, false},
		{"max valid 17-bit (131,071)", 0x1FFFF, false},
		{"exactly 131,072 (max allowed)", MaxMessageSize, false},
		{"exceeds 17-bit limit", 0x20000, true},
		{"upper bits set (invalid)", 0xFF0000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConn()
			session := NewSession(conn)

			// Manually construct header with specific length
			conn.readBuf.WriteByte(MessageTypeSessionMessage)
			conn.readBuf.WriteByte(byte(tt.length >> 16))
			conn.readBuf.WriteByte(byte(tt.length >> 8))
			conn.readBuf.WriteByte(byte(tt.length))

			// Write data if length is valid
			if !tt.shouldErr && tt.length <= MaxMessageSize {
				conn.readBuf.Write(make([]byte, tt.length))
			}

			_, err := session.ReadPacket()
			if (err != nil) != tt.shouldErr {
				t.Errorf("ReadPacket() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}

func BenchmarkWritePacket(b *testing.B) {
	sizes := []int{100, 1024, 16384, 65536}

	for _, size := range sizes {
		b.Run("", func(b *testing.B) {
			conn := newMockConn()
			session := NewSession(conn)
			data := make([]byte, size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				conn.writeBuf.Reset()
				if err := session.WritePacket(data); err != nil {
					b.Fatal(err)
				}
			}
			b.SetBytes(int64(size))
		})
	}
}

func BenchmarkReadPacket(b *testing.B) {
	sizes := []int{100, 1024, 16384, 65536}

	for _, size := range sizes {
		b.Run("", func(b *testing.B) {
			data := make([]byte, size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				conn := newMockConn()
				session := NewSession(conn)
				writeNetBIOSHeader(conn.readBuf, MessageTypeSessionMessage, uint32(size))
				conn.readBuf.Write(data)
				b.StartTimer()

				if _, err := session.ReadPacket(); err != nil {
					b.Fatal(err)
				}
			}
			b.SetBytes(int64(size))
		})
	}
}

// testLogger implements the logging.Logger interface for testing
type testLogger struct {
	logs []string
}

func (l *testLogger) Debug(format string, args ...interface{}) {
	l.logs = append(l.logs, fmt.Sprintf("[DEBUG] "+format, args...))
}

func (l *testLogger) Info(format string, args ...interface{}) {
	l.logs = append(l.logs, fmt.Sprintf("[INFO] "+format, args...))
}

func (l *testLogger) Warn(format string, args ...interface{}) {
	l.logs = append(l.logs, fmt.Sprintf("[WARN] "+format, args...))
}

func (l *testLogger) Error(format string, args ...interface{}) {
	l.logs = append(l.logs, fmt.Sprintf("[ERROR] "+format, args...))
}

func TestContextBasedLogging(t *testing.T) {
	// Test that logging works when logger is in context
	t.Run("with logger in context", func(t *testing.T) {
		logger := &testLogger{}
		ctx := logging.WithLogger(context.Background(), logger)

		conn := newMockConn()
		session := NewSession(conn)

		// Write a test message
		testData := []byte("test message")
		writeNetBIOSHeader(conn.readBuf, MessageTypeSessionMessage, uint32(len(testData)))
		conn.readBuf.Write(testData)

		// Read with context - should produce logs
		data, err := session.ReadPacketContext(ctx)
		if err != nil {
			t.Fatalf("ReadPacketContext failed: %v", err)
		}

		if !bytes.Equal(data, testData) {
			t.Errorf("Data mismatch: got %v, want %v", data, testData)
		}

		// Verify logging occurred
		if len(logger.logs) == 0 {
			t.Fatal("No logs recorded - context-based logging not working")
		}

		// Verify at least one log contains expected content
		found := false
		for _, log := range logger.logs {
			if bytes.Contains([]byte(log), []byte("netbios:")) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("No netbios logs found. Logs: %v", logger.logs)
		}
	})

	// Test that logging doesn't panic when no logger in context
	t.Run("without logger in context", func(t *testing.T) {
		ctx := context.Background()

		conn := newMockConn()
		session := NewSession(conn)

		// Write a test message
		testData := []byte("test message")
		writeNetBIOSHeader(conn.readBuf, MessageTypeSessionMessage, uint32(len(testData)))
		conn.readBuf.Write(testData)

		// Read with context that has no logger - should not panic
		data, err := session.ReadPacketContext(ctx)
		if err != nil {
			t.Fatalf("ReadPacketContext failed: %v", err)
		}

		if !bytes.Equal(data, testData) {
			t.Errorf("Data mismatch: got %v, want %v", data, testData)
		}
	})

	// Test WritePacketContext with logging
	t.Run("write with logger in context", func(t *testing.T) {
		logger := &testLogger{}
		ctx := logging.WithLogger(context.Background(), logger)

		conn := newMockConn()
		session := NewSession(conn)

		testData := []byte("test write")
		err := session.WritePacketContext(ctx, testData)
		if err != nil {
			t.Fatalf("WritePacketContext failed: %v", err)
		}

		// Verify logging occurred
		if len(logger.logs) == 0 {
			t.Fatal("No logs recorded for write - context-based logging not working")
		}

		// Verify at least one log contains expected content
		found := false
		for _, log := range logger.logs {
			if bytes.Contains([]byte(log), []byte("writing message")) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("No write logs found. Logs: %v", logger.logs)
		}
	})
}
