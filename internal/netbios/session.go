// Package netbios implements the NetBIOS session service layer for SMB1 protocol.
// This provides the framing layer that wraps TCP connections for SMB communication.
package netbios

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/macourteau/smb1client/internal/logging"
)

// ErrConnectionClosed reports that the peer went away part-way through a
// NetBIOS frame — while its header was being read, or while its payload was.
// The frame will never arrive and the session is unusable.
//
// It wraps net.ErrClosed so callers can classify it with errors.Is instead of
// matching the message text. The io.EOF or io.ErrUnexpectedEOF that surfaced it
// is deliberately not propagated: a hangup mid-frame is not an orderly end of
// data, and a caller testing for io.EOF would draw the opposite conclusion.
var ErrConnectionClosed = fmt.Errorf("netbios: connection closed: %w", net.ErrClosed)

// isHangup reports whether err means the peer went away mid-frame.
//
// io.ReadFull distinguishes two shapes that are the same event: it answers a
// close that lands exactly on a boundary with io.EOF, and one that lands
// part-way through the bytes it was promised with io.ErrUnexpectedEOF. Either
// way the frame will never arrive and the session is finished, so both must
// classify as a connection failure rather than as an ordinary read error.
func isHangup(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// NetBIOS Session Service message types as defined in RFC 1001/1002
const (
	// SESSION_MESSAGE (0x00) - Normal session message containing SMB data
	MessageTypeSessionMessage byte = 0x00

	// SESSION_REQUEST (0x81) - Session establishment request
	MessageTypeSessionRequest byte = 0x81

	// POSITIVE_RESPONSE (0x82) - Session establishment successful
	MessageTypePositiveResponse byte = 0x82

	// NEGATIVE_RESPONSE (0x83) - Session establishment failed
	MessageTypeNegativeResponse byte = 0x83

	// RETARGET_RESPONSE (0x84) - Redirect to another address
	MessageTypeRetargetResponse byte = 0x84

	// SESSION_KEEP_ALIVE (0x85) - Keep-alive message
	MessageTypeSessionKeepAlive byte = 0x85
)

// MaxMessageSize is the maximum size for a NetBIOS session message.
// The length field is 17 bits, allowing for 2^17 = 131,072 bytes.
const MaxMessageSize = 131072

// ReadTimeout is the maximum time to wait for message data after reading the header.
// This prevents memory exhaustion attacks where a malicious server sends a valid
// length in the header but never sends the actual data, causing allocated memory
// to be held indefinitely. 30 seconds should be sufficient even for slow networks.
const ReadTimeout = 30 * time.Second

// Session wraps a TCP connection and provides NetBIOS session service framing.
// NetBIOS messages have a 4-byte header: [Type:1 byte][Length:3 bytes (big-endian)]
// followed by the message data.
type Session struct {
	conn net.Conn
}

// NewSession creates a new NetBIOS session that wraps the provided TCP connection.
// The connection should already be established (typically to port 445 for SMB).
func NewSession(conn net.Conn) *Session {
	// Enable TCP_NODELAY to disable Nagle's algorithm for lower latency.
	// SMB already has message framing, so we don't benefit from Nagle's buffering.
	// This can significantly improve performance for small-to-medium sized transfers.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	return &Session{
		conn: conn,
	}
}

// ReadPacket reads one NetBIOS-framed message from the connection.
// It returns the message data (without the NetBIOS header) or an error.
// The returned data should be processed according to the message type.
//
// Message format: [Type:1 byte][Length:3 bytes][Data:N bytes]
// The length field is 24 bits big-endian, but only the lower 17 bits are used.
func (s *Session) ReadPacket() ([]byte, error) {
	return s.ReadPacketContext(context.Background())
}

// ReadPacketContext reads one NetBIOS-framed message with context support.
// This allows for cancellation and timeout control during the read operation.
func (s *Session) ReadPacketContext(ctx context.Context) ([]byte, error) {
	logger := logging.FromContext(ctx)

	// Read the 4-byte header
	header := make([]byte, 4)

	// Check context before starting
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Set read deadline for the entire packet read (header + data) to prevent
	// memory exhaustion attacks. A malicious server could send a valid length
	// in the header but never send the actual data, causing allocated memory
	// to be held indefinitely. The deadline is cleared after reading completes.
	if err := s.conn.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		logger.Debug("netbios: failed to set read deadline: %v", err)
		return nil, fmt.Errorf("netbios: failed to set read deadline: %w", err)
	}
	defer func() {
		s.conn.SetReadDeadline(time.Time{})
	}()

	if _, err := io.ReadFull(s.conn, header); err != nil {
		if isHangup(err) {
			logger.Debug("netbios: connection closed during header read: %v", err)
			return nil, ErrConnectionClosed
		}
		logger.Debug("netbios: failed to read header: %v", err)
		return nil, fmt.Errorf("netbios: failed to read header: %w", err)
	}

	// Parse header: [Type:1 byte][Length:3 bytes big-endian]
	messageType := header[0]

	// Extract 24-bit length (big-endian), but only lower 17 bits are valid
	// Format: 0x00 | MSB | MID | LSB
	length := uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])

	// Validate length (only lower 17 bits should be used)
	if length > MaxMessageSize {
		logger.Debug("netbios: message size %d exceeds maximum %d", length, MaxMessageSize)
		return nil, fmt.Errorf("netbios: message size %d exceeds maximum %d", length, MaxMessageSize)
	}

	// Handle different message types
	switch messageType {
	case MessageTypeSessionMessage:
		// Most common case - contains SMB data
		logger.Debug("netbios: reading session message, length=%d", length)
		// Fall through to read the payload
	case MessageTypeSessionKeepAlive:
		// Keep-alive messages have zero length
		if length != 0 {
			logger.Debug("netbios: keep-alive message with invalid non-zero length %d", length)
			return nil, fmt.Errorf("netbios: keep-alive message with non-zero length %d", length)
		}
		logger.Debug("netbios: received keep-alive message")
		// Return empty data for keep-alive
		return []byte{}, nil
	case MessageTypePositiveResponse, MessageTypeNegativeResponse, MessageTypeRetargetResponse:
		// These are session establishment responses
		// Caller should handle these appropriately
		logger.Debug("netbios: reading session establishment response type=0x%02x, length=%d", messageType, length)
		// Fall through to read payload if present
	default:
		logger.Debug("netbios: unknown message type 0x%02x", messageType)
		return nil, fmt.Errorf("netbios: unknown message type 0x%02x", messageType)
	}

	// Handle zero-length messages
	if length == 0 {
		return []byte{}, nil
	}

	// Check context before reading data
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Read the message data
	data := make([]byte, length)
	if _, err := io.ReadFull(s.conn, data); err != nil {
		// The overwhelming majority of a transfer's wire time is spent here, so
		// this is where a peer dying mid-transfer is most likely to surface.
		if isHangup(err) {
			logger.Debug("netbios: connection closed during message data read: %v", err)
			return nil, ErrConnectionClosed
		}
		logger.Debug("netbios: failed to read message data: %v", err)
		return nil, fmt.Errorf("netbios: failed to read message data: %w", err)
	}

	logger.Debug("netbios: successfully read %d bytes", length)
	return data, nil
}

// WritePacket writes a NetBIOS-framed message to the connection.
// The data should be the SMB message payload; this function adds the NetBIOS header.
// By default, messages are sent as SESSION_MESSAGE type (0x00).
func (s *Session) WritePacket(data []byte) error {
	return s.WritePacketContext(context.Background(), data)
}

// WritePacketContext writes a NetBIOS-framed message with context support.
// This allows for cancellation and timeout control during the write operation.
func (s *Session) WritePacketContext(ctx context.Context, data []byte) error {
	return s.writePacketType(ctx, MessageTypeSessionMessage, data)
}

// writePacketType writes a NetBIOS message with a specific type.
// This is used internally to support different message types.
func (s *Session) writePacketType(ctx context.Context, msgType byte, data []byte) error {
	logger := logging.FromContext(ctx)

	// Check context before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Validate message size
	if len(data) > MaxMessageSize {
		logger.Debug("netbios: message size %d exceeds maximum %d", len(data), MaxMessageSize)
		return fmt.Errorf("netbios: message size %d exceeds maximum %d", len(data), MaxMessageSize)
	}

	logger.Debug("netbios: writing message type=0x%02x, length=%d", msgType, len(data))

	// Build the 4-byte header: [Type:1 byte][Length:3 bytes big-endian]
	// Encode 24-bit length in big-endian format
	length := uint32(len(data))
	header := [4]byte{
		msgType,
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	// Combine header and data into a single write to reduce syscalls and TCP packets.
	// This is especially important with TCP_NODELAY enabled.
	if len(data) > 0 {
		// Use writev-style approach: create a single buffer with header + data
		packet := make([]byte, 4+len(data))
		copy(packet[0:4], header[:])
		copy(packet[4:], data)

		if _, err := s.conn.Write(packet); err != nil {
			logger.Debug("netbios: failed to write packet: %v", err)
			return fmt.Errorf("netbios: failed to write packet: %w", err)
		}
	} else {
		// No data, just write header
		if _, err := s.conn.Write(header[:]); err != nil {
			logger.Debug("netbios: failed to write header: %v", err)
			return fmt.Errorf("netbios: failed to write header: %w", err)
		}
	}

	logger.Debug("netbios: successfully wrote %d bytes", len(data))
	return nil
}

// Close closes the underlying TCP connection.
func (s *Session) Close() error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// Conn returns the underlying net.Conn for advanced use cases.
// This should be used carefully as direct access bypasses NetBIOS framing.
func (s *Session) Conn() net.Conn {
	return s.conn
}

// LocalAddr returns the local network address.
func (s *Session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (s *Session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}
