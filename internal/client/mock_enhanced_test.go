package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// SMBRequest represents a decoded SMB request that was sent by the client.
// It provides a high-level view of the request for test inspection and response generation.
type SMBRequest struct {
	// Core SMB header fields
	MID     uint16 // Multiplex ID (for request/response matching)
	Command byte   // SMB command code
	TID     uint16 // Tree ID (share connection)
	FID     uint16 // File ID (for file operations)
	PID     uint16 // Process ID (low 16 bits)
	UID     uint16 // User ID (session)

	// Full header and packet data
	Header *smb1.Header
	Params []byte // Parameters section (after WordCount)
	Data   []byte // Data section (after ByteCount)

	// Timestamp for debugging
	Timestamp time.Time

	// Command-specific decoded fields
	// For READ_ANDX requests
	ReadOffset uint64
	ReadLength uint32

	// For WRITE_ANDX requests
	WriteOffset uint64
	WriteData   []byte
}

// mockResponse represents a queued response for a specific MID.
type mockResponse struct {
	header *smb1.Header
	params []byte
	data   []byte
}

// EnhancedMockConn provides advanced mocking capabilities for testing pipelined operations.
// It tracks all requests, allows controlled response delivery, and integrates with synctest
// for deterministic testing of concurrent operations.
//
// Key features:
//   - Request tracking: All sent requests are stored and inspectable
//   - Controlled responses: Queue specific responses for MIDs or use auto-responder
//   - Synctest integration: Buffered channels and helpers for deterministic scheduling
//   - Thread-safe: All methods use proper synchronization
//
// Example usage:
//
//	mock := newEnhancedMockConn()
//
//	// Queue a response for a specific MID
//	header, params, data := CreateReadResponse(1, []byte("hello"))
//	mock.QueueResponse(1, header, params, data)
//
//	// Or use an auto-responder
//	mock.SetAutoResponder(func(req SMBRequest) (*smb1.Header, []byte, []byte) {
//	    if req.Command == smb1.SMB_COM_READ_ANDX {
//	        return CreateReadResponse(req.MID, []byte("data"))
//	    }
//	    return nil, nil, nil
//	})
//
//	// Wait for requests in tests
//	if ok := mock.WaitForRequests(2, 5*time.Second); ok {
//	    requests := mock.GetRequests()
//	    // Inspect requests...
//	}
type EnhancedMockConn struct {
	mu sync.Mutex

	// Request tracking
	requests []SMBRequest // All requests sent, in order

	// Response management
	responseQueue map[uint16]mockResponse // MID → queued response
	autoResponder func(req SMBRequest) (header *smb1.Header, params, data []byte)

	// Underlying mock for actual I/O
	inner *mockConn

	// Synctest integration
	newRequestCh chan SMBRequest // Signals when new request arrives (buffered for synctest)

	// Logging for debugging
	t *testing.T
}

// newEnhancedMockConn creates a new EnhancedMockConn.
// The connection starts with no queued responses and no auto-responder.
func newEnhancedMockConn() *EnhancedMockConn {
	return &EnhancedMockConn{
		requests:      make([]SMBRequest, 0),
		responseQueue: make(map[uint16]mockResponse),
		inner:         newMockConn(),
		newRequestCh:  make(chan SMBRequest, 100), // Buffered for synctest
	}
}

// newEnhancedMockConnWithLogging creates a new EnhancedMockConn with test logging.
// Logs will be written using t.Logf for debugging test failures.
func newEnhancedMockConnWithLogging(t *testing.T) *EnhancedMockConn {
	mock := newEnhancedMockConn()
	mock.t = t
	return mock
}

// Write intercepts outgoing data, decodes SMB requests, and queues responses.
// This is the core method that enables request tracking and controlled response delivery.
//
// The method:
// 1. Strips the NetBIOS header (4 bytes)
// 2. Decodes the SMB packet to extract request details
// 3. Stores the request in the requests slice
// 4. Sends notification to newRequestCh for synctest integration
// 5. Checks if we have a queued response for this MID
// 6. If no queued response, uses autoResponder (if set)
// 7. Queues the response (if any) for Read() to return
func (m *EnhancedMockConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.inner.closed {
		return 0, io.EOF
	}

	// Pass through to inner mock (it stores the written data)
	n, err := m.inner.Write(b)
	if err != nil {
		return n, err
	}

	// Decode the request
	// The data includes the NetBIOS header (4 bytes), which we need to strip
	if len(b) < 4 {
		if m.t != nil {
			m.t.Logf("EnhancedMockConn.Write: packet too short for NetBIOS header: %d bytes", len(b))
		}
		return n, nil // Not enough data for a full packet
	}

	// Strip NetBIOS header (4 bytes)
	smbPacket := b[4:]

	// Decode the SMB packet
	req, err := decodeSMBRequest(smbPacket)
	if err != nil {
		if m.t != nil {
			m.t.Logf("EnhancedMockConn.Write: failed to decode SMB request: %v", err)
		}
		return n, nil // Continue even if decode fails
	}

	// Store the request
	m.requests = append(m.requests, *req)

	if m.t != nil {
		m.t.Logf("EnhancedMockConn: Request #%d: MID=%d Command=0x%02X TID=%d FID=%d",
			len(m.requests), req.MID, req.Command, req.TID, req.FID)
	}

	// Notify waiters (non-blocking)
	select {
	case m.newRequestCh <- *req:
	default:
		// Channel full, skip notification
		if m.t != nil {
			m.t.Logf("EnhancedMockConn: newRequestCh full, skipping notification")
		}
	}

	// Check if we have a queued response for this MID
	var response *mockResponse
	if resp, ok := m.responseQueue[req.MID]; ok {
		response = &resp
		delete(m.responseQueue, req.MID)
		if m.t != nil {
			m.t.Logf("EnhancedMockConn: Using queued response for MID=%d", req.MID)
		}
	} else if m.autoResponder != nil {
		// Use auto-responder
		header, params, data := m.autoResponder(*req)
		if header != nil {
			response = &mockResponse{
				header: header,
				params: params,
				data:   data,
			}
			if m.t != nil {
				m.t.Logf("EnhancedMockConn: Using auto-responder for MID=%d", req.MID)
			}
		}
	}

	// Queue the response if we have one
	if response != nil {
		m.inner.addResponse(response.header, response.params, response.data)
	}

	return n, nil
}

// Read reads data from the mock connection.
// This delegates to the inner mock connection.
func (m *EnhancedMockConn) Read(b []byte) (int, error) {
	return m.inner.Read(b)
}

// Close closes the mock connection.
func (m *EnhancedMockConn) Close() error {
	return m.inner.Close()
}

// LocalAddr returns the local network address.
func (m *EnhancedMockConn) LocalAddr() net.Addr {
	return m.inner.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (m *EnhancedMockConn) RemoteAddr() net.Addr {
	return m.inner.RemoteAddr()
}

// SetDeadline sets the read and write deadlines.
func (m *EnhancedMockConn) SetDeadline(t time.Time) error {
	return m.inner.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (m *EnhancedMockConn) SetReadDeadline(t time.Time) error {
	return m.inner.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
func (m *EnhancedMockConn) SetWriteDeadline(t time.Time) error {
	return m.inner.SetWriteDeadline(t)
}

// GetRequests returns all requests sent so far.
// The returned slice is a copy and safe to use without holding locks.
func (m *EnhancedMockConn) GetRequests() []SMBRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]SMBRequest, len(m.requests))
	copy(result, m.requests)
	return result
}

// GetRequestsByCommand returns all requests matching a specific command.
func (m *EnhancedMockConn) GetRequestsByCommand(cmd byte) []SMBRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []SMBRequest
	for _, req := range m.requests {
		if req.Command == cmd {
			result = append(result, req)
		}
	}
	return result
}

// GetRequestByMID returns the request with the specified MID.
// Returns nil if no request with that MID was found.
func (m *EnhancedMockConn) GetRequestByMID(mid uint16) *SMBRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.requests {
		if m.requests[i].MID == mid {
			req := m.requests[i]
			return &req
		}
	}
	return nil
}

// GetRequestCount returns the number of requests sent so far.
func (m *EnhancedMockConn) GetRequestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.requests)
}

// WaitForRequests blocks until at least count requests have been sent.
// Returns true if the count was reached, false if the timeout expired.
// This method works with synctest for deterministic testing.
func (m *EnhancedMockConn) WaitForRequests(count int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		m.mu.Lock()
		currentCount := len(m.requests)
		m.mu.Unlock()

		if currentCount >= count {
			return true
		}

		// Yield to let goroutines run
		// In synctest mode, this advances virtual time
		time.Sleep(10 * time.Millisecond)
	}

	return false
}

// WaitForRequest waits for a request matching the predicate.
// Uses polling with time.Sleep for deterministic testing with synctest.
// Returns the matching request and true, or nil and false if timeout expires.
func (m *EnhancedMockConn) WaitForRequest(
	predicate func(SMBRequest) bool,
	timeout time.Duration,
) (*SMBRequest, bool) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		m.mu.Lock()
		for i := range m.requests {
			if predicate(m.requests[i]) {
				req := m.requests[i]
				m.mu.Unlock()
				return &req, true
			}
		}
		m.mu.Unlock()

		// Yield to let goroutines run
		time.Sleep(10 * time.Millisecond)
	}

	return nil, false
}

// QueueResponse queues a response for a specific MID.
// The response will be returned when a request with that MID is sent.
// If a response is already queued for this MID, it will be replaced.
func (m *EnhancedMockConn) QueueResponse(mid uint16, header *smb1.Header, params, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.responseQueue[mid] = mockResponse{
		header: header,
		params: params,
		data:   data,
	}

	if m.t != nil {
		m.t.Logf("EnhancedMockConn: Queued response for MID=%d", mid)
	}
}

// SetAutoResponder sets a function that automatically generates responses.
// The function is called for each request if no queued response exists for that MID.
// If the function returns nil for the header, no response is sent.
// Set to nil to disable auto-responding.
func (m *EnhancedMockConn) SetAutoResponder(fn func(SMBRequest) (*smb1.Header, []byte, []byte)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.autoResponder = fn

	if m.t != nil {
		if fn == nil {
			m.t.Logf("EnhancedMockConn: Auto-responder disabled")
		} else {
			m.t.Logf("EnhancedMockConn: Auto-responder enabled")
		}
	}
}

// ClearRequests clears the request history.
// Useful for tests that want to reset state between operations.
func (m *EnhancedMockConn) ClearRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.requests = make([]SMBRequest, 0)

	if m.t != nil {
		m.t.Logf("EnhancedMockConn: Cleared request history")
	}
}

// ClearResponseQueue clears all queued responses.
func (m *EnhancedMockConn) ClearResponseQueue() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.responseQueue = make(map[uint16]mockResponse)

	if m.t != nil {
		m.t.Logf("EnhancedMockConn: Cleared response queue")
	}
}

// decodeSMBRequest decodes an SMB packet and extracts request information.
// The input should be the SMB packet without the NetBIOS header.
func decodeSMBRequest(packet []byte) (*SMBRequest, error) {
	// Decode the SMB packet
	header, params, data, err := smb1.DecodePacket(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SMB packet: %w", err)
	}

	req := &SMBRequest{
		MID:       header.MID,
		Command:   header.Command,
		TID:       header.TID,
		PID:       header.PIDLow,
		UID:       header.UID,
		Header:    header,
		Params:    params,
		Data:      data,
		Timestamp: time.Now(),
	}

	// Decode command-specific fields
	switch header.Command {
	case smb1.SMB_COM_READ_ANDX:
		if len(params) >= 20 {
			req.FID = binary.LittleEndian.Uint16(params[4:6])
			offsetLow := binary.LittleEndian.Uint32(params[6:10])
			req.ReadLength = uint32(binary.LittleEndian.Uint16(params[10:12]))

			// Check if we have OffsetHigh (WordCount = 12)
			if len(params) >= 24 {
				offsetHigh := binary.LittleEndian.Uint32(params[20:24])
				req.ReadOffset = uint64(offsetLow) | (uint64(offsetHigh) << 32)
			} else {
				req.ReadOffset = uint64(offsetLow)
			}
		}

	case smb1.SMB_COM_WRITE_ANDX:
		if len(params) >= 24 {
			req.FID = binary.LittleEndian.Uint16(params[4:6])
			offsetLow := binary.LittleEndian.Uint32(params[6:10])
			dataLength := binary.LittleEndian.Uint16(params[20:22])
			dataLengthHigh := binary.LittleEndian.Uint16(params[18:20])
			totalLength := uint32(dataLength) | (uint32(dataLengthHigh) << 16)

			// Check if we have OffsetHigh (WordCount = 14)
			if len(params) >= 28 {
				offsetHigh := binary.LittleEndian.Uint32(params[24:28])
				req.WriteOffset = uint64(offsetLow) | (uint64(offsetHigh) << 32)
			} else {
				req.WriteOffset = uint64(offsetLow)
			}

			// Extract write data
			if totalLength > 0 && int(totalLength) <= len(data) {
				req.WriteData = make([]byte, totalLength)
				copy(req.WriteData, data[:totalLength])
			}
		}

	case smb1.SMB_COM_NT_CREATE_ANDX, smb1.SMB_COM_CLOSE:
		if len(params) >= 6 {
			req.FID = binary.LittleEndian.Uint16(params[0:2])
		}
	}

	return req, nil
}

// CreateReadResponse is a helper to create a READ_ANDX response.
// The response will have the SMB_FLAGS_REPLY flag set and STATUS_SUCCESS.
func CreateReadResponse(mid uint16, data []byte) (*smb1.Header, []byte, []byte) {
	header := smb1.NewHeader(smb1.SMB_COM_READ_ANDX)
	header.MID = mid
	header.Status = smb1.STATUS_SUCCESS
	header.Flags |= smb1.SMB_FLAGS_REPLY

	// Calculate data length (split into low and high parts)
	dataLength := uint16(len(data) & 0xFFFF)
	dataLengthHigh := uint32(len(data) >> 16)

	// Calculate DataOffset: Header(32) + WordCount(1) + Params(24) + ByteCount(2) = 59
	dataOffset := uint16(smb1.HeaderSize + 1 + 24 + 2)

	// Build READ_ANDX response parameters (WordCount = 12, 24 bytes)
	params := make([]byte, 24)
	params[0] = smb1.SMB_COM_NO_ANDX_COMMAND                     // AndXCommand
	params[1] = 0                                                // AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], 0)                // AndXOffset
	binary.LittleEndian.PutUint16(params[4:6], 0)                // Remaining
	binary.LittleEndian.PutUint16(params[6:8], 0)                // DataCompactionMode
	binary.LittleEndian.PutUint16(params[8:10], 0)               // Reserved
	binary.LittleEndian.PutUint16(params[10:12], dataLength)     // DataLength
	binary.LittleEndian.PutUint16(params[12:14], dataOffset)     // DataOffset
	binary.LittleEndian.PutUint32(params[14:18], dataLengthHigh) // DataLengthHigh
	// params[18:24] are reserved

	return header, params, data
}

// CreateWriteResponse is a helper to create a WRITE_ANDX response.
// The response will have the SMB_FLAGS_REPLY flag set and STATUS_SUCCESS.
func CreateWriteResponse(mid uint16, bytesWritten uint32) (*smb1.Header, []byte, []byte) {
	header := smb1.NewHeader(smb1.SMB_COM_WRITE_ANDX)
	header.MID = mid
	header.Status = smb1.STATUS_SUCCESS
	header.Flags |= smb1.SMB_FLAGS_REPLY

	// Split bytes written into low and high parts
	countLow := uint16(bytesWritten & 0xFFFF)
	countHigh := uint32(bytesWritten >> 16)

	// Build WRITE_ANDX response parameters (WordCount = 6, 12 bytes)
	params := make([]byte, 12)
	params[0] = smb1.SMB_COM_NO_ANDX_COMMAND               // AndXCommand
	params[1] = 0                                          // AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], 0)          // AndXOffset
	binary.LittleEndian.PutUint16(params[4:6], countLow)   // Count
	binary.LittleEndian.PutUint16(params[6:8], 0)          // Remaining
	binary.LittleEndian.PutUint32(params[8:12], countHigh) // CountHigh

	return header, params, []byte{}
}

// CreateErrorResponse creates an error response for any command.
// The response will have the SMB_FLAGS_REPLY flag set and the specified status code.
func CreateErrorResponse(mid uint16, command byte, status uint32) (*smb1.Header, []byte, []byte) {
	header := smb1.NewHeader(command)
	header.MID = mid
	header.Status = status
	header.Flags |= smb1.SMB_FLAGS_REPLY

	// Empty response (WordCount = 0, ByteCount = 0)
	return header, []byte{}, []byte{}
}

// CreateNTCreateResponse creates an NT_CREATE_ANDX response.
// The response will have the SMB_FLAGS_REPLY flag set and STATUS_SUCCESS.
func CreateNTCreateResponse(mid uint16, fid uint16, isDirectory bool, fileSize uint64) (*smb1.Header, []byte, []byte) {
	header := smb1.NewHeader(smb1.SMB_COM_NT_CREATE_ANDX)
	header.MID = mid
	header.Status = smb1.STATUS_SUCCESS
	header.Flags |= smb1.SMB_FLAGS_REPLY

	// Build NT_CREATE_ANDX response parameters (WordCount = 34, 68 bytes)
	params := make([]byte, 68)
	params[0] = smb1.SMB_COM_NO_ANDX_COMMAND                      // AndXCommand
	params[1] = 0                                                 // AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], 0)                 // AndXOffset
	params[4] = smb1.OPLOCK_NONE                                  // OpLockLevel
	binary.LittleEndian.PutUint16(params[5:7], fid)               // FID
	binary.LittleEndian.PutUint32(params[7:11], smb1.FILE_OPENED) // CreateAction
	binary.LittleEndian.PutUint64(params[11:19], 0)               // CreationTime
	binary.LittleEndian.PutUint64(params[19:27], 0)               // LastAccessTime
	binary.LittleEndian.PutUint64(params[27:35], 0)               // LastWriteTime
	binary.LittleEndian.PutUint64(params[35:43], 0)               // ChangeTime

	fileAttributes := smb1.FILE_ATTRIBUTE_NORMAL
	if isDirectory {
		fileAttributes = smb1.FILE_ATTRIBUTE_DIRECTORY
	}
	binary.LittleEndian.PutUint32(params[43:47], fileAttributes)      // FileAttributes
	binary.LittleEndian.PutUint64(params[47:55], fileSize)            // AllocationSize
	binary.LittleEndian.PutUint64(params[55:63], fileSize)            // EndOfFile
	binary.LittleEndian.PutUint16(params[63:65], smb1.FILE_TYPE_DISK) // FileType
	binary.LittleEndian.PutUint16(params[65:67], 0)                   // IPCState
	if isDirectory {
		params[67] = 1 // IsDirectory
	} else {
		params[67] = 0
	}

	return header, params, []byte{}
}

// CreateCloseResponse creates a CLOSE response.
// The response will have the SMB_FLAGS_REPLY flag set and STATUS_SUCCESS.
func CreateCloseResponse(mid uint16) (*smb1.Header, []byte, []byte) {
	header := smb1.NewHeader(smb1.SMB_COM_CLOSE)
	header.MID = mid
	header.Status = smb1.STATUS_SUCCESS
	header.Flags |= smb1.SMB_FLAGS_REPLY

	// CLOSE response is empty (WordCount = 0, ByteCount = 0)
	return header, []byte{}, []byte{}
}
