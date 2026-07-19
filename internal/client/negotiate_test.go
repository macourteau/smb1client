package client

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// testSystemTime is 2020-01-01T00:00:00Z as a Windows FILETIME
// (100-nanosecond intervals since 1601-01-01 UTC).
const testSystemTime = uint64(132223104000000000)

// TestNegotiateSuccess tests successful negotiation.
func TestNegotiateSuccess(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Start receive goroutine
	go c.Receive()

	// Prepare successful negotiate response
	respParams := make([]byte, 34)
	respParams[0] = 0    // DialectIndex (low)
	respParams[1] = 0    // DialectIndex (high)
	respParams[2] = 0x02 // SecurityMode (NEGOTIATE_ENCRYPT_PASSWORDS)

	// MaxMpxCount
	respParams[3] = 50
	respParams[4] = 0

	// MaxNumberVcs
	respParams[5] = 1
	respParams[6] = 0

	// MaxBufferSize
	respParams[7] = 0x04
	respParams[8] = 0x11
	respParams[9] = 0x00
	respParams[10] = 0x00

	// MaxRawSize
	respParams[11] = 0x00
	respParams[12] = 0x00
	respParams[13] = 0x01
	respParams[14] = 0x00

	// SessionKey
	respParams[15] = 0
	respParams[16] = 0
	respParams[17] = 0
	respParams[18] = 0

	// Capabilities (NT_SMBS | UNICODE | LARGE_FILES | STATUS32)
	caps := smb1.CAP_NT_SMBS | smb1.CAP_UNICODE | smb1.CAP_LARGE_FILES | smb1.CAP_STATUS32
	respParams[19] = byte(caps)
	respParams[20] = byte(caps >> 8)
	respParams[21] = byte(caps >> 16)
	respParams[22] = byte(caps >> 24)

	// SystemTime (8 bytes, Windows FILETIME)
	binary.LittleEndian.PutUint64(respParams[23:31], testSystemTime)

	// ServerTimeZone (2 bytes, minutes from UTC)
	binary.LittleEndian.PutUint16(respParams[31:33], uint16(int16(300)))

	// ChallengeLength
	respParams[33] = 8 // 8-byte challenge

	// Data: challenge + domain + server
	respData := make([]byte, 8)
	for i := 0; i < 8; i++ {
		respData[i] = byte(i) // challenge
	}

	// Send negotiate in goroutine
	ctx := context.Background()
	done := make(chan struct{})
	var err error

	go func() {
		err = Negotiate(c, ctx)
		close(done)
	}()

	// Wait a bit for request
	time.Sleep(10 * time.Millisecond)

	// Add response
	respHeader := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = 0

	mockTCP.addResponse(respHeader, respParams, respData)

	// Wait for negotiate to complete
	select {
	case <-done:
		if err != nil {
			t.Fatalf("Negotiate failed: %v", err)
		}

		// Check negotiated parameters
		c.mu.Lock()
		if c.capabilities != caps {
			t.Errorf("capabilities: got 0x%08X, want 0x%08X", c.capabilities, caps)
		}
		if c.maxBufferSize != 0x00001104 {
			t.Errorf("maxBufferSize: got 0x%08X, want 0x%08X", c.maxBufferSize, 0x00001104)
		}
		if c.maxMpxCount != 50 {
			t.Errorf("maxMpxCount: got %d, want %d", c.maxMpxCount, 50)
		}
		if c.securityMode != 0x02 {
			t.Errorf("securityMode: got 0x%02X, want 0x02", c.securityMode)
		}
		if len(c.challenge) != 8 {
			t.Errorf("challenge length: got %d, want 8", len(c.challenge))
		}
		if c.systemTime != testSystemTime {
			t.Errorf("systemTime: got %d, want %d", c.systemTime, testSystemTime)
		}
		if c.timeZone != 300 {
			t.Errorf("timeZone: got %d, want 300", c.timeZone)
		}
		if c.negotiateTime.IsZero() {
			t.Error("negotiateTime: got zero time, want local receive time")
		}
		c.mu.Unlock()

	case <-time.After(1 * time.Second):
		t.Fatal("Negotiate timed out")
	}
}

// TestNegotiateNoDialect tests negotiate with no matching dialect.
func TestNegotiateNoDialect(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Start receive goroutine
	go c.Receive()

	// Prepare response with DialectIndex = 0xFFFF
	respParams := make([]byte, 34)
	respParams[0] = 0xFF
	respParams[1] = 0xFF

	// Send negotiate in goroutine
	ctx := context.Background()
	done := make(chan struct{})
	var err error

	go func() {
		err = Negotiate(c, ctx)
		close(done)
	}()

	// Wait a bit for request
	time.Sleep(10 * time.Millisecond)

	// Add response
	respHeader := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = 0

	mockTCP.addResponse(respHeader, respParams, nil)

	// Wait for negotiate to complete
	select {
	case <-done:
		if err == nil {
			t.Fatal("Negotiate should have failed with no dialect")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Negotiate timed out")
	}
}

// TestNegotiateMissingCapabilities tests negotiate with missing required capabilities.
func TestNegotiateMissingCapabilities(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Start receive goroutine
	go c.Receive()

	// Prepare response with insufficient capabilities
	respParams := make([]byte, 34)
	respParams[0] = 0    // DialectIndex
	respParams[1] = 0    //
	respParams[2] = 0x02 // SecurityMode

	// Only set CAP_UNICODE, missing other required caps
	caps := smb1.CAP_UNICODE
	respParams[19] = byte(caps)
	respParams[20] = byte(caps >> 8)
	respParams[21] = byte(caps >> 16)
	respParams[22] = byte(caps >> 24)

	respParams[33] = 0 // ChallengeLength

	// Send negotiate in goroutine
	ctx := context.Background()
	done := make(chan struct{})
	var err error

	go func() {
		err = Negotiate(c, ctx)
		close(done)
	}()

	// Wait a bit for request
	time.Sleep(10 * time.Millisecond)

	// Add response
	respHeader := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = 0

	mockTCP.addResponse(respHeader, respParams, nil)

	// Wait for negotiate to complete
	select {
	case <-done:
		if err == nil {
			t.Fatal("Negotiate should have failed with missing capabilities")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Negotiate timed out")
	}
}

// TestNegotiateNoEncryption tests negotiate with server not requiring encryption.
func TestNegotiateNoEncryption(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Start receive goroutine
	go c.Receive()

	// Prepare response without encrypted passwords
	respParams := make([]byte, 34)
	respParams[0] = 0   // DialectIndex
	respParams[1] = 0   //
	respParams[2] = 0x0 // SecurityMode (no NEGOTIATE_ENCRYPT_PASSWORDS)

	// Set all required capabilities
	caps := smb1.CAP_NT_SMBS | smb1.CAP_UNICODE | smb1.CAP_LARGE_FILES | smb1.CAP_STATUS32
	respParams[19] = byte(caps)
	respParams[20] = byte(caps >> 8)
	respParams[21] = byte(caps >> 16)
	respParams[22] = byte(caps >> 24)

	respParams[33] = 0 // ChallengeLength

	// Send negotiate in goroutine
	ctx := context.Background()
	done := make(chan struct{})
	var err error

	go func() {
		err = Negotiate(c, ctx)
		close(done)
	}()

	// Wait a bit for request
	time.Sleep(10 * time.Millisecond)

	// Add response
	respHeader := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = 0

	mockTCP.addResponse(respHeader, respParams, nil)

	// Wait for negotiate to complete
	select {
	case <-done:
		if err == nil {
			t.Fatal("Negotiate should have failed without encryption requirement")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Negotiate timed out")
	}
}

// TestNegotiateContextCancel tests negotiate with context cancellation.
func TestNegotiateContextCancel(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Start receive goroutine
	go c.Receive()

	ctx, cancel := context.WithCancel(context.Background())

	// Send negotiate in goroutine
	done := make(chan struct{})
	var err error

	go func() {
		err = Negotiate(c, ctx)
		close(done)
	}()

	// Wait a bit then cancel
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Wait for negotiate to return
	select {
	case <-done:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Negotiate did not return after context cancel")
	}
}

// TestConnServerTime tests the Conn.ServerTime accessor.
func TestConnServerTime(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	received := time.Date(2020, 1, 1, 0, 0, 1, 0, time.UTC)

	c.mu.Lock()
	c.systemTime = testSystemTime
	c.timeZone = -60
	c.negotiateTime = received
	c.mu.Unlock()

	systemTime, timeZoneMinutes, receivedAt := c.ServerTime()
	if systemTime != testSystemTime {
		t.Errorf("systemTime: got %d, want %d", systemTime, testSystemTime)
	}
	if timeZoneMinutes != -60 {
		t.Errorf("timeZoneMinutes: got %d, want -60", timeZoneMinutes)
	}
	if !receivedAt.Equal(received) {
		t.Errorf("receivedAt: got %v, want %v", receivedAt, received)
	}
}

// TestNegotiateServerError tests negotiate with server error response.
func TestNegotiateServerError(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Start receive goroutine
	go c.Receive()

	// Send negotiate in goroutine
	ctx := context.Background()
	done := make(chan struct{})
	var err error

	go func() {
		err = Negotiate(c, ctx)
		close(done)
	}()

	// Wait a bit for request
	time.Sleep(10 * time.Millisecond)

	// Add error response
	respHeader := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_ACCESS_DENIED
	respHeader.MID = 0

	mockTCP.addResponse(respHeader, nil, nil)

	// Wait for negotiate to complete
	select {
	case <-done:
		if err == nil {
			t.Fatal("Negotiate should have failed with server error")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Negotiate timed out")
	}
}
