package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// TestNewConn tests connection creation.
func TestNewConn(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)

	if c == nil {
		t.Fatal("NewConn returned nil")
	}

	if c.netbiosConn == nil {
		t.Error("netbiosConn is nil")
	}

	if c.pending == nil {
		t.Error("pending map is nil")
	}

	if c.done == nil {
		t.Error("done channel is nil")
	}
}

// TestConnClose tests connection close.
func TestConnClose(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)

	err := c.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Check that done is closed
	select {
	case <-c.done:
		// OK
	default:
		t.Error("done channel not closed")
	}

	// Closing again should not error
	err = c.Close()
	if err != nil {
		t.Errorf("Second Close returned error: %v", err)
	}
}

// TestAllocateMID tests message ID allocation.
func TestAllocateMID(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Allocate some MIDs
	var mids []uint16
	for i := 0; i < 10; i++ {
		c.mu.Lock()
		mid, err := c.allocateMID()
		c.mu.Unlock()
		if err != nil {
			t.Fatalf("allocateMID failed: %v", err)
		}
		mids = append(mids, mid)
	}

	// Check they are sequential
	for i := 0; i < len(mids); i++ {
		if mids[i] != uint16(i) {
			t.Errorf("MID %d: got %d, want %d", i, mids[i], i)
		}
	}
}

// TestAllocateMIDWrap tests message ID wraparound.
func TestAllocateMIDWrap(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Set nextMID to near max
	c.mu.Lock()
	c.nextMID = 65534
	c.mu.Unlock()

	// Allocate MIDs
	c.mu.Lock()
	mid1, err1 := c.allocateMID()
	mid2, err2 := c.allocateMID()
	mid3, err3 := c.allocateMID()
	c.mu.Unlock()

	if err1 != nil {
		t.Fatalf("allocateMID failed: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("allocateMID failed: %v", err2)
	}
	if err3 != nil {
		t.Fatalf("allocateMID failed: %v", err3)
	}

	if mid1 != 65534 {
		t.Errorf("mid1: got %d, want 65534", mid1)
	}
	if mid2 != 65535 {
		t.Errorf("mid2: got %d, want 65535", mid2)
	}
	if mid3 != 0 {
		t.Errorf("mid3: got %d, want 0", mid3)
	}
}

// TestAllocateMIDCollision tests that allocateMID detects and avoids collisions
// with pending MIDs.
func TestAllocateMIDCollision(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Fill up all MIDs by adding them to pending map
	// uint16 has 65536 possible values (0-65535)
	c.mu.Lock()
	for i := 0; i <= 65535; i++ {
		c.pending[uint16(i)] = &pendingRequest{respCh: make(chan *response, 1), cancelled: false}
	}
	c.nextMID = 0
	c.mu.Unlock()

	// Try to allocate a MID when all are in use
	c.mu.Lock()
	mid, err := c.allocateMID()
	c.mu.Unlock()

	if err == nil {
		t.Errorf("expected error when all MIDs in use, got MID %d", mid)
	}
	if mid != 0 {
		t.Errorf("expected MID 0 on error, got %d", mid)
	}

	// Free one MID and verify we can allocate it
	c.mu.Lock()
	delete(c.pending, 100)
	c.nextMID = 99
	c.mu.Unlock()

	c.mu.Lock()
	mid, err = c.allocateMID()
	c.mu.Unlock()

	if err != nil {
		t.Fatalf("expected successful allocation after freeing MID: %v", err)
	}
	if mid != 100 {
		t.Errorf("expected MID 100 (the free slot), got %d", mid)
	}
}

// TestAllocateMIDSkipsInUse tests that allocateMID skips over MIDs that are
// already in the pending map and finds the next available one.
func TestAllocateMIDSkipsInUse(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	// Add MIDs 0, 1, 2 to pending map
	c.mu.Lock()
	c.pending[0] = &pendingRequest{respCh: make(chan *response, 1), cancelled: false}
	c.pending[1] = &pendingRequest{respCh: make(chan *response, 1), cancelled: false}
	c.pending[2] = &pendingRequest{respCh: make(chan *response, 1), cancelled: false}
	c.nextMID = 0
	c.mu.Unlock()

	// Allocate next MID - should skip 0, 1, 2 and return 3
	c.mu.Lock()
	mid, err := c.allocateMID()
	c.mu.Unlock()

	if err != nil {
		t.Fatalf("allocateMID failed: %v", err)
	}
	if mid != 3 {
		t.Errorf("expected MID 3 (first free slot), got %d", mid)
	}
}

// TestSend tests sending a request.
func TestSend(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)
	defer c.Close()

	header := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
	params := []byte{0x00, 0x00}
	data := []byte("test")

	err := c.send(header, params, data)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// MID 0 is valid - just check it was allocated
	// (We can't check exact value since it depends on allocation order)

	// Check that data was written
	mockTCP.mu.Lock()
	written := len(mockTCP.writeBuf)
	mockTCP.mu.Unlock()

	if written == 0 {
		t.Error("no data written")
	}
}

// TestSendRecv tests send and receive.
func TestSendRecv(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockTCP := newMockConn()
		c := NewConn(mockTCP)
		defer c.Close()

		// Start receive goroutine
		go c.Receive()

		// Prepare response
		respHeader := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
		respHeader.Flags |= smb1.SMB_FLAGS_REPLY
		respHeader.Status = smb1.STATUS_SUCCESS
		respHeader.MID = 0 // Will be updated by send

		respParams := []byte{0x00, 0x00}
		respData := []byte("response")

		// Send request in goroutine
		ctx := context.Background()
		var resp *response
		var err error
		done := make(chan struct{})

		go func() {
			header := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
			params := []byte{0x00, 0x00}
			data := []byte("request")

			resp, err = c.sendRecv(header, params, data, ctx)
			close(done)
		}()

		// Wait a bit for request to be sent
		time.Sleep(10 * time.Millisecond)

		// Add response to mock connection
		mockTCP.mu.Lock()
		// Get the MID from the request
		// In real scenario, we'd parse the written data
		// For now, we know it's MID 0
		respHeader.MID = 0
		mockTCP.mu.Unlock()

		mockTCP.addResponse(respHeader, respParams, respData)

		// Wait for response
		select {
		case <-done:
			if err != nil {
				t.Fatalf("sendRecv failed: %v", err)
			}
			if resp == nil {
				t.Fatal("response is nil")
			}
			if resp.header.Status != smb1.STATUS_SUCCESS {
				t.Errorf("status: got 0x%08X, want 0x%08X", resp.header.Status, smb1.STATUS_SUCCESS)
			}
			if string(resp.data) != "response" {
				t.Errorf("data: got %q, want %q", string(resp.data), "response")
			}
		case <-time.After(1 * time.Second):
			t.Fatal("sendRecv timed out")
		}
	})
}

// TestSendRecvContextCancel tests context cancellation.
func TestSendRecvContextCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockTCP := newMockConn()
		c := NewConn(mockTCP)
		defer c.Close()

		// Start receive goroutine
		go c.Receive()

		ctx, cancel := context.WithCancel(context.Background())

		// Send request in goroutine
		done := make(chan struct{})
		var err error

		go func() {
			header := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
			params := []byte{0x00, 0x00}
			data := []byte("request")

			_, err = c.sendRecv(header, params, data, ctx)
			close(done)
		}()

		// Wait a bit then cancel
		time.Sleep(10 * time.Millisecond)
		cancel()

		// Wait for sendRecv to return
		select {
		case <-done:
			if err != context.Canceled {
				t.Errorf("expected context.Canceled, got %v", err)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("sendRecv did not return after context cancel")
		}
	})
}

// TestConcurrentOperations tests concurrent send/recv operations.
func TestConcurrentOperations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockTCP := newMockConn()
		c := NewConn(mockTCP)
		defer c.Close()

		// Start receive goroutine
		go c.Receive()

		// Send multiple requests concurrently
		var wg sync.WaitGroup
		ctx := context.Background()

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				header := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
				params := []byte{0x00, 0x00}
				data := []byte("request")

				resp, err := c.sendRecv(header, params, data, ctx)
				if err != nil {
					t.Errorf("request %d failed: %v", idx, err)
					return
				}
				if resp == nil {
					t.Errorf("request %d: response is nil", idx)
				}
			}(i)
		}

		// Wait for all requests to be sent
		time.Sleep(10 * time.Millisecond)

		// Now prepare responses for all 5 requests
		for i := 0; i < 5; i++ {
			respHeader := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
			respHeader.Flags |= smb1.SMB_FLAGS_REPLY
			respHeader.Status = smb1.STATUS_SUCCESS
			respHeader.MID = uint16(i)

			respParams := []byte{0x00, 0x00}
			respData := []byte("response")

			mockTCP.addResponse(respHeader, respParams, respData)
		}

		wg.Wait()
	})
}

// TestSetError tests error propagation.
func TestSetError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockTCP := newMockConn()
		c := NewConn(mockTCP)
		defer c.Close()

		testErr := errors.New("test error")

		// Add a pending request
		c.mu.Lock()
		respCh := make(chan *response, 1)
		c.pending[123] = &pendingRequest{respCh: respCh, cancelled: false}
		c.mu.Unlock()

		// Set error
		c.setError(testErr)

		// Check that error was set
		c.mu.Lock()
		if c.err != testErr {
			t.Errorf("error not set: got %v, want %v", c.err, testErr)
		}

		// Check that done is closed
		select {
		case <-c.done:
			// OK
		default:
			t.Error("done channel not closed")
		}
		c.mu.Unlock()

		// Check that pending request was woken
		select {
		case resp := <-respCh:
			if resp.err != testErr {
				t.Errorf("pending request error: got %v, want %v", resp.err, testErr)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("pending request not woken")
		}

		// Check that pending map was cleared
		c.mu.Lock()
		if len(c.pending) != 0 {
			t.Errorf("pending map not cleared: %d entries", len(c.pending))
		}
		c.mu.Unlock()
	})
}

// TestSendAfterClose tests sending after connection is closed.
func TestSendAfterClose(t *testing.T) {
	mockTCP := newMockConn()
	c := NewConn(mockTCP)

	// Close connection
	c.Close()

	// Try to send
	header := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
	params := []byte{0x00, 0x00}
	data := []byte("test")

	err := c.send(header, params, data)
	if err == nil {
		t.Error("send after close should return error")
	}
}
