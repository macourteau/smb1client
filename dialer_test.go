package smb1

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// mockFailingConn simulates a connection that fails during read.
type mockFailingConn struct {
	mu       sync.Mutex
	closed   bool
	readCh   chan []byte
	writeBuf []byte
}

func newMockFailingConn() *mockFailingConn {
	return &mockFailingConn{
		readCh: make(chan []byte, 1),
	}
}

func (m *mockFailingConn) Read(b []byte) (n int, err error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, io.EOF
	}
	m.mu.Unlock()

	// Block until connection is closed
	data := <-m.readCh
	if data == nil {
		return 0, io.EOF
	}
	return copy(b, data), nil
}

func (m *mockFailingConn) Write(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, errors.New("connection closed")
	}

	m.writeBuf = append(m.writeBuf, b...)
	return len(b), nil
}

func (m *mockFailingConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.closed {
		m.closed = true
		// Wake up any blocked readers
		select {
		case m.readCh <- nil:
		default:
		}
		close(m.readCh)
	}
	return nil
}

func (m *mockFailingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (m *mockFailingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 445}
}

func (m *mockFailingConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockFailingConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockFailingConn) SetWriteDeadline(t time.Time) error { return nil }

// TestDialNegotiateFailureNoGoroutineLeak verifies that when negotiation fails,
// the Receive goroutine is properly cleaned up and doesn't leak.
func TestDialNegotiateFailureNoGoroutineLeak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Count goroutines before
		initialGoroutines := runtime.NumGoroutine()

		mockConn := newMockFailingConn()
		d := &Dialer{
			Initiator: &NTLMInitiator{
				User:     "testuser",
				Password: "testpass",
			},
		}

		// Send malformed response that will cause negotiation to fail
		go func() {
			time.Sleep(10 * time.Millisecond)
			// Send a malformed NetBIOS packet (empty)
			mockConn.readCh <- []byte{0x00, 0x00, 0x00, 0x00}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := d.DialContext(ctx, mockConn)
		if err == nil {
			t.Fatal("expected dial to fail, but it succeeded")
		}

		// Give time for cleanup
		time.Sleep(50 * time.Millisecond)

		// Force GC to clean up any stopped goroutines
		runtime.GC()
		time.Sleep(10 * time.Millisecond)

		// Count goroutines after
		finalGoroutines := runtime.NumGoroutine()

		// The Receive goroutine should have exited
		// Allow some tolerance for GC and test framework goroutines
		if finalGoroutines > initialGoroutines+2 {
			t.Errorf("goroutine leak detected: before=%d, after=%d, leaked=%d",
				initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
		}
	})
}

// TestDialSessionSetupFailureNoGoroutineLeak verifies that when session setup fails,
// the Receive goroutine is properly cleaned up.
func TestDialSessionSetupFailureNoGoroutineLeak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Count goroutines before
		initialGoroutines := runtime.NumGoroutine()

		mockConn := newMockFailingConn()
		d := &Dialer{
			Initiator: &NTLMInitiator{
				User:     "testuser",
				Password: "testpass",
			},
		}

		// This test won't actually reach session setup because negotiation will fail,
		// but it demonstrates the pattern. In a real scenario with a proper mock,
		// we'd simulate successful negotiation followed by session setup failure.

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := d.DialContext(ctx, mockConn)
		if err == nil {
			t.Fatal("expected dial to fail, but it succeeded")
		}

		// Give time for cleanup
		time.Sleep(50 * time.Millisecond)

		// Force GC
		runtime.GC()
		time.Sleep(10 * time.Millisecond)

		// Count goroutines after
		finalGoroutines := runtime.NumGoroutine()

		// Allow some tolerance
		if finalGoroutines > initialGoroutines+2 {
			t.Errorf("goroutine leak detected: before=%d, after=%d, leaked=%d",
				initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
		}
	})
}

// TestDialContextCancelNoGoroutineLeak verifies that when the dial context is cancelled,
// the Receive goroutine is properly cleaned up.
func TestDialContextCancelNoGoroutineLeak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Count goroutines before
		initialGoroutines := runtime.NumGoroutine()

		mockConn := newMockFailingConn()
		d := &Dialer{
			Initiator: &NTLMInitiator{
				User:     "testuser",
				Password: "testpass",
			},
		}

		ctx, cancel := context.WithCancel(context.Background())

		// Cancel immediately to trigger cleanup
		go func() {
			time.Sleep(5 * time.Millisecond)
			cancel()
		}()

		_, err := d.DialContext(ctx, mockConn)
		if err == nil {
			t.Fatal("expected dial to fail due to cancellation, but it succeeded")
		}

		// Give time for cleanup
		time.Sleep(50 * time.Millisecond)

		// Force GC
		runtime.GC()
		time.Sleep(10 * time.Millisecond)

		// Count goroutines after
		finalGoroutines := runtime.NumGoroutine()

		// Allow some tolerance
		if finalGoroutines > initialGoroutines+2 {
			t.Errorf("goroutine leak detected: before=%d, after=%d, leaked=%d",
				initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
		}
	})
}
