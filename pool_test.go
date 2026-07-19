package smb1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// mockNetConn is a mock net.Conn for testing
type mockNetConn struct {
	net.Conn
	closed     bool
	readErr    error
	remoteAddr net.Addr
}

func (m *mockNetConn) Read(b []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	// Simulate a timeout for healthy connections
	return 0, &net.OpError{Op: "read", Err: errors.New("i/o timeout")}
}

func (m *mockNetConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockNetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockNetConn) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:445")
	return addr
}

func (m *mockNetConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	return addr
}

func (m *mockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockNetConn) Write(b []byte) (int, error)        { return len(b), nil }

// mockDialer creates mock connections for testing
type mockDialer struct {
	mu          sync.Mutex
	createCount int
	createError error
	createDelay time.Duration
	dialerFunc  func() (*Session, net.Conn, error)
}

func (m *mockDialer) dial(ctx context.Context, addr string, d *Dialer) (*Session, net.Conn, error) {
	m.mu.Lock()
	m.createCount++
	m.mu.Unlock()

	if m.createDelay > 0 {
		time.Sleep(m.createDelay)
	}

	if m.createError != nil {
		return nil, nil, m.createError
	}

	if m.dialerFunc != nil {
		return m.dialerFunc()
	}

	// Create mock connection and session
	conn := &mockNetConn{}
	session := &Session{
		addr: addr,
		ctx:  context.Background(),
	}

	return session, conn, nil
}

func (m *mockDialer) getCreateCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createCount
}

// createTestPool creates a pool with a mock dialer for testing
func createTestPool(config *PoolConfig, mock *mockDialer) *ConnectionPool {
	if config == nil {
		config = &PoolConfig{
			MaxIdle:     5,
			MaxActive:   10,
			IdleTimeout: 5 * time.Minute,
			WaitTimeout: 1 * time.Second,
		}
	}

	dialer := &Dialer{
		Initiator: &NTLMInitiator{
			User:     "test",
			Password: "test",
			Domain:   "TEST",
		},
	}

	p := &ConnectionPool{
		serverAddr:  "127.0.0.1:445",
		dialer:      dialer,
		config:      config,
		idle:        make([]*pooledSession, 0, config.MaxIdle),
		waitChan:    make(chan struct{}, 1),
		cleanupDone: make(chan struct{}),
		cleanupQuit: make(chan struct{}),
	}

	// Set mock create function
	p.createFunc = func(ctx context.Context) (*pooledSession, error) {
		session, tcpConn, err := mock.dial(ctx, p.serverAddr, p.dialer)
		if err != nil {
			return nil, err
		}

		return &pooledSession{
			session:  session,
			tcpConn:  tcpConn,
			pool:     p,
			lastUsed: time.Now(),
			inUse:    true,
		}, nil
	}

	if config.IdleTimeout > 0 {
		go p.cleanupLoop()
	} else {
		close(p.cleanupDone)
	}

	return p
}

func TestNewConnectionPool(t *testing.T) {
	dialer := &Dialer{
		Initiator: &NTLMInitiator{
			User:     "test",
			Password: "test",
		},
	}

	t.Run("with default config", func(t *testing.T) {
		pool := NewConnectionPool("127.0.0.1:445", dialer, nil)
		defer pool.Close()

		if pool.config.MaxIdle != 5 {
			t.Errorf("expected MaxIdle=5, got %d", pool.config.MaxIdle)
		}
		if pool.config.MaxActive != 10 {
			t.Errorf("expected MaxActive=10, got %d", pool.config.MaxActive)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &PoolConfig{
			MaxIdle:     3,
			MaxActive:   20,
			IdleTimeout: 10 * time.Minute,
			WaitTimeout: 5 * time.Second,
		}
		pool := NewConnectionPool("127.0.0.1:445", dialer, config)
		defer pool.Close()

		if pool.config.MaxIdle != 3 {
			t.Errorf("expected MaxIdle=3, got %d", pool.config.MaxIdle)
		}
		if pool.config.MaxActive != 20 {
			t.Errorf("expected MaxActive=20, got %d", pool.config.MaxActive)
		}
	})

	t.Run("with invalid config values", func(t *testing.T) {
		config := &PoolConfig{
			MaxIdle:   10,
			MaxActive: 5, // MaxIdle > MaxActive
		}
		pool := NewConnectionPool("127.0.0.1:445", dialer, config)
		defer pool.Close()

		// Should adjust MaxIdle to match MaxActive
		if pool.config.MaxIdle != 5 {
			t.Errorf("expected MaxIdle to be adjusted to 5, got %d", pool.config.MaxIdle)
		}
	})
}

func TestPoolGetAndPut(t *testing.T) {
	mock := &mockDialer{}
	pool := createTestPool(nil, mock)
	defer pool.Close()

	ctx := context.Background()

	t.Run("get creates new connection", func(t *testing.T) {
		conn, err := pool.Get(ctx)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		defer conn.Close()

		if mock.getCreateCount() != 1 {
			t.Errorf("expected 1 connection created, got %d", mock.getCreateCount())
		}

		stats := pool.Stats()
		if stats.Active != 1 {
			t.Errorf("expected 1 active connection, got %d", stats.Active)
		}
	})

	t.Run("put returns connection to pool", func(t *testing.T) {
		conn, err := pool.Get(ctx)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		initialCount := mock.getCreateCount()

		err = conn.Close()
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		stats := pool.Stats()
		if stats.Idle != 1 {
			t.Errorf("expected 1 idle connection, got %d", stats.Idle)
		}

		// Get another connection - should reuse existing
		conn2, err := pool.Get(ctx)
		if err != nil {
			t.Fatalf("second Get failed: %v", err)
		}
		defer conn2.Close()

		if mock.getCreateCount() != initialCount {
			t.Errorf("expected connection to be reused, but new connection was created")
		}
	})
}

func TestPoolMaxIdle(t *testing.T) {
	config := &PoolConfig{
		MaxIdle:     2,
		MaxActive:   10,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 1 * time.Second,
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Create 3 connections
	conn1, _ := pool.Get(ctx)
	conn2, _ := pool.Get(ctx)
	conn3, _ := pool.Get(ctx)

	// Return them all
	conn1.Close()
	conn2.Close()
	conn3.Close()

	// Wait a bit for async close
	time.Sleep(10 * time.Millisecond)

	stats := pool.Stats()
	if stats.Idle > 2 {
		t.Errorf("expected at most 2 idle connections, got %d", stats.Idle)
	}
}

func TestPoolMaxActive(t *testing.T) {
	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   2,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 100 * time.Millisecond,
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Get 2 connections (max)
	conn1, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get 1 failed: %v", err)
	}
	defer conn1.Close()

	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get 2 failed: %v", err)
	}
	defer conn2.Close()

	// Try to get a third - should fail with timeout
	_, err = pool.Get(ctx)
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}
}

func TestPoolWaitForConnection(t *testing.T) {
	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   1,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 2 * time.Second,
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Get the only available connection
	conn1, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Start a goroutine to return it after a delay
	go func() {
		time.Sleep(200 * time.Millisecond)
		conn1.Close()
	}()

	// Try to get another - should wait and succeed
	start := time.Now()
	conn2, err := pool.Get(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Get should have waited and succeeded: %v", err)
	}
	defer conn2.Close()

	if elapsed < 150*time.Millisecond {
		t.Errorf("expected to wait at least 150ms, waited %v", elapsed)
	}
}

func TestPoolContextCancellation(t *testing.T) {
	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   1,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 10 * time.Second,
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	// Get the only connection
	conn1, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer conn1.Close()

	// Try to get with a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = pool.Get(ctx)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestPoolIdleTimeout(t *testing.T) {
	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   10,
		IdleTimeout: 200 * time.Millisecond,
		WaitTimeout: 1 * time.Second,
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Create a connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Return it to pool
	conn.Close()

	// Wait for it to expire
	time.Sleep(500 * time.Millisecond)

	stats := pool.Stats()
	if stats.Idle != 0 {
		t.Errorf("expected 0 idle connections after timeout, got %d", stats.Idle)
	}
}

func TestPoolConcurrency(t *testing.T) {
	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   20,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 2 * time.Second,
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()
	numGoroutines := 50
	numOpsPerGoroutine := 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOpsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOpsPerGoroutine; j++ {
				conn, err := pool.Get(ctx)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d op %d: Get failed: %w", id, j, err)
					continue
				}

				// Simulate some work
				time.Sleep(1 * time.Millisecond)

				err = conn.Close()
				if err != nil {
					errors <- fmt.Errorf("goroutine %d op %d: Close failed: %w", id, j, err)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	errorCount := 0
	for err := range errors {
		t.Errorf("concurrent operation error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Fatalf("got %d errors during concurrent operations", errorCount)
	}

	stats := pool.Stats()
	t.Logf("Final stats: Active=%d, Idle=%d", stats.Active, stats.Idle)
}

func TestPoolClose(t *testing.T) {
	mock := &mockDialer{}
	pool := createTestPool(nil, mock)

	ctx := context.Background()

	// Create some connections
	conn1, _ := pool.Get(ctx)
	conn2, _ := pool.Get(ctx)

	// Return one to pool
	conn1.Close()

	// Close the pool
	err := pool.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Try to get a connection after close
	_, err = pool.Get(ctx)
	if err != ErrPoolClosed {
		t.Errorf("expected ErrPoolClosed, got %v", err)
	}

	// Close should be idempotent
	err = pool.Close()
	if err != nil {
		t.Errorf("second Close failed: %v", err)
	}

	// Return remaining connection
	conn2.Close()
}

func TestPoolReallyClose(t *testing.T) {
	mock := &mockDialer{}
	pool := createTestPool(nil, mock)
	defer pool.Close()

	ctx := context.Background()

	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Get initial stats
	statsBefore := pool.Stats()

	// Really close the connection
	err = conn.ReallyClose()
	if err != nil {
		t.Fatalf("ReallyClose failed: %v", err)
	}

	// Check that active count decreased
	statsAfter := pool.Stats()
	if statsAfter.Active != statsBefore.Active-1 {
		t.Errorf("expected active count to decrease by 1, before=%d after=%d",
			statsBefore.Active, statsAfter.Active)
	}

	// Try to close again - should be safe
	err = conn.Close()
	if err != nil {
		t.Errorf("second Close should not fail: %v", err)
	}
}

func TestPooledSessionConvenience(t *testing.T) {
	mock := &mockDialer{
		dialerFunc: func() (*Session, net.Conn, error) {
			conn := &mockNetConn{}
			session := &Session{
				addr: "127.0.0.1:445",
				ctx:  context.Background(),
			}
			return session, conn, nil
		},
	}

	pool := createTestPool(nil, mock)
	defer pool.Close()

	ctx := context.Background()

	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer conn.Close()

	// Test convenience methods
	t.Run("Session()", func(t *testing.T) {
		session := conn.Session()
		if session == nil {
			t.Error("Session() returned nil")
		}
	})

	t.Run("WithContext()", func(t *testing.T) {
		newSession := conn.WithContext(ctx)
		if newSession == nil {
			t.Error("WithContext() returned nil")
		}
	})
}

func TestPoolStats(t *testing.T) {
	mock := &mockDialer{}
	pool := createTestPool(nil, mock)
	defer pool.Close()

	ctx := context.Background()

	// Initial stats
	stats := pool.Stats()
	if stats.Active != 0 || stats.Idle != 0 {
		t.Errorf("expected empty pool, got Active=%d Idle=%d", stats.Active, stats.Idle)
	}

	// Create connections
	conn1, _ := pool.Get(ctx)
	conn2, _ := pool.Get(ctx)

	stats = pool.Stats()
	if stats.Active != 2 {
		t.Errorf("expected 2 active, got %d", stats.Active)
	}

	// Return one
	conn1.Close()
	time.Sleep(10 * time.Millisecond)

	stats = pool.Stats()
	if stats.Idle != 1 {
		t.Errorf("expected 1 idle, got %d", stats.Idle)
	}
	if stats.Active != 2 {
		t.Errorf("expected 2 active, got %d", stats.Active)
	}

	// Return second
	conn2.Close()
	time.Sleep(10 * time.Millisecond)

	stats = pool.Stats()
	if stats.Idle != 2 {
		t.Errorf("expected 2 idle, got %d", stats.Idle)
	}
}

func TestPoolCreateError(t *testing.T) {
	mock := &mockDialer{
		createError: errors.New("connection failed"),
	}

	pool := createTestPool(nil, mock)
	defer pool.Close()

	ctx := context.Background()

	_, err := pool.Get(ctx)
	if err == nil {
		t.Error("expected error, got nil")
	}

	// Active count should not increase
	stats := pool.Stats()
	if stats.Active != 0 {
		t.Errorf("expected 0 active after failed create, got %d", stats.Active)
	}
}

func TestDefaultPoolConfig(t *testing.T) {
	config := DefaultPoolConfig()

	if config.MaxIdle != 5 {
		t.Errorf("expected MaxIdle=5, got %d", config.MaxIdle)
	}
	if config.MaxActive != 10 {
		t.Errorf("expected MaxActive=10, got %d", config.MaxActive)
	}
	if config.IdleTimeout != 5*time.Minute {
		t.Errorf("expected IdleTimeout=5m, got %v", config.IdleTimeout)
	}
	if config.WaitTimeout != 30*time.Second {
		t.Errorf("expected WaitTimeout=30s, got %v", config.WaitTimeout)
	}
}

func TestPoolNoIdleTimeout(t *testing.T) {
	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   10,
		IdleTimeout: 0, // No timeout
		WaitTimeout: 1 * time.Second,
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Create and return a connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	conn.Close()

	// Wait a while
	time.Sleep(200 * time.Millisecond)

	// Should still be in pool
	stats := pool.Stats()
	if stats.Idle != 1 {
		t.Errorf("expected 1 idle connection (no timeout), got %d", stats.Idle)
	}
}

func TestPoolNoWaitTimeout(t *testing.T) {
	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   1,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 0, // Fail immediately
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Get the only connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer conn.Close()

	// Try to get another - should fail immediately
	start := time.Now()
	_, err = pool.Get(ctx)
	elapsed := time.Since(start)

	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}

	if elapsed > 50*time.Millisecond {
		t.Errorf("should fail immediately, but took %v", elapsed)
	}
}

func TestPoolHealthCheckCalled(t *testing.T) {
	var healthCheckCount int
	var mu sync.Mutex

	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   10,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 1 * time.Second,
		HealthCheck: func(s *Session) (bool, error) {
			mu.Lock()
			healthCheckCount++
			mu.Unlock()
			return true, nil
		},
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Get a connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Return to pool
	conn.Close()

	// Get another connection - should reuse and call health check
	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("second Get failed: %v", err)
	}
	defer conn2.Close()

	mu.Lock()
	count := healthCheckCount
	mu.Unlock()

	if count != 1 {
		t.Errorf("expected health check to be called once, got %d calls", count)
	}
}

func TestPoolHealthCheckFailure(t *testing.T) {
	var healthCheckCount int
	var mu sync.Mutex

	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   10,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 1 * time.Second,
		HealthCheck: func(s *Session) (bool, error) {
			mu.Lock()
			healthCheckCount++
			failing := healthCheckCount == 1 // Fail first time
			mu.Unlock()
			return !failing, nil
		},
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Get a connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	initialCreateCount := mock.getCreateCount()

	// Return to pool
	conn.Close()

	// Get another connection - health check should fail, causing new connection
	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("second Get failed: %v", err)
	}
	defer conn2.Close()

	mu.Lock()
	count := healthCheckCount
	mu.Unlock()

	if count != 1 {
		t.Errorf("expected health check to be called once, got %d calls", count)
	}

	// Should have created a new connection due to health check failure
	if mock.getCreateCount() != initialCreateCount+1 {
		t.Errorf("expected new connection to be created, but count didn't increase")
	}
}

func TestPoolHealthCheckError(t *testing.T) {
	healthCheckErr := errors.New("health check failed")

	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   10,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 1 * time.Second,
		HealthCheck: func(s *Session) (bool, error) {
			return false, healthCheckErr
		},
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Get a connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	initialCreateCount := mock.getCreateCount()

	// Return to pool
	conn.Close()

	// Get another connection - health check error should cause new connection
	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("second Get failed: %v", err)
	}
	defer conn2.Close()

	// Should have created a new connection due to health check error
	if mock.getCreateCount() != initialCreateCount+1 {
		t.Errorf("expected new connection to be created, but count didn't increase")
	}
}

func TestPoolNoHealthCheck(t *testing.T) {
	// Test default behavior without health check
	config := &PoolConfig{
		MaxIdle:     5,
		MaxActive:   10,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 1 * time.Second,
		HealthCheck: nil, // Explicitly nil
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Get a connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	initialCreateCount := mock.getCreateCount()

	// Return to pool
	conn.Close()

	// Get another connection - should reuse without health check
	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("second Get failed: %v", err)
	}
	defer conn2.Close()

	// Should not have created a new connection
	if mock.getCreateCount() != initialCreateCount {
		t.Errorf("expected connection to be reused, but new connection was created")
	}
}

func TestPoolHealthCheckMultipleFailures(t *testing.T) {
	var healthCheckCount int
	var mu sync.Mutex

	config := &PoolConfig{
		MaxIdle:     3,
		MaxActive:   10,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 1 * time.Second,
		HealthCheck: func(s *Session) (bool, error) {
			mu.Lock()
			healthCheckCount++
			// Fail all health checks
			mu.Unlock()
			return false, nil
		},
	}

	mock := &mockDialer{}
	pool := createTestPool(config, mock)
	defer pool.Close()

	ctx := context.Background()

	// Create 3 connections and return them to pool
	conn1, _ := pool.Get(ctx)
	conn2, _ := pool.Get(ctx)
	conn3, _ := pool.Get(ctx)

	conn1.Close()
	conn2.Close()
	conn3.Close()

	time.Sleep(10 * time.Millisecond)

	stats := pool.Stats()
	if stats.Idle != 3 {
		t.Fatalf("expected 3 idle connections, got %d", stats.Idle)
	}

	initialCreateCount := mock.getCreateCount()

	// Get 3 connections - all health checks should fail, creating 3 new connections
	newConn1, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get 1 failed: %v", err)
	}
	defer newConn1.Close()

	newConn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get 2 failed: %v", err)
	}
	defer newConn2.Close()

	newConn3, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get 3 failed: %v", err)
	}
	defer newConn3.Close()

	mu.Lock()
	count := healthCheckCount
	mu.Unlock()

	// Each Get should have tried at least one health check
	if count < 3 {
		t.Errorf("expected at least 3 health checks, got %d", count)
	}

	// Should have created 3 new connections
	if mock.getCreateCount() != initialCreateCount+3 {
		t.Errorf("expected 3 new connections, created %d", mock.getCreateCount()-initialCreateCount)
	}
}

func TestPoolGetNilContext(t *testing.T) {
	mock := &mockDialer{}
	pool := createTestPool(nil, mock)
	defer pool.Close()

	//lint:ignore SA1012 intentionally testing nil-context handling
	_, err := pool.Get(nil)
	if err == nil {
		t.Fatal("expected error for nil context, got nil")
	}

	var internalErr *InternalError
	if !errors.As(err, &internalErr) {
		t.Fatalf("expected InternalError, got %T: %v", err, err)
	}

	errMsg := err.Error()
	if errMsg != "smb1: internal error: nil context" {
		t.Errorf("expected error message 'smb1: internal error: nil context', got %q", errMsg)
	}
}

func TestPooledSessionWithContextNilContext(t *testing.T) {
	mock := &mockDialer{
		dialerFunc: func() (*Session, net.Conn, error) {
			conn := &mockNetConn{}
			session := &Session{
				addr: "127.0.0.1:445",
				ctx:  context.Background(),
			}
			return session, conn, nil
		},
	}

	pool := createTestPool(nil, mock)
	defer pool.Close()

	ctx := context.Background()
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer conn.Close()

	//lint:ignore SA1012 intentionally testing nil-context handling
	newSession := conn.WithContext(nil)
	if newSession != nil {
		t.Errorf("expected nil session for nil context, got %v", newSession)
	}
}
