package smb1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	// ErrPoolClosed is returned when attempting to get a connection from a closed pool.
	ErrPoolClosed = errors.New("connection pool is closed")

	// ErrPoolExhausted is returned when the pool has reached its maximum active connections
	// and no connections are available.
	ErrPoolExhausted = errors.New("connection pool exhausted")
)

// PoolConfig contains configuration options for a ConnectionPool.
type PoolConfig struct {
	// MaxIdle is the maximum number of idle connections to keep in the pool.
	// Zero means no idle connections are kept (every Get creates a new connection).
	// Default is 5.
	MaxIdle int

	// MaxActive is the maximum number of active connections (idle + in-use).
	// Zero means no limit on active connections.
	// Default is 10.
	MaxActive int

	// IdleTimeout is the maximum time an idle connection can remain in the pool
	// before being closed. Zero means no timeout (idle connections never expire).
	// Default is 5 minutes.
	IdleTimeout time.Duration

	// WaitTimeout is the maximum time to wait for a connection when the pool is exhausted.
	// Zero means fail immediately if no connection is available.
	// Default is 30 seconds.
	WaitTimeout time.Duration

	// HealthCheck is an optional callback function to verify connection health before reuse.
	// If provided, it will be called before returning a connection from the idle pool.
	// If the health check returns false or an error, the connection is closed and a new one is created.
	// If nil, connections are assumed to be alive (default behavior for backward compatibility).
	//
	// Example health check that sends an Echo command:
	//
	//	HealthCheck: func(s *Session) (bool, error) {
	//		// Try to send an Echo command with a timeout
	//		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	//		defer cancel()
	//		err := s.WithContext(ctx).sendEcho()
	//		return err == nil, err
	//	}
	//
	// Performance note: Health checks add latency to connection acquisition from the pool.
	// Use with caution for latency-sensitive workloads.
	HealthCheck func(*Session) (bool, error)
}

// DefaultPoolConfig returns a PoolConfig with recommended default values.
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxIdle:     5,
		MaxActive:   10,
		IdleTimeout: 5 * time.Minute,
		WaitTimeout: 30 * time.Second,
	}
}

// ConnectionPool manages a pool of SMB connections for reuse.
// It provides connection pooling to improve performance for workloads
// with many short-lived operations by avoiding the overhead of
// repeatedly establishing TCP connections and performing authentication.
//
// The pool is thread-safe and can be used concurrently from multiple goroutines.
//
// Example usage:
//
//	pool := smb1.NewConnectionPool("192.168.1.100:445", dialer, nil)
//	defer pool.Close()
//
//	// Get a connection from the pool
//	conn, err := pool.Get(ctx)
//	if err != nil {
//		return err
//	}
//	defer conn.Close() // Returns connection to pool
//
//	// Use the connection
//	share, err := conn.Mount("Public")
//	...
type ConnectionPool struct {
	serverAddr string
	dialer     *Dialer
	config     *PoolConfig

	mu       sync.Mutex
	idle     []*pooledSession
	active   int
	closed   bool
	waitChan chan struct{} // Signaled when a connection is returned

	cleanupOnce sync.Once
	cleanupDone chan struct{}
	cleanupQuit chan struct{}

	// createFunc can be overridden for testing
	createFunc func(ctx context.Context) (*pooledSession, error)
}

// pooledSession wraps a Session with pool-specific metadata.
type pooledSession struct {
	session    *Session
	tcpConn    net.Conn
	pool       *ConnectionPool
	lastUsed   time.Time
	inUse      bool
	realClosed bool // True if really closed (not just returned to pool)
}

// NewConnectionPool creates a new connection pool.
//
// Parameters:
//   - serverAddr: The server address (e.g., "192.168.1.100:445")
//   - dialer: The Dialer with authentication credentials
//   - config: Pool configuration (nil for defaults)
//
// The pool starts a background goroutine to clean up idle connections.
// Call Close() when done to release resources and close all connections.
func NewConnectionPool(serverAddr string, dialer *Dialer, config *PoolConfig) *ConnectionPool {
	if config == nil {
		config = DefaultPoolConfig()
	}

	// Validate and apply defaults
	if config.MaxIdle < 0 {
		config.MaxIdle = 0
	}
	if config.MaxActive < 0 {
		config.MaxActive = 0
	}
	if config.MaxActive > 0 && config.MaxIdle > config.MaxActive {
		config.MaxIdle = config.MaxActive
	}

	p := &ConnectionPool{
		serverAddr:  serverAddr,
		dialer:      dialer,
		config:      config,
		idle:        make([]*pooledSession, 0, config.MaxIdle),
		waitChan:    make(chan struct{}, 1),
		cleanupDone: make(chan struct{}),
		cleanupQuit: make(chan struct{}),
	}

	// Start cleanup goroutine if idle timeout is set
	if config.IdleTimeout > 0 {
		go p.cleanupLoop()
	} else {
		close(p.cleanupDone)
	}

	return p
}

// Get retrieves a connection from the pool or creates a new one.
//
// The returned PooledSession should be closed when done, which returns
// it to the pool for reuse. To actually close the connection, call ReallyClose().
//
// If the pool is exhausted (MaxActive reached), Get will wait up to
// WaitTimeout for a connection to become available. If the context is
// canceled or the timeout expires, an error is returned.
func (p *ConnectionPool) Get(ctx context.Context) (*PooledSession, error) {
	if ctx == nil {
		return nil, &InternalError{"nil context"}
	}

	// Check if context is already canceled
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var waitDeadline time.Time
	if p.config.WaitTimeout > 0 {
		waitDeadline = time.Now().Add(p.config.WaitTimeout)
	}

	for {
		p.mu.Lock()

		// Drain the wait channel to avoid stale signals
		select {
		case <-p.waitChan:
		default:
		}

		// Check if pool is closed
		if p.closed {
			p.mu.Unlock()
			return nil, ErrPoolClosed
		}

		// Try to get an idle connection
		if len(p.idle) > 0 {
			// Pop from the end (most recently used)
			ps := p.idle[len(p.idle)-1]
			p.idle = p.idle[:len(p.idle)-1]
			ps.inUse = true
			ps.lastUsed = time.Now()
			p.mu.Unlock()

			// Test if the connection is still alive
			if p.isAlive(ps) {
				return &PooledSession{pooledSession: ps}, nil
			}

			// Connection is dead, close it and try again
			p.closeSession(ps)
			continue
		}

		// No idle connections available
		// Check if we can create a new one
		canCreate := p.config.MaxActive == 0 || p.active < p.config.MaxActive

		if canCreate {
			// Create a new connection
			p.active++
			p.mu.Unlock()

			// Use createFunc if set (for testing), otherwise use default
			var ps *pooledSession
			var err error
			if p.createFunc != nil {
				ps, err = p.createFunc(ctx)
			} else {
				ps, err = p.createConnection(ctx)
			}

			if err != nil {
				// Failed to create, decrement active count
				p.mu.Lock()
				p.active--
				p.mu.Unlock()
				return nil, err
			}

			return &PooledSession{pooledSession: ps}, nil
		}

		// Pool is exhausted, wait for a connection
		if p.config.WaitTimeout == 0 {
			p.mu.Unlock()
			return nil, ErrPoolExhausted
		}

		// Calculate wait timeout
		var timeout time.Duration
		if !waitDeadline.IsZero() {
			timeout = time.Until(waitDeadline)
			if timeout <= 0 {
				p.mu.Unlock()
				return nil, ErrPoolExhausted
			}
		}

		// Wait for a connection to be returned or context cancellation
		waitChan := p.waitChan
		p.mu.Unlock()

		if timeout > 0 {
			timer := time.NewTimer(timeout)
			select {
			case <-waitChan:
				timer.Stop()
				// Try again
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
				return nil, ErrPoolExhausted
			}
		} else {
			select {
			case <-waitChan:
				// Try again
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
}

// createConnection creates a new SMB connection.
func (p *ConnectionPool) createConnection(ctx context.Context) (*pooledSession, error) {
	// Create TCP connection
	tcpConn, err := net.Dial("tcp", p.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", p.serverAddr, err)
	}

	// Perform SMB negotiation and authentication
	session, err := p.dialer.DialContext(ctx, tcpConn)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	ps := &pooledSession{
		session:  session,
		tcpConn:  tcpConn,
		pool:     p,
		lastUsed: time.Now(),
		inUse:    true,
	}

	return ps, nil
}

// put returns a connection to the pool.
func (p *ConnectionPool) put(ps *pooledSession) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Don't return to pool if already closed or pool is closed
	if ps.realClosed || p.closed {
		return nil
	}

	// Mark as not in use
	ps.inUse = false
	ps.lastUsed = time.Now()

	// Check if we should keep it in the idle pool
	if p.config.MaxIdle == 0 || len(p.idle) >= p.config.MaxIdle {
		// Pool is full, close the connection
		p.active--
		p.mu.Unlock()
		p.closeSession(ps)
		p.mu.Lock()
		return nil
	}

	// Add to idle pool
	p.idle = append(p.idle, ps)

	// Signal waiting goroutines (non-blocking)
	// Multiple signals are fine since we check pool state in the wait loop
	select {
	case p.waitChan <- struct{}{}:
	default:
		// Channel is full, but that's okay - a waiter will check the pool
	}

	return nil
}

// remove removes a connection from the pool and closes it.
func (p *ConnectionPool) remove(ps *pooledSession) error {
	p.mu.Lock()

	// Mark as really closed
	ps.realClosed = true

	// If it was in use, decrement active count
	if ps.inUse {
		p.active--
		ps.inUse = false
	} else {
		// Remove from idle pool if present
		for i, idle := range p.idle {
			if idle == ps {
				p.idle = append(p.idle[:i], p.idle[i+1:]...)
				p.active--
				break
			}
		}
	}

	p.mu.Unlock()

	// Close the session
	return p.closeSession(ps)
}

// closeSession closes a pooled session's underlying connection.
func (p *ConnectionPool) closeSession(ps *pooledSession) error {
	if ps == nil {
		return nil
	}

	// Perform SMB logoff which also closes the TCP connection
	// Note: Session.Logoff() handles closing the TCP connection,
	// so we don't need to (and shouldn't) close it separately here
	if ps.session != nil {
		return ps.session.Logoff()
	}

	// If there's no session but there's a TCP connection, close it
	if ps.tcpConn != nil {
		return ps.tcpConn.Close()
	}

	return nil
}

// isAlive checks if a connection is still alive.
func (p *ConnectionPool) isAlive(ps *pooledSession) bool {
	// Check if the connection has been really closed
	if ps.realClosed {
		return false
	}

	// Check if TCP connection and session are present
	if ps.tcpConn == nil || ps.session == nil {
		return false
	}

	// If a health check is configured, use it to verify the connection
	if p.config.HealthCheck != nil {
		healthy, err := p.config.HealthCheck(ps.session)
		if err != nil || !healthy {
			return false
		}
	}

	return true
}

// cleanupLoop runs in the background to clean up expired idle connections.
func (p *ConnectionPool) cleanupLoop() {
	defer close(p.cleanupDone)

	ticker := time.NewTicker(p.config.IdleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupExpired()
		case <-p.cleanupQuit:
			return
		}
	}
}

// cleanupExpired removes expired idle connections from the pool.
func (p *ConnectionPool) cleanupExpired() {
	p.mu.Lock()

	now := time.Now()
	var toClose []*pooledSession

	// Find expired connections
	validIdle := p.idle[:0]
	for _, ps := range p.idle {
		if now.Sub(ps.lastUsed) > p.config.IdleTimeout {
			toClose = append(toClose, ps)
			p.active--
		} else {
			validIdle = append(validIdle, ps)
		}
	}
	p.idle = validIdle

	p.mu.Unlock()

	// Close expired connections outside the lock
	for _, ps := range toClose {
		p.closeSession(ps)
	}
}

// Close closes the pool and all connections in it.
// After calling Close, the pool cannot be used.
func (p *ConnectionPool) Close() error {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		return nil
	}

	p.closed = true
	idle := p.idle
	p.idle = nil

	p.mu.Unlock()

	// Signal cleanup goroutine to exit
	close(p.cleanupQuit)

	// Wait for cleanup goroutine to finish
	p.cleanupOnce.Do(func() {
		<-p.cleanupDone
	})

	// Close all idle connections
	for _, ps := range idle {
		p.closeSession(ps)
	}

	return nil
}

// Stats returns statistics about the pool.
func (p *ConnectionPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return PoolStats{
		Idle:   len(p.idle),
		Active: p.active,
		Closed: p.closed,
	}
}

// PoolStats contains statistics about a ConnectionPool.
type PoolStats struct {
	// Idle is the number of idle connections in the pool.
	Idle int

	// Active is the total number of active connections (idle + in-use).
	Active int

	// Closed indicates whether the pool has been closed.
	Closed bool
}

// PooledSession wraps a Session obtained from a ConnectionPool.
// When Close() is called, the session is returned to the pool for reuse.
// To actually close the connection, use ReallyClose().
type PooledSession struct {
	*pooledSession
}

// Close returns the connection to the pool instead of closing it.
// The session can be reused by another caller.
func (ps *PooledSession) Close() error {
	if ps.pooledSession == nil {
		return nil
	}
	return ps.pool.put(ps.pooledSession)
}

// ReallyClose closes the connection and removes it from the pool.
// Use this when you want to permanently close a connection (e.g., on error).
func (ps *PooledSession) ReallyClose() error {
	if ps.pooledSession == nil {
		return nil
	}
	return ps.pool.remove(ps.pooledSession)
}

// Session returns the underlying Session for use.
// The returned Session should not be closed directly - use PooledSession.Close() instead.
func (ps *PooledSession) Session() *Session {
	if ps.pooledSession == nil {
		return nil
	}
	return ps.pooledSession.session
}

// Logoff is a convenience method that calls ReallyClose().
// It's provided for API compatibility but actually closes the connection
// rather than returning it to the pool.
func (ps *PooledSession) Logoff() error {
	return ps.ReallyClose()
}

// Mount is a convenience method that calls Mount on the underlying Session.
func (ps *PooledSession) Mount(sharename string) (*Share, error) {
	if ps.pooledSession == nil || ps.pooledSession.session == nil {
		return nil, &InternalError{"session is nil"}
	}
	return ps.pooledSession.session.Mount(sharename)
}

// ListSharenames is a convenience method that calls ListSharenames on the underlying Session.
func (ps *PooledSession) ListSharenames() ([]string, error) {
	if ps.pooledSession == nil || ps.pooledSession.session == nil {
		return nil, &InternalError{"session is nil"}
	}
	return ps.pooledSession.session.ListSharenames()
}

// WithContext is a convenience method that calls WithContext on the underlying Session.
func (ps *PooledSession) WithContext(ctx context.Context) *Session {
	if ctx == nil {
		return nil
	}
	if ps.pooledSession == nil || ps.pooledSession.session == nil {
		return nil
	}
	return ps.pooledSession.session.WithContext(ctx)
}
