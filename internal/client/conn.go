package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/macourteau/smb1client/internal/logging"
	"github.com/macourteau/smb1client/internal/netbios"
	"github.com/macourteau/smb1client/internal/smb1"
)

// ErrConnectionClosed is the error handed to every request still in flight
// when the connection is torn down — either by an explicit Close or by the
// Receive goroutine exiting after a socket failure. A dead connection stays
// dead: this library does not reconnect, so a caller seeing this must dial
// again.
//
// It wraps net.ErrClosed so that errors.Is and the public IsNetworkError
// predicate classify it as a network failure rather than leaving callers to
// match on the message text. It deliberately does not wrap io.EOF: the
// connection dying mid-frame is not an orderly end of data, and a caller
// testing for io.EOF would misread it as one.
var ErrConnectionClosed = fmt.Errorf("smb1: connection closed: %w", net.ErrClosed)

// response represents a received SMB1 response waiting to be processed.
type response struct {
	header *smb1.Header
	params []byte
	data   []byte
	err    error
}

// pendingRequest tracks a request waiting for a response.
// It includes a cancellation flag to coordinate cleanup between
// the sender and the Receive goroutine.
type pendingRequest struct {
	respCh    chan *response
	cancelled bool
}

// conn represents a connection to an SMB1 server.
// It manages the underlying NetBIOS session, request/response correlation,
// and negotiated protocol parameters.
type Conn struct {
	netbiosConn *netbios.Session // NetBIOS-wrapped TCP connection

	mu            sync.Mutex                 // protects shared state below
	nextMID       uint16                     // next message ID to allocate
	pending       map[uint16]*pendingRequest // pending requests waiting for responses
	capabilities  uint32                     // negotiated capabilities from negotiate
	maxBufferSize uint32                     // negotiated max buffer size
	maxMpxCount   uint16                     // max concurrent requests
	sessionKey    uint32                     // session key from negotiate
	securityMode  uint8                      // security mode from negotiate
	challenge     []byte                     // NTLM challenge from negotiate
	serverName    string                     // server name from negotiate
	domainName    string                     // domain name from negotiate
	systemTime    uint64                     // server system time from negotiate (Windows FILETIME)
	timeZone      int16                      // server time zone from negotiate (minutes from UTC)
	negotiateTime time.Time                  // local time when the negotiate response was received
	done          chan struct{}              // signals connection shutdown
	err           error                      // connection error (if any)
}

// NewConn creates a new SMB1 connection wrapping the provided TCP connection.
// The TCP connection should already be established to the SMB server (typically port 445).
func NewConn(tcpConn net.Conn) *Conn {
	return &Conn{
		netbiosConn: netbios.NewSession(tcpConn),
		pending:     make(map[uint16]*pendingRequest),
		done:        make(chan struct{}),
	}
}

// GetCapabilities returns the negotiated server capabilities.
// This is a thread-safe way to access capability information.
func (c *Conn) GetCapabilities() (maxMpx uint16, maxBuf uint32, serverName, domainName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxMpxCount, c.maxBufferSize, c.serverName, c.domainName
}

// Close closes the connection and cleans up all resources.
// It wakes all pending requests with an error and closes the underlying connection.
func (c *Conn) Close() error {
	c.mu.Lock()
	select {
	case <-c.done:
		// Already closed
		c.mu.Unlock()
		return nil
	default:
	}

	close(c.done)
	c.err = ErrConnectionClosed

	// Swap out pending map to prevent Receive() from accessing it
	pending := c.pending
	c.pending = make(map[uint16]*pendingRequest)
	c.mu.Unlock()

	// Cleanup outside lock to avoid blocking Receive()
	for _, req := range pending {
		select {
		case req.respCh <- &response{err: c.err}:
		default:
		}
		close(req.respCh)
	}

	// Close NetBIOS connection
	if c.netbiosConn != nil {
		return c.netbiosConn.Close()
	}
	return nil
}

// allocateMID allocates the next available message ID.
// Message IDs wrap around at uint16 max (65535).
// Returns an error if all 65536 MIDs are already in use by concurrent requests.
// Must be called with c.mu held.
func (c *Conn) allocateMID() (uint16, error) {
	start := c.nextMID
	for {
		mid := c.nextMID
		c.nextMID++

		if _, exists := c.pending[mid]; !exists {
			return mid, nil
		}

		// Wrapped around without finding free MID
		if c.nextMID == start {
			return 0, fmt.Errorf("smb1: no available message IDs (>65535 concurrent requests)")
		}
	}
}

// send sends an SMB1 request without waiting for a response.
// The header's MID field will be set by this function.
func (c *Conn) send(header *smb1.Header, params, data []byte) error {
	c.mu.Lock()

	// Check if connection is closed
	select {
	case <-c.done:
		c.mu.Unlock()
		return c.err
	default:
	}

	// Allocate message ID
	mid, err := c.allocateMID()
	if err != nil {
		c.mu.Unlock()
		return err
	}
	header.MID = mid
	c.mu.Unlock()

	// Encode packet
	packet, err := smb1.EncodePacket(header, params, data)
	if err != nil {
		return fmt.Errorf("smb1: failed to encode packet: %w", err)
	}

	// Send via NetBIOS
	if err := c.netbiosConn.WritePacket(packet); err != nil {
		c.setError(fmt.Errorf("smb1: failed to send packet: %w", err))
		return err
	}

	return nil
}

// sendRecv sends an SMB1 request and waits for the response.
// It supports context cancellation and timeouts.
func (c *Conn) sendRecv(header *smb1.Header, params, data []byte, ctx context.Context) (*response, error) {
	logger := logging.FromContext(ctx)

	logger.Debug("sendRecv: attempting to acquire lock for command 0x%02X", header.Command)
	c.mu.Lock()
	logger.Debug("sendRecv: lock acquired for command 0x%02X", header.Command)

	// Check if connection is closed
	select {
	case <-c.done:
		c.mu.Unlock()
		return nil, c.err
	default:
	}

	// Allocate message ID and create response channel
	mid, err := c.allocateMID()
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	header.MID = mid
	respCh := make(chan *response, 1)
	c.pending[header.MID] = &pendingRequest{respCh: respCh, cancelled: false}
	c.mu.Unlock()

	logger.Debug("sendRecv: sending SMB command 0x%02X with MID %d", header.Command, header.MID)

	// Cleanup: remove from pending map when done
	defer func() {
		c.mu.Lock()
		delete(c.pending, header.MID)
		c.mu.Unlock()
	}()

	// Encode packet
	packet, err := smb1.EncodePacket(header, params, data)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode packet: %w", err)
	}

	// Send via NetBIOS
	if err := c.netbiosConn.WritePacketContext(ctx, packet); err != nil {
		c.setError(fmt.Errorf("smb1: failed to send packet: %w", err))
		return nil, err
	}

	// Wait for response or context cancellation
	select {
	case resp := <-respCh:
		if resp.err != nil {
			logger.Debug("sendRecv: received error response for MID %d: %v", header.MID, resp.err)
		} else {
			logger.Debug("sendRecv: received response for MID %d", header.MID)
		}
		return resp, resp.err
	case <-ctx.Done():
		logger.Debug("sendRecv: context cancelled for MID %d", header.MID)
		return nil, ctx.Err()
	case <-c.done:
		logger.Debug("sendRecv: connection closed for MID %d", header.MID)
		return nil, c.err
	}
}

// Receive is the background goroutine that reads responses and dispatches them to waiters.
// It should be started with go c.Receive() after the connection is created.
// This is exported for use by the public API layer.
//
// Goroutine cleanup guarantees:
//   - When Close() is called, it closes c.done and c.netbiosConn
//   - This goroutine checks c.done at the start of each iteration
//   - If blocked in ReadPacket(), closing the connection causes it to return an error
//   - Any error from ReadPacket() triggers setError() which closes c.done
//   - The deferred Close() call ensures cleanup even if the goroutine panics
//   - This guarantees the goroutine always exits when the connection is closed
func (c *Conn) Receive() {
	defer func() {
		// Connection closed, wake all pending requests
		c.Close()
	}()

	for {
		// Check if connection is closed
		select {
		case <-c.done:
			return
		default:
		}

		// Read packet from NetBIOS.
		// If the connection is closed while blocked here, this will return an error.
		packet, err := c.netbiosConn.ReadPacket()
		if err != nil {
			c.setError(fmt.Errorf("smb1: failed to read packet: %w", err))
			return
		}

		// Decode packet
		header, params, data, err := smb1.DecodePacket(packet)
		if err != nil {
			// Malformed packet - log and continue
			continue
		}

		// Dispatch to waiting request
		c.mu.Lock()
		req, ok := c.pending[header.MID]
		if !ok {
			// No one waiting for this MID
			c.mu.Unlock()
			continue
		}
		if req.cancelled {
			// Request was cancelled - remove from pending map and discard response
			delete(c.pending, header.MID)
			c.mu.Unlock()
			continue
		}
		respCh := req.respCh
		c.mu.Unlock()

		// Build response
		resp := &response{
			header: header,
			params: params,
			data:   data,
		}

		// Check for SMB error status
		if header.IsError() {
			resp.err = header.Error()
		}

		// Send to waiter (non-blocking)
		select {
		case respCh <- resp:
		default:
			// Channel full or closed - waiter gave up
		}
	}
}

// setError sets the connection error and wakes all waiters.
// It's safe to call multiple times (only first error is stored).
func (c *Conn) setError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.done:
		// Already closed
		return
	default:
	}

	if c.err == nil {
		c.err = err
	}

	// Wake all pending requests
	for mid, req := range c.pending {
		select {
		case req.respCh <- &response{err: err}:
		default:
		}
		delete(c.pending, mid)
	}

	close(c.done)
}

// cleanupCancelledRequests removes all cancelled requests from the pending map.
// This is safe to call because cancelled requests will never receive responses
// (Receive() skips them). This is primarily used after operations are cancelled
// to prevent memory leaks.
func (c *Conn) cleanupCancelledRequests() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for mid, req := range c.pending {
		if req.cancelled {
			delete(c.pending, mid)
		}
	}
}

// ServerName returns the server's NetBIOS name discovered during negotiation.
// This method is exported for use by the public API layer.
func (c *Conn) ServerName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverName
}

// ServerTime returns the server clock values captured from the negotiate
// response: the server's system time as a Windows FILETIME (100-nanosecond
// intervals since January 1, 1601 UTC), the server's time zone in minutes
// from UTC, and the local time at which the negotiate response was received.
// This method is exported for use by the public API layer.
func (c *Conn) ServerTime() (systemTime uint64, timeZoneMinutes int16, receivedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.systemTime, c.timeZone, c.negotiateTime
}
