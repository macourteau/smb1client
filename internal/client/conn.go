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

const (
	// responseQueueDepth is how many response messages may be buffered for a
	// single in-flight request before the receive loop starts dropping them.
	// A TRANS2 reply split across several messages arrives back to back while
	// the waiter is still reassembling, so one slot is not enough.
	responseQueueDepth = 64

	// maxTrans2Fragments bounds the number of messages accepted for one TRANS2
	// reply. The largest reply this client asks for is 64 KiB, which a server
	// sending the SMB1 minimum of 4356 bytes per message splits into 16; the
	// cap only guards against a server that never signals completion.
	maxTrans2Fragments = 64
)

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
	respCh, mid, cleanup, err := c.beginRequest(header, params, data, ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	resp, err := c.awaitResponse(respCh, mid, ctx)
	if err != nil {
		return resp, err
	}
	return resp, resp.err
}

// awaitResponse waits for one message on respCh, honouring context
// cancellation and connection teardown. The error status carried by the
// message itself is left for the caller to act on.
func (c *Conn) awaitResponse(respCh <-chan *response, mid uint16, ctx context.Context) (*response, error) {
	logger := logging.FromContext(ctx)

	select {
	case resp := <-respCh:
		if resp.err != nil {
			logger.Debug("sendRecv: received error response for MID %d: %v", mid, resp.err)
		} else {
			logger.Debug("sendRecv: received response for MID %d", mid)
		}
		return resp, nil
	case <-ctx.Done():
		logger.Debug("sendRecv: context cancelled for MID %d", mid)
		return nil, ctx.Err()
	case <-c.done:
		logger.Debug("sendRecv: connection closed for MID %d", mid)
		return nil, c.err
	}
}

// sendRecvTransaction sends a TRANS2 or TRANSACTION request and returns the
// fully reassembled
// response together with the header of its first message.
//
// A server answers a TRANS2 request with as many bytes as fit its own send
// buffer, not as many as the request's MaxDataCount allows: Samba caps each
// message at the negotiated max_xmit (~16 KiB), so a large directory listing
// arrives split across several messages. Every message repeats the request's
// MID and reports the totals for the whole reply in TotalParameterCount and
// TotalDataCount, placing its own bytes at ParameterDisplacement and
// DataDisplacement. Reading only the first message would drop whole directory
// entries with no error to show for it, so keep reading until the accumulated
// counts reach the totals.
func (c *Conn) sendRecvTransaction(header *smb1.Header, params, data []byte, ctx context.Context) (*response, *smb1.Trans2Response, error) {
	respCh, mid, cleanup, err := c.beginRequest(header, params, data, ctx)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	logger := logging.FromContext(ctx)

	var (
		first          *response
		assembled      *smb1.Trans2Response
		paramBuf       []byte
		dataBuf        []byte
		gotParams      int
		gotData        int
		wantParams     int
		wantData       int
		fragmentsRead  int
		emptyFragments int
	)

	for {
		resp, err := c.awaitResponse(respCh, mid, ctx)
		if err != nil {
			return nil, nil, err
		}

		frag, err := smb1.DecodeTrans2Response(resp.params, resp.data)
		if err != nil {
			return nil, nil, err
		}

		// An error status ends the transaction; there is nothing further to
		// reassemble. Hand the message back so the caller can apply its own
		// error/warning policy.
		if resp.err != nil && resp.header.IsError() {
			return resp, frag, nil
		}

		if first == nil {
			first = resp
			assembled = frag
			wantParams = int(frag.TotalParameterCount)
			wantData = int(frag.TotalDataCount)
			paramBuf = make([]byte, wantParams)
			dataBuf = make([]byte, wantData)
		}

		if err := placeFragment(paramBuf, frag.Parameters, frag.ParameterDisplacement, "parameter"); err != nil {
			return nil, nil, err
		}
		if err := placeFragment(dataBuf, frag.Data, frag.DataDisplacement, "data"); err != nil {
			return nil, nil, err
		}
		gotParams += len(frag.Parameters)
		gotData += len(frag.Data)

		if gotParams >= wantParams && gotData >= wantData {
			break
		}

		// Guard against a server that keeps sending messages contributing
		// nothing, which would otherwise spin here until the context expires.
		if len(frag.Parameters) == 0 && len(frag.Data) == 0 {
			emptyFragments++
			if emptyFragments > 1 {
				return nil, nil, fmt.Errorf("smb1: trans2 response stalled at %d/%d parameter and %d/%d data bytes",
					gotParams, wantParams, gotData, wantData)
			}
		}

		fragmentsRead++
		if fragmentsRead > maxTrans2Fragments {
			return nil, nil, fmt.Errorf("smb1: trans2 response split across more than %d messages", maxTrans2Fragments)
		}
		logger.Debug("sendRecvTransaction: MID %d reassembling, have %d/%d parameter and %d/%d data bytes",
			mid, gotParams, wantParams, gotData, wantData)
	}

	assembled.Parameters = paramBuf
	assembled.Data = dataBuf
	assembled.ParameterCount = uint16(wantParams)
	assembled.DataCount = uint16(wantData)

	return first, assembled, nil
}

// placeFragment copies one message's slice of a TRANS2 reply into the
// reassembly buffer at the displacement the server reported.
func placeFragment(buf, frag []byte, displacement uint16, what string) error {
	if len(frag) == 0 {
		return nil
	}
	start := int(displacement)
	if start < 0 || start+len(frag) > len(buf) {
		return fmt.Errorf("smb1: trans2 %s fragment at offset %d length %d overflows the %d-byte reply",
			what, start, len(frag), len(buf))
	}
	copy(buf[start:], frag)
	return nil
}

// beginRequest allocates a MID, registers the request as pending and sends it.
// The returned channel carries every message the server sends for that MID;
// cleanup unregisters it and must be called once the caller is done reading.
func (c *Conn) beginRequest(header *smb1.Header, params, data []byte, ctx context.Context) (<-chan *response, uint16, func(), error) {
	logger := logging.FromContext(ctx)

	c.mu.Lock()

	select {
	case <-c.done:
		c.mu.Unlock()
		return nil, 0, nil, c.err
	default:
	}

	mid, err := c.allocateMID()
	if err != nil {
		c.mu.Unlock()
		return nil, 0, nil, err
	}
	header.MID = mid
	respCh := make(chan *response, responseQueueDepth)
	c.pending[mid] = &pendingRequest{respCh: respCh, cancelled: false}
	c.mu.Unlock()

	cleanup := func() {
		c.mu.Lock()
		delete(c.pending, mid)
		c.mu.Unlock()
	}

	logger.Debug("sendRecv: sending SMB command 0x%02X with MID %d", header.Command, mid)

	packet, err := smb1.EncodePacket(header, params, data)
	if err != nil {
		cleanup()
		return nil, 0, nil, fmt.Errorf("smb1: failed to encode packet: %w", err)
	}

	if err := c.netbiosConn.WritePacketContext(ctx, packet); err != nil {
		cleanup()
		c.setError(fmt.Errorf("smb1: failed to send packet: %w", err))
		return nil, 0, nil, err
	}

	return respCh, mid, cleanup, nil
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
