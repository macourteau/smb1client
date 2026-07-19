package smb1

import (
	"context"
	"net"

	"github.com/macourteau/smb1client/internal/client"
	"github.com/macourteau/smb1client/internal/ntlm"
)

// Negotiator contains options for protocol negotiation, mirroring go-smb2's
// type of the same name for source compatibility. SMB1 ignores all fields:
// negotiation is always performed automatically, this client does not
// negotiate signing, SMB1 negotiation carries no client GUID, and the
// dialect is always NT LM 0.12.
type Negotiator struct {
	RequireMessageSigning bool     // ignored for SMB1
	ClientGuid            [16]byte // ignored for SMB1
	SpecifiedDialect      uint16   // ignored for SMB1
}

// Dialer contains options for establishing an SMB1 session.
//
// API Compatibility Note:
// MaxCreditBalance and Negotiator are kept for go-smb2 API compatibility,
// but are not used in SMB1 (SMB1 doesn't have credit-based flow control).
type Dialer struct {
	// MaxCreditBalance is unused for SMB1 (kept for API compatibility).
	// SMB1 does not use the credit-based flow control that SMB2+ uses.
	MaxCreditBalance uint16

	// Negotiator is unused for SMB1 (kept for API compatibility).
	// SMB1 negotiation is always performed automatically.
	Negotiator Negotiator

	// Initiator is required for authentication.
	// Use NTLMInitiator for NTLM v2 authentication.
	Initiator Initiator
}

// Dial performs protocol negotiation and authentication on the provided TCP connection.
//
// The tcpConn should already be connected to the SMB server (typically port 445 or 139).
// This method wraps the connection with NetBIOS framing, negotiates the SMB1 protocol,
// and performs NTLM authentication.
//
// Important: This implementation doesn't support NetBIOS transport on port 139 yet.
// Use direct SMB over TCP on port 445 instead.
//
// The returned Session uses context.Background() as its default context
// (with no logger attached). To attach a logger or custom context, use
// DialContext instead.
//
// Example:
//
//	conn, err := net.Dial("tcp", "192.168.1.100:445")
//	if err != nil {
//		return err
//	}
//	defer conn.Close()
//
//	d := &smb1.Dialer{
//		Initiator: &smb1.NTLMInitiator{
//			User:     "username",
//			Password: "password",
//			Domain:   "WORKGROUP",
//		},
//	}
//
//	session, err := d.Dial(conn)
//	if err != nil {
//		return err
//	}
//	defer session.Logoff()
func (d *Dialer) Dial(tcpConn net.Conn) (*Session, error) {
	return d.DialContext(context.Background(), tcpConn)
}

// DialContext performs negotiation and authentication using the provided context.
//
// The context is used for the negotiation and authentication phases only.
// Any logger attached to the context will be extracted and used by the returned
// Session, but timeouts and cancellations are not inherited.
//
// If you want to change the session's context (e.g., to add timeouts), call
// Session.WithContext() to create a new session with a different context.
//
// The context can be used to set timeouts or cancel the dial operation:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	session, err := d.DialContext(ctx, conn)
func (d *Dialer) DialContext(ctx context.Context, tcpConn net.Conn) (*Session, error) {
	if ctx == nil {
		return nil, &InternalError{"nil context"}
	}

	if d.Initiator == nil {
		return nil, &InternalError{"Initiator is empty"}
	}

	// Validate NTLMInitiator if that's what we have
	if i, ok := d.Initiator.(*NTLMInitiator); ok {
		if i.User == "" {
			return nil, &InternalError{"Anonymous account is not supported. Use a username and password"}
		}
	}

	logger := LoggerFromContext(ctx)
	logger.Debug("Starting SMB1 dial to %s", tcpConn.RemoteAddr())

	// Create connection (wraps TCP conn with NetBIOS framing)
	conn := client.NewConn(tcpConn)

	// Start background receive loop.
	//
	// Goroutine lifecycle and cleanup:
	// The Receive goroutine is started before negotiation/session setup to handle
	// asynchronous responses. If dial fails at any point, conn.Close() ensures
	// proper cleanup:
	//   1. conn.Close() closes the conn.done channel
	//   2. Receive() checks conn.done at the start of each loop iteration
	//   3. If blocked in ReadPacket(), closing the underlying connection causes
	//      ReadPacket() to return an error, which triggers Receive() to exit
	//   4. Receive() has a defer that calls Close() again (idempotent)
	// This guarantees the Receive goroutine exits even if errors occur during
	// negotiation or session setup.
	go conn.Receive()

	// Negotiate protocol.
	// If this fails, conn.Close() will signal the Receive goroutine to exit.
	logger.Debug("Negotiating SMB1 protocol")
	if err := client.Negotiate(conn, ctx); err != nil {
		conn.Close()
		return nil, wrapError(err)
	}

	// Create internal initiator wrapper
	initiator := &initiatorWrapper{i: d.Initiator}

	// Perform session setup (NTLM authentication).
	// If this fails, conn.Close() will signal the Receive goroutine to exit.
	logger.Debug("Performing session setup (NTLM authentication)")
	sess, err := client.NewSession(conn, initiator, ctx)
	if err != nil {
		conn.Close()
		return nil, wrapError(err)
	}

	logger.Debug("SMB1 session established successfully")

	// Create public session wrapper
	// Extract logger from dial context and attach to a new background context
	// This allows the session to use the logger without inheriting timeouts/cancellation
	sessionCtx := WithLogger(context.Background(), LoggerFromContext(ctx))

	return &Session{
		s:    sess,
		conn: conn,
		ctx:  sessionCtx,
		addr: tcpConn.RemoteAddr().String(),
	}, nil
}

// initiatorWrapper adapts the public Initiator interface to the internal client.Initiator interface.
type initiatorWrapper struct {
	i Initiator
}

func (w *initiatorWrapper) Negotiate() ([]byte, error) {
	return w.i.initSecContext()
}

func (w *initiatorWrapper) Authenticate(challengeMsg []byte) ([]byte, error) {
	return w.i.acceptSecContext(challengeMsg)
}

func (w *initiatorWrapper) Session() *ntlm.Session {
	// For NTLMInitiator, get the session
	if ni, ok := w.i.(*NTLMInitiator); ok && ni.ntlm != nil {
		return ni.ntlm.Session()
	}
	return nil
}
