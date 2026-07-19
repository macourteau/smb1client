package client

import (
	"context"
	"fmt"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// Negotiate performs SMB protocol negotiation with the server.
// It sends a negotiate request with supported dialects and validates the response.
// After successful negotiation, the connection's capabilities, buffer sizes, and
// challenge are populated.
func Negotiate(c *Conn, ctx context.Context) error {
	// Create negotiate request with default dialects
	dialects := []string{"NT LM 0.12", "NT LANMAN 1.0", "LANMAN1.0"}
	params, data, err := smb1.EncodeNegotiateRequest(dialects)
	if err != nil {
		return fmt.Errorf("smb1: failed to encode negotiate request: %w", err)
	}

	// Create SMB header for negotiate command
	header := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)

	// Send negotiate request and wait for response
	resp, err := c.sendRecv(header, params, data, ctx)
	if err != nil {
		// Don't wrap context errors - preserve original error for proper error checking
		if err == context.Canceled || err == context.DeadlineExceeded {
			return err
		}
		return fmt.Errorf("smb1: negotiate failed: %w", err)
	}

	// Capture the local receive time of the negotiate response so callers can
	// compare the server clock (SystemTime below) against the local clock.
	receivedAt := time.Now()

	// Check for protocol errors
	if resp.err != nil {
		return fmt.Errorf("smb1: negotiate returned error: %w", resp.err)
	}

	// Decode negotiate response
	negResp, err := smb1.DecodeNegotiateResponse(resp.params, resp.data)
	if err != nil {
		return fmt.Errorf("smb1: failed to decode negotiate response: %w", err)
	}

	// Validate that server selected a dialect (not 0xFFFF)
	if negResp.DialectIndex == 0xFFFF {
		return fmt.Errorf("smb1: server does not support any of the proposed dialects")
	}

	// Validate required capabilities
	requiredCaps := smb1.CAP_NT_SMBS | smb1.CAP_UNICODE | smb1.CAP_LARGE_FILES | smb1.CAP_STATUS32
	if (negResp.Capabilities & requiredCaps) != requiredCaps {
		return fmt.Errorf("smb1: server does not support required capabilities (need NT_SMBS, Unicode, Large Files, NT_STATUS)")
	}

	// Validate security mode (must use challenge/response)
	if (negResp.SecurityMode & smb1.NEGOTIATE_ENCRYPT_PASSWORDS) == 0 {
		return fmt.Errorf("smb1: server does not require encrypted passwords (insecure)")
	}

	// Store negotiated parameters in connection
	c.mu.Lock()
	c.capabilities = negResp.Capabilities
	c.maxBufferSize = negResp.MaxBufferSize
	c.maxMpxCount = negResp.MaxMpxCount
	c.sessionKey = negResp.SessionKey
	c.securityMode = negResp.SecurityMode
	c.challenge = make([]byte, len(negResp.Challenge))
	copy(c.challenge, negResp.Challenge)
	c.serverName = negResp.ServerName
	c.domainName = negResp.DomainName
	c.systemTime = negResp.SystemTime
	c.timeZone = negResp.ServerTimeZone
	c.negotiateTime = receivedAt
	c.mu.Unlock()

	return nil
}
