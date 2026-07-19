package smb1

import "fmt"

// ServerCapabilities contains information about the SMB server's capabilities
// as negotiated during the protocol handshake.
type ServerCapabilities struct {
	// MaxMpxCount is the maximum number of outstanding (pipelined) requests
	// the server can handle concurrently. A value of 0 or 1 means the server
	// does not support request pipelining.
	MaxMpxCount uint16

	// MaxBufferSize is the maximum size of an SMB message (in bytes) that the
	// server can receive. This limits the size of individual read/write requests.
	MaxBufferSize uint32

	// ServerName is the NetBIOS name of the server.
	ServerName string

	// DomainName is the domain or workgroup name the server belongs to.
	DomainName string

	// SupportsPipelining indicates whether the server supports concurrent
	// (pipelined) requests. This is true when MaxMpxCount > 1.
	SupportsPipelining bool

	// EffectivePipelineDepth is the actual pipeline depth that will be used
	// by this client implementation, capped at 50 for safety.
	EffectivePipelineDepth int
}

// String returns a human-readable representation of the server capabilities.
func (c ServerCapabilities) String() string {
	pipelineStatus := "No (sequential requests only)"
	if c.SupportsPipelining {
		pipelineStatus = fmt.Sprintf("Yes (up to %d concurrent requests)", c.EffectivePipelineDepth)
	}

	return fmt.Sprintf(`Server Capabilities:
  Server Name:          %s
  Domain:               %s
  Max Buffer Size:      %d bytes (%.1f KiB)
  Max Multiplex Count:  %d
  Pipelining Support:   %s`,
		c.ServerName,
		c.DomainName,
		c.MaxBufferSize,
		float64(c.MaxBufferSize)/1024.0,
		c.MaxMpxCount,
		pipelineStatus)
}

// Capabilities returns information about the negotiated server capabilities.
// This includes details about request pipelining support, buffer sizes,
// and server identification.
func (s *Session) Capabilities() ServerCapabilities {
	maxMpx, maxBuf, serverName, domainName := s.conn.GetCapabilities()

	// Calculate effective pipeline depth using same logic as file.go
	effectiveDepth := int(maxMpx)
	if effectiveDepth == 0 {
		// Server didn't specify, use safe default
		effectiveDepth = 30
	} else if effectiveDepth > 50 {
		// Cap at 50 for safety with servers advertising very high values
		effectiveDepth = 50
	}

	supportsPipelining := maxMpx > 1

	return ServerCapabilities{
		MaxMpxCount:            maxMpx,
		MaxBufferSize:          maxBuf,
		ServerName:             serverName,
		DomainName:             domainName,
		SupportsPipelining:     supportsPipelining,
		EffectivePipelineDepth: effectiveDepth,
	}
}
