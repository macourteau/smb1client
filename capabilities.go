package smb1

import (
	"fmt"

	"github.com/macourteau/smb1client/internal/client"
)

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

	// ServerName is the NetBIOS name of the server. It is empty against a
	// server that negotiates extended security, which sends a GUID and a
	// security blob in place of the names.
	ServerName string

	// DomainName is the domain or workgroup name the server belongs to. It is
	// empty against a server that negotiates extended security, for the same
	// reason as ServerName.
	DomainName string

	// SupportsPipelining indicates whether the server supports concurrent
	// (pipelined) requests. This is true when MaxMpxCount > 1.
	SupportsPipelining bool

	// EffectivePipelineDepth is the actual pipeline depth that will be used
	// by this client implementation, capped at 50 for safety. It is 1 when
	// SupportsPipelining is false, since the client then issues one request at
	// a time.
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

	// Ask the transfer paths what they will do rather than restating it, so a
	// report of "no pipelining, depth 30" cannot arise again.
	effectiveDepth, supportsPipelining := client.PipelineDepth(maxMpx)

	return ServerCapabilities{
		MaxMpxCount:            maxMpx,
		MaxBufferSize:          maxBuf,
		ServerName:             serverName,
		DomainName:             domainName,
		SupportsPipelining:     supportsPipelining,
		EffectivePipelineDepth: effectiveDepth,
	}
}
