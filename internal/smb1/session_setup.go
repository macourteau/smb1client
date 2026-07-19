package smb1

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/macourteau/smb1client/internal/utf16le"
)

// SessionSetupRequest represents an SMB_COM_SESSION_SETUP_ANDX request.
// This command establishes a user session with the server using NTLM authentication.
//
// Request format (AndX command, WordCount = 12 for extended security):
//
//	Parameters (24 bytes = 12 words):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-6:   MaxBufferSize (uint16)
//	  6-8:   MaxMpxCount (uint16)
//	  8-10:  VcNumber (uint16)
//	  10-14: SessionKey (uint32)
//	  14-16: SecurityBlobLength (uint16)
//	  16-20: Reserved (uint32)
//	  20-24: Capabilities (uint32)
//	Data:
//	  SecurityBlob (NTLM token)
//	  NativeOS (null-terminated string)
//	  NativeLanMan (null-terminated string)
type SessionSetupRequest struct {
	AndXCommand        uint8  // Chained command (usually SMB_COM_NO_ANDX_COMMAND)
	AndXReserved       uint8  // Reserved (must be 0)
	AndXOffset         uint16 // Offset to next command
	MaxBufferSize      uint16 // Client max buffer size
	MaxMpxCount        uint16 // Client max pending requests
	VcNumber           uint16 // Virtual circuit number
	SessionKey         uint32 // Session key from negotiate
	SecurityBlobLength uint16 // Length of NTLM token
	Reserved           uint32 // Reserved (must be 0)
	Capabilities       uint32 // Client capabilities
	SecurityBlob       []byte // NTLM authentication token
	NativeOS           string // Client OS (e.g., "Unix")
	NativeLanMan       string // Client LAN Manager (e.g., "Samba")
	UseUnicode         bool   // Whether to use Unicode strings
}

// SessionSetupResponse represents an SMB_COM_SESSION_SETUP_ANDX response.
//
// Response format (AndX command, WordCount = 4 for extended security):
//
//	Parameters (8 bytes = 4 words):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-6:   Action (uint16)
//	  6-8:   SecurityBlobLength (uint16)
//	Data:
//	  SecurityBlob (NTLM token)
//	  NativeOS (null-terminated string)
//	  NativeLanMan (null-terminated string)
//	  PrimaryDomain (null-terminated string, optional)
type SessionSetupResponse struct {
	AndXCommand        uint8  // Chained command
	AndXReserved       uint8  // Reserved
	AndXOffset         uint16 // Offset to next command
	Action             uint16 // Action flags
	SecurityBlobLength uint16 // Length of NTLM token
	SecurityBlob       []byte // NTLM authentication response
	NativeOS           string // Server OS
	NativeLanMan       string // Server LAN Manager
	PrimaryDomain      string // Primary domain (optional)
}

// Action flags for SessionSetupResponse.Action
const (
	SESSION_SETUP_GUEST uint16 = 0x0001 // User logged in as guest
)

// EncodeSessionSetupRequest encodes an SMB_COM_SESSION_SETUP_ANDX request.
// Returns parameters and data sections.
func EncodeSessionSetupRequest(req *SessionSetupRequest) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: session setup request is nil")
	}

	// Parameters: 12 words = 24 bytes (extended security format)
	params := make([]byte, 24)

	// AndX header (4 bytes)
	params[0] = req.AndXCommand
	params[1] = req.AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], req.AndXOffset)

	// Session setup parameters
	binary.LittleEndian.PutUint16(params[4:6], req.MaxBufferSize)
	binary.LittleEndian.PutUint16(params[6:8], req.MaxMpxCount)
	binary.LittleEndian.PutUint16(params[8:10], req.VcNumber)
	binary.LittleEndian.PutUint32(params[10:14], req.SessionKey)
	binary.LittleEndian.PutUint16(params[14:16], req.SecurityBlobLength)
	binary.LittleEndian.PutUint32(params[16:20], req.Reserved)
	binary.LittleEndian.PutUint32(params[20:24], req.Capabilities)

	// Note: ByteCount is not part of parameters, it's calculated by EncodePacket

	// Data section
	var data []byte

	// Security blob
	if len(req.SecurityBlob) > 0 {
		data = append(data, req.SecurityBlob...)
	}

	// Padding for alignment (if using Unicode, data should be word-aligned)
	if req.UseUnicode && len(data)%2 != 0 {
		data = append(data, 0)
	}

	// Native OS string
	if req.UseUnicode {
		osBytes := utf16le.EncodeStringToBytes(req.NativeOS)
		data = append(data, osBytes...)
		data = append(data, 0, 0) // UTF-16LE null terminator
	} else {
		data = append(data, []byte(req.NativeOS)...)
		data = append(data, 0) // ASCII null terminator
	}

	// Native LAN Manager string
	if req.UseUnicode {
		lanmanBytes := utf16le.EncodeStringToBytes(req.NativeLanMan)
		data = append(data, lanmanBytes...)
		data = append(data, 0, 0) // UTF-16LE null terminator
	} else {
		data = append(data, []byte(req.NativeLanMan)...)
		data = append(data, 0) // ASCII null terminator
	}

	return params, data, nil
}

// DecodeSessionSetupResponse decodes an SMB_COM_SESSION_SETUP_ANDX response.
func DecodeSessionSetupResponse(params, data []byte, useUnicode bool) (*SessionSetupResponse, error) {
	// Validate parameters size (should be at least 6 bytes for simple response, 8 for extended security)
	if len(params) < 6 {
		return nil, fmt.Errorf("smb1: session setup response parameters too short: got %d bytes, need at least 6", len(params))
	}

	resp := &SessionSetupResponse{}

	// Parse AndX header
	resp.AndXCommand = params[0]
	resp.AndXReserved = params[1]
	resp.AndXOffset = binary.LittleEndian.Uint16(params[2:4])

	// Parse session setup response parameters
	resp.Action = binary.LittleEndian.Uint16(params[4:6])

	// SecurityBlobLength is optional (not present in simple/guest auth responses)
	if len(params) >= 8 {
		resp.SecurityBlobLength = binary.LittleEndian.Uint16(params[6:8])
	}

	// Parse data section
	if len(data) < int(resp.SecurityBlobLength) {
		return nil, fmt.Errorf("smb1: data too short for security blob: got %d bytes, need %d", len(data), resp.SecurityBlobLength)
	}

	// Extract security blob
	if resp.SecurityBlobLength > 0 {
		resp.SecurityBlob = make([]byte, resp.SecurityBlobLength)
		copy(resp.SecurityBlob, data[0:resp.SecurityBlobLength])
	}

	offset := int(resp.SecurityBlobLength)

	// Skip padding for alignment if using Unicode
	if useUnicode && offset < len(data) && offset%2 != 0 {
		offset++
	}

	// Parse strings (NativeOS, NativeLanMan, PrimaryDomain)
	if useUnicode {
		// UTF-16LE strings
		// Native OS
		if offset < len(data) {
			osEnd := offset
			for osEnd+1 < len(data) {
				if data[osEnd] == 0 && data[osEnd+1] == 0 {
					break
				}
				osEnd += 2
			}
			if osEnd > offset {
				resp.NativeOS = utf16le.DecodeToString(data[offset:osEnd])
			}
			offset = osEnd + 2 // skip null terminator
		}

		// Native LAN Manager
		if offset < len(data) {
			lanmanEnd := offset
			for lanmanEnd+1 < len(data) {
				if data[lanmanEnd] == 0 && data[lanmanEnd+1] == 0 {
					break
				}
				lanmanEnd += 2
			}
			if lanmanEnd > offset {
				resp.NativeLanMan = utf16le.DecodeToString(data[offset:lanmanEnd])
			}
			offset = lanmanEnd + 2 // skip null terminator
		}

		// Primary Domain (optional)
		if offset < len(data) {
			domainEnd := offset
			for domainEnd+1 < len(data) {
				if data[domainEnd] == 0 && data[domainEnd+1] == 0 {
					break
				}
				domainEnd += 2
			}
			if domainEnd > offset {
				resp.PrimaryDomain = utf16le.DecodeToString(data[offset:domainEnd])
			}
		}
	} else {
		// ASCII strings
		// Native OS
		if offset < len(data) {
			osEnd := offset
			for osEnd < len(data) && data[osEnd] != 0 {
				osEnd++
			}
			resp.NativeOS = string(data[offset:osEnd])
			offset = osEnd + 1 // skip null terminator
		}

		// Native LAN Manager
		if offset < len(data) {
			lanmanEnd := offset
			for lanmanEnd < len(data) && data[lanmanEnd] != 0 {
				lanmanEnd++
			}
			resp.NativeLanMan = string(data[offset:lanmanEnd])
			offset = lanmanEnd + 1 // skip null terminator
		}

		// Primary Domain (optional)
		if offset < len(data) {
			domainEnd := offset
			for domainEnd < len(data) && data[domainEnd] != 0 {
				domainEnd++
			}
			resp.PrimaryDomain = string(data[offset:domainEnd])
		}
	}

	return resp, nil
}

// IsGuest returns true if the user was logged in as a guest.
func (r *SessionSetupResponse) IsGuest() bool {
	return (r.Action & SESSION_SETUP_GUEST) != 0
}

// HasChaining returns true if this response chains to another command.
func (r *SessionSetupResponse) HasChaining() bool {
	return r.AndXCommand != SMB_COM_NO_ANDX_COMMAND
}

// String returns a human-readable representation of the session setup response.
func (r *SessionSetupResponse) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SessionSetupResponse{Action:0x%04X ", r.Action))
	if r.IsGuest() {
		sb.WriteString("(GUEST) ")
	}
	sb.WriteString(fmt.Sprintf("OS:%q LanMan:%q", r.NativeOS, r.NativeLanMan))
	if r.PrimaryDomain != "" {
		sb.WriteString(fmt.Sprintf(" Domain:%q", r.PrimaryDomain))
	}
	sb.WriteString("}")
	return sb.String()
}
