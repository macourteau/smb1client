package smb1

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/macourteau/smb1client/internal/utf16le"
)

// NegotiateRequest represents an SMB_COM_NEGOTIATE request.
// This is the first command sent by a client to negotiate protocol dialect and capabilities.
//
// Request format:
//
//	WordCount: 0 (no parameters for negotiate request)
//	ByteCount: variable
//	BufferFormat: 0x02 (for each dialect)
//	DialectString: null-terminated ASCII string
type NegotiateRequest struct {
	Dialects []string // List of supported dialects (e.g., "NT LM 0.12")
}

// NegotiateResponse represents an SMB_COM_NEGOTIATE response for NT LM 0.12 dialect.
// The server selects a dialect and returns its capabilities.
//
// Response format (for NT LM 0.12, WordCount = 17):
//
//	Parameters (34 bytes = 17 words):
//	  0-2:   DialectIndex (uint16)
//	  2-3:   SecurityMode (uint8)
//	  3-5:   MaxMpxCount (uint16)
//	  5-7:   MaxNumberVcs (uint16)
//	  7-11:  MaxBufferSize (uint32)
//	  11-15: MaxRawSize (uint32)
//	  15-19: SessionKey (uint32)
//	  19-23: Capabilities (uint32)
//	  23-31: SystemTime (uint64)
//	  31-33: ServerTimeZone (int16)
//	  33-34: ChallengeLength (uint8)
//	Data:
//	  Challenge (ChallengeLength bytes)
//	  DomainName (null-terminated, UTF-16LE if CAP_UNICODE)
//	  ServerName (null-terminated, UTF-16LE if CAP_UNICODE)
type NegotiateResponse struct {
	DialectIndex    uint16 // Index of selected dialect (0xFFFF = none supported)
	SecurityMode    uint8  // Security mode flags
	MaxMpxCount     uint16 // Max pending requests
	MaxNumberVcs    uint16 // Max virtual circuits
	MaxBufferSize   uint32 // Max buffer size in bytes
	MaxRawSize      uint32 // Max raw buffer size
	SessionKey      uint32 // Session key
	Capabilities    uint32 // Server capabilities (CAP_* flags)
	SystemTime      uint64 // Server time (Windows FILETIME)
	ServerTimeZone  int16  // Minutes from UTC
	ChallengeLength uint8  // Length of challenge
	Challenge       []byte // NTLM challenge (usually 8 bytes)
	DomainName      string // Server domain name
	ServerName      string // Server name
}

// Security mode flags for NegotiateResponse.SecurityMode
const (
	NEGOTIATE_USER_SECURITY                uint8 = 0x01 // User-level security (vs share-level)
	NEGOTIATE_ENCRYPT_PASSWORDS            uint8 = 0x02 // Challenge/response authentication
	NEGOTIATE_SECURITY_SIGNATURES_ENABLED  uint8 = 0x04 // Security signatures enabled
	NEGOTIATE_SECURITY_SIGNATURES_REQUIRED uint8 = 0x08 // Security signatures required
)

// DefaultDialects is the default list of dialects to negotiate, in preference order.
// NT LM 0.12 is the primary SMB1 dialect supported by modern Windows servers.
var DefaultDialects = []string{
	"NT LM 0.12",
	"NT LANMAN 1.0",
	"LANMAN1.0",
}

// EncodeNegotiateRequest encodes an SMB_COM_NEGOTIATE request with the specified dialects.
// Returns parameters (empty for negotiate) and data sections.
//
// The data section contains each dialect as:
//   - BufferFormat (0x02)
//   - DialectString (null-terminated ASCII)
func EncodeNegotiateRequest(dialects []string) ([]byte, []byte, error) {
	if len(dialects) == 0 {
		return nil, nil, fmt.Errorf("smb1: negotiate requires at least one dialect")
	}

	// Parameters section is empty (WordCount = 0)
	params := []byte{}

	// Data section contains dialects
	var data []byte
	for _, dialect := range dialects {
		// Buffer format identifier (0x02 = dialect string)
		data = append(data, 0x02)
		// Dialect string (null-terminated ASCII)
		data = append(data, []byte(dialect)...)
		data = append(data, 0x00) // null terminator
	}

	return params, data, nil
}

// DecodeNegotiateResponse decodes an SMB_COM_NEGOTIATE response.
// The params and data slices should be extracted from the SMB packet.
//
// For NT LM 0.12 dialect, WordCount should be 17 (34 bytes of parameters).
func DecodeNegotiateResponse(params, data []byte) (*NegotiateResponse, error) {
	// Validate parameters size (should be 34 bytes = 17 words for NT LM 0.12)
	if len(params) < 34 {
		return nil, fmt.Errorf("smb1: negotiate response parameters too short: got %d bytes, need 34", len(params))
	}

	resp := &NegotiateResponse{}

	// Parse parameters (34 bytes = 17 words)
	resp.DialectIndex = binary.LittleEndian.Uint16(params[0:2])
	resp.SecurityMode = params[2]
	resp.MaxMpxCount = binary.LittleEndian.Uint16(params[3:5])
	resp.MaxNumberVcs = binary.LittleEndian.Uint16(params[5:7])
	resp.MaxBufferSize = binary.LittleEndian.Uint32(params[7:11])
	resp.MaxRawSize = binary.LittleEndian.Uint32(params[11:15])
	resp.SessionKey = binary.LittleEndian.Uint32(params[15:19])
	resp.Capabilities = binary.LittleEndian.Uint32(params[19:23])
	resp.SystemTime = binary.LittleEndian.Uint64(params[23:31])
	resp.ServerTimeZone = int16(binary.LittleEndian.Uint16(params[31:33]))
	resp.ChallengeLength = params[33]

	// Check if dialect was accepted
	if resp.DialectIndex == 0xFFFF {
		return nil, fmt.Errorf("smb1: server does not support any of the proposed dialects")
	}

	// Parse data section
	if len(data) < int(resp.ChallengeLength) {
		return nil, fmt.Errorf("smb1: data too short for challenge: got %d bytes, need %d", len(data), resp.ChallengeLength)
	}

	// Extract challenge
	resp.Challenge = make([]byte, resp.ChallengeLength)
	copy(resp.Challenge, data[0:resp.ChallengeLength])

	// Parse domain and server names
	offset := int(resp.ChallengeLength)
	unicode := (resp.Capabilities & CAP_UNICODE) != 0

	// Some servers advertise CAP_UNICODE but still send ASCII strings in the
	// negotiate response. We need to auto-detect the encoding by checking if
	// the first string looks like ASCII (single null terminator) or UTF-16LE
	// (double null terminator with alternating nulls).
	actuallyUnicode := false
	if unicode && offset < len(data) {
		// Check if this looks like UTF-16LE or ASCII by examining the null terminator pattern
		// UTF-16LE: pairs of bytes where odd bytes are 0 for ASCII chars, ending in 00 00
		// Plain ASCII: bytes with values, ending in single 00
		//
		// We check: are most odd-positioned bytes zero? If yes, it's UTF-16LE.
		// For short strings, check if we have at least 2 null bytes in odd positions.

		// Align to even offset for UTF-16LE check
		checkOffset := offset
		if checkOffset%2 != 0 {
			checkOffset++
		}

		// Count nulls in odd positions (which would be the high bytes of UTF-16LE)
		// vs nulls in even positions
		nullsInOddPositions := 0
		nullsInEvenPositions := 0
		bytesChecked := 0

		for i := checkOffset; i < len(data) && bytesChecked < 16; i++ {
			if data[i] == 0 {
				if (i-checkOffset)%2 == 1 {
					nullsInOddPositions++
				} else {
					nullsInEvenPositions++
				}
			}
			bytesChecked++
			// Stop at first double null (either UTF-16LE terminator or consecutive ASCII nulls)
			if i > checkOffset && data[i] == 0 && data[i-1] == 0 {
				break
			}
		}

		// If we have multiple nulls in odd positions and few/none in even positions,
		// it's likely UTF-16LE. Otherwise it's ASCII.
		actuallyUnicode = nullsInOddPositions >= 2 && nullsInOddPositions > nullsInEvenPositions
	}

	if actuallyUnicode {
		// UTF-16LE strings - align to even offset and parse
		if offset%2 != 0 {
			offset++
		}

		// Domain name (UTF-16LE, null-terminated)
		if offset < len(data) {
			domainEnd := offset
			for domainEnd+1 < len(data) {
				if data[domainEnd] == 0 && data[domainEnd+1] == 0 {
					break
				}
				domainEnd += 2
			}
			if domainEnd > offset {
				resp.DomainName = utf16le.DecodeToString(data[offset:domainEnd])
			}
			offset = domainEnd + 2 // skip null terminator
		}

		// Server name (UTF-16LE, null-terminated)
		if offset < len(data) {
			serverEnd := offset
			for serverEnd+1 < len(data) {
				if data[serverEnd] == 0 && data[serverEnd+1] == 0 {
					break
				}
				serverEnd += 2
			}
			if serverEnd > offset {
				resp.ServerName = utf16le.DecodeToString(data[offset:serverEnd])
			}
		}
	} else {
		// Strings are ASCII, null-terminated
		// Domain name
		if offset < len(data) {
			domainEnd := offset
			for domainEnd < len(data) && data[domainEnd] != 0 {
				domainEnd++
			}
			resp.DomainName = string(data[offset:domainEnd])
			offset = domainEnd + 1 // skip null terminator
		}

		// Server name
		if offset < len(data) {
			serverEnd := offset
			for serverEnd < len(data) && data[serverEnd] != 0 {
				serverEnd++
			}
			resp.ServerName = string(data[offset:serverEnd])
		}
	}

	return resp, nil
}

// SupportsExtendedSecurity returns true if the server supports extended security (NTLM).
func (r *NegotiateResponse) SupportsExtendedSecurity() bool {
	return (r.Capabilities & CAP_EXTENDED_SECURITY) != 0
}

// SupportsUnicode returns true if the server supports Unicode strings.
func (r *NegotiateResponse) SupportsUnicode() bool {
	return (r.Capabilities & CAP_UNICODE) != 0
}

// SupportsLargeFiles returns true if the server supports 64-bit file offsets.
func (r *NegotiateResponse) SupportsLargeFiles() bool {
	return (r.Capabilities & CAP_LARGE_FILES) != 0
}

// RequiresEncryption returns true if the server requires password encryption.
func (r *NegotiateResponse) RequiresEncryption() bool {
	return (r.SecurityMode & NEGOTIATE_ENCRYPT_PASSWORDS) != 0
}

// String returns a human-readable representation of the negotiate response.
func (r *NegotiateResponse) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("NegotiateResponse{DialectIndex:%d SecurityMode:0x%02X ", r.DialectIndex, r.SecurityMode))
	sb.WriteString(fmt.Sprintf("MaxMpxCount:%d MaxBufferSize:%d ", r.MaxMpxCount, r.MaxBufferSize))
	sb.WriteString(fmt.Sprintf("Capabilities:0x%08X Domain:%q Server:%q}", r.Capabilities, r.DomainName, r.ServerName))
	return sb.String()
}
