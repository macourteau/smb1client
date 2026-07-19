package smb1

import (
	"encoding/binary"
	"fmt"
)

// HeaderSize is the fixed size of an SMB1 header (32 bytes)
const HeaderSize = 32

// Header represents the SMB1 protocol header (32 bytes).
// The SMB1 header appears at the start of every SMB1 message and contains
// metadata about the command, status, and session identifiers.
//
// Header format (all fields little-endian except Protocol):
//
//	Offset  Size  Field
//	0       4     Protocol (0xFF 'S' 'M' 'B')
//	4       1     Command
//	5       4     Status (NT_STATUS)
//	9       1     Flags
//	10      2     Flags2
//	12      2     PIDHigh
//	14      8     SecurityFeatures (signature or zero)
//	22      2     Reserved
//	24      2     TID (Tree ID)
//	26      2     PIDLow
//	28      2     UID (User ID)
//	30      2     MID (Multiplex ID)
type Header struct {
	Protocol         [4]byte // 0xFF 'S' 'M' 'B'
	Command          uint8   // SMB command code
	Status           uint32  // NT_STATUS code
	Flags            uint8   // Flag bits
	Flags2           uint16  // Extended flag bits
	PIDHigh          uint16  // High part of Process ID
	SecurityFeatures [8]byte // Security signature (or zero if not signing)
	Reserved         uint16  // Reserved (must be zero)
	TID              uint16  // Tree ID (share connection)
	PIDLow           uint16  // Low part of Process ID
	UID              uint16  // User ID (session)
	MID              uint16  // Multiplex ID (request/response matching)
}

// NewHeader creates a new SMB1 header with the specified command.
// The header is initialized with the SMB1 protocol signature and default values:
//   - Protocol: 0xFF 'S' 'M' 'B'
//   - Command: as specified
//   - Status: STATUS_SUCCESS
//   - Flags: SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS
//   - Flags2: SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_UNICODE | SMB_FLAGS2_EXTENDED_SECURITY | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_EAS
//   - PIDLow: 1 (some servers require non-zero PID)
//   - All other fields: 0
func NewHeader(command uint8) *Header {
	h := &Header{
		Command: command,
		Status:  STATUS_SUCCESS,
		// Default flags for modern SMB1 clients
		Flags:  SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS,
		Flags2: SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_UNICODE | SMB_FLAGS2_EXTENDED_SECURITY | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_EAS,
		PIDLow: 1, // Some servers require non-zero PID
	}
	copy(h.Protocol[:], ProtocolSMB1)
	return h
}

// Encode serializes the header into a 32-byte buffer.
// All multi-byte fields are encoded in little-endian format.
func (h *Header) Encode() []byte {
	buf := make([]byte, HeaderSize)

	// Protocol signature (4 bytes)
	copy(buf[0:4], h.Protocol[:])

	// Command (1 byte)
	buf[4] = h.Command

	// Status (4 bytes, little-endian)
	binary.LittleEndian.PutUint32(buf[5:9], h.Status)

	// Flags (1 byte)
	buf[9] = h.Flags

	// Flags2 (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[10:12], h.Flags2)

	// PIDHigh (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[12:14], h.PIDHigh)

	// SecurityFeatures (8 bytes)
	copy(buf[14:22], h.SecurityFeatures[:])

	// Reserved (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[22:24], h.Reserved)

	// TID (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[24:26], h.TID)

	// PIDLow (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[26:28], h.PIDLow)

	// UID (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[28:30], h.UID)

	// MID (2 bytes, little-endian)
	binary.LittleEndian.PutUint16(buf[30:32], h.MID)

	return buf
}

// DecodeHeader parses a 32-byte SMB1 header from the provided data.
// Returns an error if the data is too short or the protocol signature is invalid.
func DecodeHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("smb1: header too short: got %d bytes, need %d", len(data), HeaderSize)
	}

	h := &Header{}

	// Protocol signature (4 bytes)
	copy(h.Protocol[:], data[0:4])
	if string(h.Protocol[:]) != ProtocolSMB1 {
		return nil, fmt.Errorf("smb1: invalid protocol signature: got %#v, want %#v",
			h.Protocol, []byte(ProtocolSMB1))
	}

	// Command (1 byte)
	h.Command = data[4]

	// Status (4 bytes, little-endian)
	h.Status = binary.LittleEndian.Uint32(data[5:9])

	// Flags (1 byte)
	h.Flags = data[9]

	// Flags2 (2 bytes, little-endian)
	h.Flags2 = binary.LittleEndian.Uint16(data[10:12])

	// PIDHigh (2 bytes, little-endian)
	h.PIDHigh = binary.LittleEndian.Uint16(data[12:14])

	// SecurityFeatures (8 bytes)
	copy(h.SecurityFeatures[:], data[14:22])

	// Reserved (2 bytes, little-endian)
	h.Reserved = binary.LittleEndian.Uint16(data[22:24])

	// TID (2 bytes, little-endian)
	h.TID = binary.LittleEndian.Uint16(data[24:26])

	// PIDLow (2 bytes, little-endian)
	h.PIDLow = binary.LittleEndian.Uint16(data[26:28])

	// UID (2 bytes, little-endian)
	h.UID = binary.LittleEndian.Uint16(data[28:30])

	// MID (2 bytes, little-endian)
	h.MID = binary.LittleEndian.Uint16(data[30:32])

	return h, nil
}

// IsResponse returns true if this header is from a server response (vs. client request).
func (h *Header) IsResponse() bool {
	return (h.Flags & SMB_FLAGS_REPLY) != 0
}

// IsError returns true if the status code indicates an error.
// NT status codes have the following severity levels in the top 2 bits:
// 0x0000xxxx = SUCCESS
// 0x4000xxxx = INFORMATIONAL
// 0x8000xxxx = WARNING (e.g., STATUS_NO_MORE_FILES)
// 0xC000xxxx = ERROR
// We treat ERROR-level codes as errors, except for special cases:
//   - STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) is a valid intermediate status
//     for multi-round authentication and should not be treated as an error.
//
// We also explicitly allow WARNING-level codes like STATUS_NO_MORE_FILES (0x80000006).
func (h *Header) IsError() bool {
	// Special case: STATUS_MORE_PROCESSING_REQUIRED is not an error
	if h.Status == STATUS_MORE_PROCESSING_REQUIRED {
		return false
	}
	// Allow SUCCESS and WARNING-level codes, only fail on ERROR-level codes
	return (h.Status & 0xC0000000) == 0xC0000000
}

// Error returns a Go error for the header's status code, or nil if STATUS_SUCCESS.
func (h *Header) Error() error {
	return StatusToError(h.Status)
}

// String returns a human-readable representation of the header.
func (h *Header) String() string {
	return fmt.Sprintf("SMB1 Header{Cmd:0x%02X Status:0x%08X Flags:0x%02X Flags2:0x%04X TID:%d UID:%d MID:%d}",
		h.Command, h.Status, h.Flags, h.Flags2, h.TID, h.UID, h.MID)
}

// AndXHeader represents the AndX command chaining header used in some SMB1 commands.
// Commands that support chaining (SESSION_SETUP_ANDX, TREE_CONNECT_ANDX, etc.)
// can chain multiple commands in a single message for efficiency.
//
// The AndX header appears immediately after the SMB header in the Parameters section:
//
//	Offset  Size  Field
//	0       1     AndXCommand (next chained command, or 0xFF for none)
//	1       1     AndXReserved (must be 0)
//	2       2     AndXOffset (offset to next command from start of SMB header)
type AndXHeader struct {
	AndXCommand  uint8  // Next chained command (SMB_COM_NO_ANDX_COMMAND if none)
	AndXReserved uint8  // Reserved (must be zero)
	AndXOffset   uint16 // Offset to next command from start of SMB header
}

// NewAndXHeader creates a new AndX header with no chaining (command = 0xFF).
func NewAndXHeader() *AndXHeader {
	return &AndXHeader{
		AndXCommand:  SMB_COM_NO_ANDX_COMMAND,
		AndXReserved: 0,
		AndXOffset:   0,
	}
}

// Encode serializes the AndX header into a 4-byte buffer.
func (a *AndXHeader) Encode() []byte {
	buf := make([]byte, 4)
	buf[0] = a.AndXCommand
	buf[1] = a.AndXReserved
	binary.LittleEndian.PutUint16(buf[2:4], a.AndXOffset)
	return buf
}

// DecodeAndXHeader parses a 4-byte AndX header from the provided data.
func DecodeAndXHeader(data []byte) (*AndXHeader, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("smb1: AndX header too short: got %d bytes, need 4", len(data))
	}

	return &AndXHeader{
		AndXCommand:  data[0],
		AndXReserved: data[1],
		AndXOffset:   binary.LittleEndian.Uint16(data[2:4]),
	}, nil
}

// HasChaining returns true if this AndX header chains to another command.
func (a *AndXHeader) HasChaining() bool {
	return a.AndXCommand != SMB_COM_NO_ANDX_COMMAND
}

// String returns a human-readable representation of the AndX header.
func (a *AndXHeader) String() string {
	if !a.HasChaining() {
		return "AndX{None}"
	}
	return fmt.Sprintf("AndX{Cmd:0x%02X Offset:%d}", a.AndXCommand, a.AndXOffset)
}
