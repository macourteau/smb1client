package dcerpc

import (
	"encoding/binary"
	"fmt"
)

// Protocol constants based on DCE/RPC specification version 5.0
const (
	// VersionMajor is the major version of the DCE/RPC protocol (5)
	VersionMajor = 5
	// VersionMinor is the minor version of the DCE/RPC protocol (0)
	VersionMinor = 0
)

// Packet types define the different DCE/RPC PDU types
const (
	PacketTypeRequest  = 0  // Request PDU
	PacketTypeResponse = 2  // Response PDU
	PacketTypeBind     = 11 // Bind PDU
	PacketTypeBindAck  = 12 // Bind_Ack PDU
)

// Packet flags
const (
	// PFCFirstFrag indicates this is the first fragment
	PFCFirstFrag = 0x01
	// PFCLastFrag indicates this is the last fragment
	PFCLastFrag = 0x02
)

// DataRepresentation defines the little-endian NDR encoding
var DataRepresentation = [4]byte{0x10, 0x00, 0x00, 0x00}

// TransferSyntaxUUID is the UUID for 32-bit NDR transfer syntax
// UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
var TransferSyntaxUUID = [16]byte{
	0x04, 0x5d, 0x88, 0x8a, // time_low (little-endian)
	0xeb, 0x1c, // time_mid (little-endian)
	0xc9, 0x11, // time_hi_and_version (little-endian)
	0x9f, 0xe8, // clock_seq_hi_and_reserved, clock_seq_low
	0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, // node
}

// TransferSyntaxVersion is the version of the NDR transfer syntax (2.0)
// Encoded as uint32 with major version in low 16 bits, minor version in high 16 bits
const TransferSyntaxVersion = 0x00000002

// Header represents a DCE/RPC protocol header (16 bytes)
// This is the common header for all DCE/RPC PDUs.
type Header struct {
	Version      uint8   // RPC version (5)
	VersionMinor uint8   // RPC version minor (0)
	PacketType   uint8   // PDU type (Bind, Request, Response, etc.)
	Flags        uint8   // Packet flags (first/last fragment, etc.)
	DataRep      [4]byte // Data representation (little-endian NDR: [0x10, 0x00, 0x00, 0x00])
	FragLength   uint16  // Total length of the PDU including header
	AuthLength   uint16  // Length of authentication verifier (0 for no auth)
	CallID       uint32  // Call identifier for matching requests/responses
}

// HeaderSize is the size of the DCE/RPC header in bytes
const HeaderSize = 16

// EncodeHeader encodes a DCE/RPC header into a byte slice.
// Returns a 16-byte slice containing the encoded header.
func EncodeHeader(h *Header) []byte {
	buf := make([]byte, HeaderSize)
	buf[0] = h.Version
	buf[1] = h.VersionMinor
	buf[2] = h.PacketType
	buf[3] = h.Flags
	copy(buf[4:8], h.DataRep[:])
	binary.LittleEndian.PutUint16(buf[8:10], h.FragLength)
	binary.LittleEndian.PutUint16(buf[10:12], h.AuthLength)
	binary.LittleEndian.PutUint32(buf[12:16], h.CallID)
	return buf
}

// DecodeHeader parses a DCE/RPC header from a byte slice.
// Returns an error if the buffer is too short or contains invalid data.
func DecodeHeader(buf []byte) (*Header, error) {
	if len(buf) < HeaderSize {
		return nil, fmt.Errorf("dcerpc: header too short: got %d bytes, need %d", len(buf), HeaderSize)
	}

	h := &Header{
		Version:      buf[0],
		VersionMinor: buf[1],
		PacketType:   buf[2],
		Flags:        buf[3],
		FragLength:   binary.LittleEndian.Uint16(buf[8:10]),
		AuthLength:   binary.LittleEndian.Uint16(buf[10:12]),
		CallID:       binary.LittleEndian.Uint32(buf[12:16]),
	}
	copy(h.DataRep[:], buf[4:8])

	// Validate version
	if h.Version != VersionMajor {
		return nil, fmt.Errorf("dcerpc: unsupported version: got %d, expected %d", h.Version, VersionMajor)
	}

	return h, nil
}

// EncodeUUID encodes a UUID in little-endian format for DCE/RPC.
// UUIDs in DCE/RPC use mixed-endian encoding:
// - time_low (4 bytes): little-endian
// - time_mid (2 bytes): little-endian
// - time_hi_and_version (2 bytes): little-endian
// - clock_seq and node (8 bytes): big-endian (network byte order)
func EncodeUUID(uuid [16]byte) [16]byte {
	// UUID is already in the correct format for DCE/RPC
	return uuid
}

// ParseUUID parses a UUID string in the format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
// and returns it in DCE/RPC little-endian format.
func ParseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	if len(s) != 36 {
		return uuid, fmt.Errorf("dcerpc: invalid UUID length: got %d, expected 36", len(s))
	}

	// Parse hex digits and convert to little-endian where needed
	// Format: 4b324fc8-1670-01d3-1278-5a47bf6ee188
	// DCE/RPC: c84f324b-7016-d301-1278-5a47bf6ee188

	// time_low (4 bytes, little-endian)
	// Parse "4b324fc8" as c8, 4f, 32, 4b
	for i := 0; i < 4; i++ {
		var b uint8
		_, err := fmt.Sscanf(s[6-2*i:8-2*i], "%02x", &b)
		if err != nil {
			return uuid, fmt.Errorf("dcerpc: invalid UUID format: %w", err)
		}
		uuid[i] = b
	}

	// Skip hyphen at position 8
	if s[8] != '-' {
		return uuid, fmt.Errorf("dcerpc: invalid UUID format: missing hyphen at position 8")
	}

	// time_mid (2 bytes, little-endian)
	// Parse "1670" as 70, 16
	for i := 0; i < 2; i++ {
		var b uint8
		_, err := fmt.Sscanf(s[11-2*i:13-2*i], "%02x", &b)
		if err != nil {
			return uuid, fmt.Errorf("dcerpc: invalid UUID format: %w", err)
		}
		uuid[4+i] = b
	}

	// Skip hyphen at position 13
	if s[13] != '-' {
		return uuid, fmt.Errorf("dcerpc: invalid UUID format: missing hyphen at position 13")
	}

	// time_hi_and_version (2 bytes, little-endian)
	// Parse "01d3" as d3, 01
	for i := 0; i < 2; i++ {
		var b uint8
		_, err := fmt.Sscanf(s[16-2*i:18-2*i], "%02x", &b)
		if err != nil {
			return uuid, fmt.Errorf("dcerpc: invalid UUID format: %w", err)
		}
		uuid[6+i] = b
	}

	// Skip hyphen at position 18
	if s[18] != '-' {
		return uuid, fmt.Errorf("dcerpc: invalid UUID format: missing hyphen at position 18")
	}

	// clock_seq (2 bytes, big-endian)
	// Parse "1278" as 12, 78
	for i := 0; i < 2; i++ {
		var b uint8
		_, err := fmt.Sscanf(s[19+2*i:21+2*i], "%02x", &b)
		if err != nil {
			return uuid, fmt.Errorf("dcerpc: invalid UUID format: %w", err)
		}
		uuid[8+i] = b
	}

	// Skip hyphen at position 23
	if s[23] != '-' {
		return uuid, fmt.Errorf("dcerpc: invalid UUID format: missing hyphen at position 23")
	}

	// node (6 bytes, big-endian)
	// Parse "5a47bf6ee188" as 5a, 47, bf, 6e, e1, 88
	for i := 0; i < 6; i++ {
		var b uint8
		_, err := fmt.Sscanf(s[24+2*i:26+2*i], "%02x", &b)
		if err != nil {
			return uuid, fmt.Errorf("dcerpc: invalid UUID format: %w", err)
		}
		uuid[10+i] = b
	}

	return uuid, nil
}
