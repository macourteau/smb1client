package smb1

import (
	"encoding/binary"
	"fmt"
)

// SMB1 packet structure:
//
//	+------------------+
//	| NetBIOS Header   | (4 bytes - handled by netbios package)
//	+------------------+
//	| SMB Header       | (32 bytes - this package)
//	+------------------+
//	| WordCount        | (1 byte - number of 16-bit words in Parameters)
//	+------------------+
//	| Parameters       | (WordCount * 2 bytes)
//	+------------------+
//	| ByteCount        | (2 bytes - number of bytes in Data)
//	+------------------+
//	| Data             | (ByteCount bytes)
//	+------------------+

// MaxParametersSize is the maximum size for the Parameters section.
// SMB1 uses WordCount (1 byte = 255 max) to specify number of 16-bit words.
// Maximum: 255 words * 2 bytes/word = 510 bytes
const MaxParametersSize = 255 * 2

// MaxDataSize is the maximum size for the Data section in a single SMB message.
// While ByteCount is a 2-byte field (max 65535), the actual data limit is determined
// by the NetBIOS session layer (131072 bytes).
// For commands like WRITE_ANDX that support >64KB data via DataLengthHigh field,
// we allow up to the NetBIOS limit minus overhead for headers (~1KB).
const MaxDataSize = 130048 // ~127KB, same as smbclient uses

// Packet represents a complete SMB1 protocol packet.
// A packet consists of:
//   - Header (32 bytes)
//   - WordCount (1 byte): number of 16-bit words in Parameters
//   - Parameters (variable): command-specific parameters
//   - ByteCount (2 bytes): number of bytes in Data
//   - Data (variable): command-specific data
type Packet struct {
	Header     *Header
	Parameters []byte
	Data       []byte
}

// EncodePacket encodes a complete SMB1 packet into a byte slice.
// The packet structure is:
//   - SMB Header (32 bytes)
//   - WordCount (1 byte)
//   - Parameters (WordCount * 2 bytes)
//   - ByteCount (2 bytes)
//   - Data (ByteCount bytes)
//
// Returns an error if:
//   - header is nil
//   - Parameters size is not a multiple of 2 (must be 16-bit words)
//   - Parameters size exceeds MaxParametersSize
//   - Data size exceeds MaxDataSize
func EncodePacket(header *Header, params []byte, data []byte) ([]byte, error) {
	if header == nil {
		return nil, fmt.Errorf("smb1: cannot encode packet with nil header")
	}

	// Validate parameters size (must be multiple of 2 for 16-bit words)
	if len(params)%2 != 0 {
		return nil, fmt.Errorf("smb1: parameters size must be multiple of 2 (16-bit words), got %d", len(params))
	}

	// Validate parameters size (WordCount is 1 byte, max 255 words = 510 bytes)
	if len(params) > MaxParametersSize {
		return nil, fmt.Errorf("smb1: parameters size %d exceeds maximum %d", len(params), MaxParametersSize)
	}

	// Validate data size (ByteCount is 2 bytes, max 65535 bytes)
	if len(data) > MaxDataSize {
		return nil, fmt.Errorf("smb1: data size %d exceeds maximum %d", len(data), MaxDataSize)
	}

	// Calculate WordCount (number of 16-bit words in parameters)
	wordCount := uint8(len(params) / 2)

	// Calculate total packet size
	totalSize := HeaderSize + 1 + len(params) + 2 + len(data)
	buf := make([]byte, totalSize)

	// Encode header (32 bytes)
	copy(buf[0:HeaderSize], header.Encode())

	// Encode WordCount (1 byte)
	buf[HeaderSize] = wordCount

	// Encode Parameters (variable length)
	if len(params) > 0 {
		copy(buf[HeaderSize+1:HeaderSize+1+len(params)], params)
	}

	// Encode ByteCount (2 bytes, little-endian)
	// For data >65535 bytes (used in WRITE_ANDX with DataLengthHigh), the ByteCount
	// field contains the low 16 bits. The actual data length is specified in the
	// command parameters (e.g., DataLength + DataLengthHigh for WRITE_ANDX).
	byteCountOffset := HeaderSize + 1 + len(params)
	binary.LittleEndian.PutUint16(buf[byteCountOffset:byteCountOffset+2], uint16(len(data)&0xFFFF))

	// Encode Data (variable length)
	if len(data) > 0 {
		dataOffset := byteCountOffset + 2
		copy(buf[dataOffset:dataOffset+len(data)], data)
	}

	return buf, nil
}

// DecodePacket parses a complete SMB1 packet from raw bytes.
// Returns the header, parameters, and data sections, or an error if parsing fails.
//
// The function validates:
//   - Minimum packet size (header + wordcount + bytecount = 35 bytes)
//   - Protocol signature in header
//   - Parameters size matches WordCount
//   - Data size matches ByteCount
//   - Packet is complete (no truncation)
func DecodePacket(raw []byte) (*Header, []byte, []byte, error) {
	// Validate minimum packet size: header(32) + wordcount(1) + bytecount(2) = 35
	const minPacketSize = HeaderSize + 1 + 2
	if len(raw) < minPacketSize {
		return nil, nil, nil, fmt.Errorf("smb1: packet too short: got %d bytes, need at least %d", len(raw), minPacketSize)
	}

	// Decode header (32 bytes)
	header, err := DecodeHeader(raw[0:HeaderSize])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("smb1: failed to decode header: %w", err)
	}

	// Read WordCount (1 byte)
	wordCount := raw[HeaderSize]
	paramsSize := int(wordCount) * 2

	// Calculate offsets
	paramsOffset := HeaderSize + 1
	byteCountOffset := paramsOffset + paramsSize

	// Validate we have enough data for parameters and ByteCount field
	if len(raw) < byteCountOffset+2 {
		return nil, nil, nil, fmt.Errorf("smb1: packet truncated: need %d bytes for parameters and bytecount, got %d",
			byteCountOffset+2, len(raw))
	}

	// Read ByteCount (2 bytes, little-endian)
	// Note: For commands that support >64KB data (like WRITE_ANDX/READ_ANDX with DataLengthHigh),
	// ByteCount may wrap. We use the actual remaining packet size instead of ByteCount
	// to handle this correctly.
	byteCount := binary.LittleEndian.Uint16(raw[byteCountOffset : byteCountOffset+2])

	// Calculate actual data size from remaining bytes in packet
	dataOffset := byteCountOffset + 2
	dataSize := len(raw) - dataOffset

	// Sanity check: dataSize should be >= byteCount (may be larger if byteCount wrapped)
	// Special case: byteCount=0xFFFF with actual data indicates wrapping for large transfers,
	// but byteCount=0xFFFF with 0 bytes is still truncated data
	if dataSize < int(byteCount) && (byteCount != 0xFFFF || dataSize == 0) {
		return nil, nil, nil, fmt.Errorf("smb1: packet truncated: ByteCount=%d but only %d bytes remaining", byteCount, dataSize)
	}

	// Extract parameters (may be zero-length)
	var params []byte
	if paramsSize > 0 {
		params = make([]byte, paramsSize)
		copy(params, raw[paramsOffset:paramsOffset+paramsSize])
	}

	// Extract data (all remaining bytes)
	var data []byte
	if dataSize > 0 {
		data = make([]byte, dataSize)
		copy(data, raw[dataOffset:dataOffset+dataSize])
	}

	return header, params, data, nil
}

// MustEncodePacket is a convenience function that encodes a packet and panics on error.
// This is useful for testing and situations where encoding should never fail.
func MustEncodePacket(header *Header, params []byte, data []byte) []byte {
	buf, err := EncodePacket(header, params, data)
	if err != nil {
		panic(fmt.Sprintf("smb1: failed to encode packet: %v", err))
	}
	return buf
}

// EncodeParameters is a helper function for encoding command parameters.
// It accepts a variable number of values and encodes them in little-endian format.
// Supported types: uint8, uint16, uint32, uint64, []byte
//
// Example:
//
//	params := EncodeParameters(
//	    uint8(10),           // 1 byte
//	    uint16(0x1234),      // 2 bytes
//	    uint32(0x12345678),  // 4 bytes
//	    []byte("data"),      // variable bytes
//	)
func EncodeParameters(values ...interface{}) ([]byte, error) {
	var buf []byte

	for i, v := range values {
		switch val := v.(type) {
		case uint8:
			buf = append(buf, val)
		case uint16:
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, val)
			buf = append(buf, b...)
		case uint32:
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, val)
			buf = append(buf, b...)
		case uint64:
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, val)
			buf = append(buf, b...)
		case []byte:
			buf = append(buf, val...)
		default:
			return nil, fmt.Errorf("smb1: unsupported parameter type at index %d: %T", i, v)
		}
	}

	// Ensure result is multiple of 2 for WordCount
	if len(buf)%2 != 0 {
		buf = append(buf, 0) // Pad with zero byte
	}

	return buf, nil
}

// DecodeUint8 reads a uint8 from the buffer at the specified offset.
func DecodeUint8(buf []byte, offset int) (uint8, error) {
	if offset < 0 || offset >= len(buf) {
		return 0, fmt.Errorf("smb1: offset %d out of range [0, %d)", offset, len(buf))
	}
	return buf[offset], nil
}

// DecodeUint16 reads a uint16 (little-endian) from the buffer at the specified offset.
func DecodeUint16(buf []byte, offset int) (uint16, error) {
	if offset < 0 || offset+2 > len(buf) {
		return 0, fmt.Errorf("smb1: offset %d out of range for uint16 [0, %d)", offset, len(buf)-1)
	}
	return binary.LittleEndian.Uint16(buf[offset : offset+2]), nil
}

// DecodeUint32 reads a uint32 (little-endian) from the buffer at the specified offset.
func DecodeUint32(buf []byte, offset int) (uint32, error) {
	if offset < 0 || offset+4 > len(buf) {
		return 0, fmt.Errorf("smb1: offset %d out of range for uint32 [0, %d)", offset, len(buf)-3)
	}
	return binary.LittleEndian.Uint32(buf[offset : offset+4]), nil
}

// DecodeUint64 reads a uint64 (little-endian) from the buffer at the specified offset.
func DecodeUint64(buf []byte, offset int) (uint64, error) {
	if offset < 0 || offset+8 > len(buf) {
		return 0, fmt.Errorf("smb1: offset %d out of range for uint64 [0, %d)", offset, len(buf)-7)
	}
	return binary.LittleEndian.Uint64(buf[offset : offset+8]), nil
}

// DecodeBytes extracts a byte slice of the specified length from the buffer at the given offset.
func DecodeBytes(buf []byte, offset, length int) ([]byte, error) {
	if offset < 0 || offset+length > len(buf) {
		return nil, fmt.Errorf("smb1: offset %d with length %d out of range [0, %d)", offset, length, len(buf))
	}
	result := make([]byte, length)
	copy(result, buf[offset:offset+length])
	return result, nil
}
