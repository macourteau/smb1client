package dcerpc

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// NDR (Network Data Representation) encoding functions
// These functions implement basic NDR marshaling needed for SRVSVC and other DCE/RPC interfaces.
// NDR uses little-endian encoding and has specific rules for alignment and pointers.

// Alignment requirements for NDR
const (
	Align2 = 2 // 2-byte alignment (uint16)
	Align4 = 4 // 4-byte alignment (uint32, pointers)
	Align8 = 8 // 8-byte alignment (uint64, hyper)
)

// AlignOffset returns the next offset aligned to the specified boundary.
// NDR requires primitives to be aligned to their natural boundaries.
func AlignOffset(offset, alignment int) int {
	if alignment == 0 {
		return offset
	}
	remainder := offset % alignment
	if remainder == 0 {
		return offset
	}
	return offset + (alignment - remainder)
}

// MarshalUint16 encodes a uint16 in little-endian format.
func MarshalUint16(v uint16) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, v)
	return buf
}

// MarshalUint32 encodes a uint32 in little-endian format.
func MarshalUint32(v uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	return buf
}

// MarshalUint64 encodes a uint64 in little-endian format.
func MarshalUint64(v uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	return buf
}

// UnmarshalUint16 decodes a uint16 from little-endian format.
func UnmarshalUint16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}

// UnmarshalUint32 decodes a uint32 from little-endian format.
func UnmarshalUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

// UnmarshalUint64 decodes a uint64 from little-endian format.
func UnmarshalUint64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

// MarshalConformantVaryingString encodes a Unicode string in NDR format.
// A conformant varying string in NDR consists of:
//   - MaxCount (4 bytes): maximum number of elements (characters + null terminator)
//   - Offset (4 bytes): offset to first character (always 0)
//   - ActualCount (4 bytes): actual number of elements (characters + null terminator)
//   - Characters (variable): UTF-16LE encoded characters including null terminator
//
// The string must be aligned to a 4-byte boundary.
func MarshalConformantVaryingString(s string) []byte {
	// Convert to UTF-16LE
	utf16Chars := utf16.Encode([]rune(s))

	// Add null terminator
	utf16Chars = append(utf16Chars, 0)

	// Calculate sizes
	charCount := len(utf16Chars)
	byteCount := charCount * 2

	// Allocate buffer: MaxCount(4) + Offset(4) + ActualCount(4) + Characters(byteCount)
	totalSize := 12 + byteCount
	buf := make([]byte, totalSize)

	// MaxCount
	binary.LittleEndian.PutUint32(buf[0:4], uint32(charCount))

	// Offset (always 0)
	binary.LittleEndian.PutUint32(buf[4:8], 0)

	// ActualCount
	binary.LittleEndian.PutUint32(buf[8:12], uint32(charCount))

	// Characters (UTF-16LE)
	offset := 12
	for _, char := range utf16Chars {
		binary.LittleEndian.PutUint16(buf[offset:offset+2], char)
		offset += 2
	}

	return buf
}

// UnmarshalConformantVaryingString decodes a Unicode string from NDR format.
// Updates the offset pointer to point past the decoded string.
func UnmarshalConformantVaryingString(b []byte, offset *int) (string, error) {
	// Align to 4-byte boundary
	*offset = AlignOffset(*offset, Align4)

	// Check minimum size for header (12 bytes)
	if len(b) < *offset+12 {
		return "", fmt.Errorf("dcerpc: buffer too short for string header")
	}

	// Read MaxCount
	maxCount := binary.LittleEndian.Uint32(b[*offset : *offset+4])
	*offset += 4

	// Read Offset
	stringOffset := binary.LittleEndian.Uint32(b[*offset : *offset+4])
	*offset += 4

	// Read ActualCount
	actualCount := binary.LittleEndian.Uint32(b[*offset : *offset+4])
	*offset += 4

	// Validate counts
	if actualCount > maxCount {
		return "", fmt.Errorf("dcerpc: invalid string: actualCount=%d > maxCount=%d", actualCount, maxCount)
	}

	// Calculate byte size
	byteCount := int(actualCount) * 2

	// Check buffer size
	if len(b) < *offset+byteCount {
		return "", fmt.Errorf("dcerpc: buffer too short for string data")
	}

	// Decode UTF-16LE characters
	utf16Chars := make([]uint16, actualCount)
	for i := 0; i < int(actualCount); i++ {
		utf16Chars[i] = binary.LittleEndian.Uint16(b[*offset+i*2 : *offset+i*2+2])
	}
	*offset += byteCount

	// Skip string offset adjustment (usually 0)
	_ = stringOffset

	// Convert to UTF-8 and remove null terminator
	runes := utf16.Decode(utf16Chars)
	if len(runes) > 0 && runes[len(runes)-1] == 0 {
		runes = runes[:len(runes)-1]
	}

	return string(runes), nil
}

// MarshalPointer encodes an NDR pointer.
// In NDR, pointers are represented as referent IDs (4-byte values).
// A non-zero referent ID indicates a non-null pointer, and is followed by the pointed-to data.
// A zero referent ID indicates a null pointer.
//
// Parameters:
//   - referentID: The referent ID for this pointer (0 for null, non-zero for non-null)
//   - data: The data being pointed to (can be empty for null pointers)
//
// Returns:
//   - The encoded pointer (4-byte referent ID) followed by the data (if non-null)
func MarshalPointer(referentID uint32, data []byte) []byte {
	// Allocate buffer for referent ID
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, referentID)

	// Append data if pointer is non-null
	if referentID != 0 && len(data) > 0 {
		buf = append(buf, data...)
	}

	return buf
}

// UnmarshalPointer decodes an NDR pointer.
// Returns the referent ID and updates the offset.
// If the referent ID is non-zero, the caller should read the pointed-to data.
func UnmarshalPointer(b []byte, offset *int) (uint32, error) {
	// Align to 4-byte boundary
	*offset = AlignOffset(*offset, Align4)

	// Check buffer size
	if len(b) < *offset+4 {
		return 0, fmt.Errorf("dcerpc: buffer too short for pointer")
	}

	// Read referent ID
	referentID := binary.LittleEndian.Uint32(b[*offset : *offset+4])
	*offset += 4

	return referentID, nil
}

// MarshalUniquePointer encodes a unique pointer (non-null or null).
// Unique pointers use referent IDs starting from 0x00020000 by convention.
func MarshalUniquePointer(data []byte) []byte {
	if len(data) == 0 {
		// Null pointer
		return MarshalPointer(0, nil)
	}
	// Non-null pointer with referent ID
	return MarshalPointer(0x00020000, data)
}

// Pad adds padding bytes to align to the specified boundary.
func Pad(buf []byte, alignment int) []byte {
	currentLen := len(buf)
	alignedLen := AlignOffset(currentLen, alignment)
	padding := alignedLen - currentLen
	if padding > 0 {
		buf = append(buf, make([]byte, padding)...)
	}
	return buf
}
