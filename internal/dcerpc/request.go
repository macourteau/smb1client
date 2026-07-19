package dcerpc

import (
	"encoding/binary"
	"fmt"
)

// Request represents a DCE/RPC Request PDU
type Request struct {
	AllocHint uint32 // Allocation hint for the response
	ContextID uint16 // Presentation context ID
	Opnum     uint16 // Operation number
	Data      []byte // Request data (stub data)
}

// Response represents a DCE/RPC Response PDU
type Response struct {
	AllocHint   uint32 // Allocation hint
	ContextID   uint16 // Presentation context ID
	CancelCount uint8  // Cancel count
	Reserved    uint8  // Reserved
	Data        []byte // Response data (stub data)
}

// EncodeRequest encodes a DCE/RPC Request PDU.
// The Request PDU includes the context ID, operation number, and request data.
//
// Parameters:
//   - contextID: The presentation context ID from the Bind
//   - opnum: The operation number to invoke
//   - data: The request stub data (NDR-encoded parameters)
//   - callID: The call identifier for matching with responses
//
// Returns the encoded Request PDU as a byte slice.
func EncodeRequest(contextID uint16, opnum uint16, data []byte, callID uint32) []byte {
	// Request body structure:
	//   AllocHint (4 bytes)
	//   ContextID (2 bytes)
	//   Opnum (2 bytes)
	//   Data (variable)
	//
	bodySize := 8 + len(data)
	totalSize := HeaderSize + bodySize

	buf := make([]byte, totalSize)

	// Encode header
	header := &Header{
		Version:      VersionMajor,
		VersionMinor: VersionMinor,
		PacketType:   PacketTypeRequest,
		Flags:        PFCFirstFrag | PFCLastFrag,
		DataRep:      DataRepresentation,
		FragLength:   uint16(totalSize),
		AuthLength:   0,
		CallID:       callID,
	}
	copy(buf[0:HeaderSize], EncodeHeader(header))

	// Encode body
	offset := HeaderSize

	// AllocHint (hint for response buffer size)
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(len(data)))
	offset += 4

	// ContextID
	binary.LittleEndian.PutUint16(buf[offset:offset+2], contextID)
	offset += 2

	// Opnum
	binary.LittleEndian.PutUint16(buf[offset:offset+2], opnum)
	offset += 2

	// Data
	if len(data) > 0 {
		copy(buf[offset:offset+len(data)], data)
	}

	return buf
}

// DecodeResponse decodes a DCE/RPC Response PDU.
// Returns the response data (stub data) and the status code.
//
// The function validates:
//   - Header is valid and packet type is Response
//   - Response body is complete
func DecodeResponse(data []byte) (responseData []byte, status uint32, err error) {
	// Decode header
	header, err := DecodeHeader(data)
	if err != nil {
		return nil, 0, fmt.Errorf("dcerpc: failed to decode Response header: %w", err)
	}

	if header.PacketType != PacketTypeResponse {
		return nil, 0, fmt.Errorf("dcerpc: expected Response packet type %d, got %d", PacketTypeResponse, header.PacketType)
	}

	// Validate minimum body size
	// Response body minimum:
	//   AllocHint (4)
	//   ContextID (2)
	//   CancelCount (1)
	//   Reserved (1)
	//   Data (variable, minimum 0)
	//
	minBodySize := 8
	if len(data) < HeaderSize+minBodySize {
		return nil, 0, fmt.Errorf("dcerpc: Response body too short: got %d bytes, need at least %d", len(data)-HeaderSize, minBodySize)
	}

	offset := HeaderSize

	// Skip AllocHint
	offset += 4

	// Read ContextID (for validation, not returned)
	// contextID := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Read CancelCount and Reserved
	// cancelCount := data[offset]
	offset += 2

	// Extract response data
	responseData = make([]byte, len(data)-offset)
	copy(responseData, data[offset:])

	// For SRVSVC, the status code is typically encoded at the end of the response data
	// as a 32-bit integer. However, this is application-specific.
	// For a generic DCE/RPC implementation, we return 0 for status and let the caller
	// parse the response data according to their interface definition.
	status = 0

	return responseData, status, nil
}

// DecodeFault decodes a DCE/RPC Fault PDU.
// Fault PDUs are returned when an error occurs during RPC processing.
//
// Returns the fault status code and any error.
func DecodeFault(data []byte) (status uint32, err error) {
	// Decode header
	header, err := DecodeHeader(data)
	if err != nil {
		return 0, fmt.Errorf("dcerpc: failed to decode Fault header: %w", err)
	}

	// Packet type 3 is Fault
	if header.PacketType != 3 {
		return 0, fmt.Errorf("dcerpc: expected Fault packet type 3, got %d", header.PacketType)
	}

	// Fault body structure:
	//   AllocHint (4 bytes)
	//   ContextID (2 bytes)
	//   CancelCount (1 byte)
	//   Reserved (1 byte)
	//   Status (4 bytes)
	//   Reserved2 (4 bytes)
	//
	minBodySize := 16
	if len(data) < HeaderSize+minBodySize {
		return 0, fmt.Errorf("dcerpc: Fault body too short: got %d bytes, need at least %d", len(data)-HeaderSize, minBodySize)
	}

	offset := HeaderSize + 8 // Skip to Status field

	// Read Status
	status = binary.LittleEndian.Uint32(data[offset : offset+4])

	return status, nil
}
