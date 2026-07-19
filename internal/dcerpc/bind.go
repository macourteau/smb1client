package dcerpc

import (
	"encoding/binary"
	"fmt"
)

// Default fragment sizes for DCE/RPC
const (
	// MaxXmitFrag is the maximum transmit fragment size (4280 bytes)
	MaxXmitFrag = 4280
	// MaxRecvFrag is the maximum receive fragment size (4280 bytes)
	MaxRecvFrag = 4280
)

// BindRequest represents a DCE/RPC Bind PDU body
type BindRequest struct {
	MaxXmitFrag  uint16        // Maximum transmit fragment size
	MaxRecvFrag  uint16        // Maximum receive fragment size
	AssocGroup   uint32        // Association group (0 for new association)
	ContextItems []ContextItem // Context items
}

// ContextItem represents a presentation context in a Bind request
type ContextItem struct {
	ContextID      uint16   // Presentation context ID
	InterfaceUUID  [16]byte // Interface UUID
	InterfaceVer   uint32   // Interface version (major in low word, minor in high word)
	TransferSyntax [16]byte // Transfer syntax UUID
	SyntaxVer      uint32   // Transfer syntax version
}

// BindAck represents a DCE/RPC Bind_Ack PDU body
type BindAck struct {
	MaxXmitFrag uint16          // Maximum transmit fragment size
	MaxRecvFrag uint16          // Maximum receive fragment size
	AssocGroup  uint32          // Association group
	SecAddr     string          // Secondary address
	Results     []ContextResult // Context results
}

// ContextResult represents the result of a presentation context negotiation
type ContextResult struct {
	Result         uint16   // Result code (0=acceptance, 1=user_rejection, 2=provider_rejection)
	Reason         uint16   // Reason code for rejection
	TransferSyntax [16]byte // Transfer syntax UUID
	SyntaxVer      uint32   // Transfer syntax version
}

// Result codes for context negotiation
const (
	ResultAcceptance        = 0 // Context accepted
	ResultUserRejection     = 1 // Context rejected by user
	ResultProviderRejection = 2 // Context rejected by provider
)

// EncodeBind encodes a DCE/RPC Bind request.
// The Bind request includes the interface UUID, version, and transfer syntax.
// By default, it includes two context items:
//  1. The main interface context
//  2. The Microsoft feature negotiation context (optional, for Windows compatibility)
//
// Parameters:
//   - interfaceUUID: The interface UUID in DCE/RPC format
//   - version: The interface version (16-bit major in low word, 16-bit minor in high word)
//
// Returns the encoded Bind PDU as a byte slice.
func EncodeBind(interfaceUUID [16]byte, version uint32) []byte {
	// Create context items
	contextItems := []ContextItem{
		{
			ContextID:      0, // Main context
			InterfaceUUID:  interfaceUUID,
			InterfaceVer:   version,
			TransferSyntax: TransferSyntaxUUID,
			SyntaxVer:      TransferSyntaxVersion,
		},
		{
			ContextID:      1,                                                                                                        // Feature negotiation context (for Windows compatibility)
			InterfaceUUID:  interfaceUUID,                                                                                            // Same interface as context 0
			InterfaceVer:   version,                                                                                                  // Same version as context 0
			TransferSyntax: [16]byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Bind Time Feature Negotiation UUID
			SyntaxVer:      0x00000001,                                                                                               // Version 1.0
		},
	}

	// Calculate body size
	// Bind body structure:
	//   MaxXmitFrag (2 bytes)
	//   MaxRecvFrag (2 bytes)
	//   AssocGroup (4 bytes)
	//   NumContextItems (1 byte)
	//   Reserved (1 byte)
	//   Reserved2 (2 bytes)
	//   ContextItems (variable, 44 bytes each)
	//
	// Each ContextItem:
	//   ContextID (2 bytes)
	//   NumTransferSyntax (1 byte)
	//   Reserved (1 byte)
	//   InterfaceUUID (16 bytes)
	//   InterfaceVer (4 bytes)
	//   TransferSyntax (16 bytes)
	//   SyntaxVer (4 bytes)
	//
	bodySize := 12 + len(contextItems)*44
	totalSize := HeaderSize + bodySize

	buf := make([]byte, totalSize)

	// Encode header
	header := &Header{
		Version:      VersionMajor,
		VersionMinor: VersionMinor,
		PacketType:   PacketTypeBind,
		Flags:        PFCFirstFrag | PFCLastFrag,
		DataRep:      DataRepresentation,
		FragLength:   uint16(totalSize),
		AuthLength:   0,
		CallID:       0,
	}
	copy(buf[0:HeaderSize], EncodeHeader(header))

	// Encode body
	offset := HeaderSize

	// MaxXmitFrag
	binary.LittleEndian.PutUint16(buf[offset:offset+2], MaxXmitFrag)
	offset += 2

	// MaxRecvFrag
	binary.LittleEndian.PutUint16(buf[offset:offset+2], MaxRecvFrag)
	offset += 2

	// AssocGroup
	binary.LittleEndian.PutUint32(buf[offset:offset+4], 0)
	offset += 4

	// NumContextItems
	buf[offset] = uint8(len(contextItems))
	offset++

	// Reserved (3 bytes)
	offset += 3

	// Encode context items
	for _, item := range contextItems {
		// ContextID
		binary.LittleEndian.PutUint16(buf[offset:offset+2], item.ContextID)
		offset += 2

		// NumTransferSyntax (always 1)
		buf[offset] = 1
		offset++

		// Reserved
		offset++

		// InterfaceUUID
		copy(buf[offset:offset+16], item.InterfaceUUID[:])
		offset += 16

		// InterfaceVer
		binary.LittleEndian.PutUint32(buf[offset:offset+4], item.InterfaceVer)
		offset += 4

		// TransferSyntax
		copy(buf[offset:offset+16], item.TransferSyntax[:])
		offset += 16

		// SyntaxVer
		binary.LittleEndian.PutUint32(buf[offset:offset+4], item.SyntaxVer)
		offset += 4
	}

	return buf
}

// DecodeBindAck decodes a DCE/RPC Bind_Ack response.
// Returns the context ID that was accepted and any error.
//
// The function validates:
//   - Header is valid and packet type is Bind_Ack
//   - At least one context result is present
//   - The first context result indicates acceptance
func DecodeBindAck(data []byte) (contextID uint16, err error) {
	// Decode header
	header, err := DecodeHeader(data)
	if err != nil {
		return 0, fmt.Errorf("dcerpc: failed to decode Bind_Ack header: %w", err)
	}

	if header.PacketType != PacketTypeBindAck {
		return 0, fmt.Errorf("dcerpc: expected Bind_Ack packet type %d, got %d", PacketTypeBindAck, header.PacketType)
	}

	// Validate minimum body size
	// Bind_Ack body minimum:
	//   MaxXmitFrag (2)
	//   MaxRecvFrag (2)
	//   AssocGroup (4)
	//   SecAddrLen (2)
	//   SecAddr (variable, minimum 0)
	//   Pad (variable, align to 4 bytes)
	//   NumResults (1)
	//   Reserved (1)
	//   Reserved2 (2)
	//   Results (variable, minimum 24 bytes per result)
	//
	minBodySize := 14 // Up to SecAddrLen
	if len(data) < HeaderSize+minBodySize {
		return 0, fmt.Errorf("dcerpc: Bind_Ack body too short: got %d bytes, need at least %d", len(data)-HeaderSize, minBodySize)
	}

	offset := HeaderSize

	// Skip MaxXmitFrag, MaxRecvFrag, AssocGroup
	offset += 8

	// Read SecAddrLen
	secAddrLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Skip secondary address and padding
	// Secondary address is null-terminated, followed by padding to 4-byte boundary
	offset += int(secAddrLen)

	// Align to 4-byte boundary
	if offset%4 != 0 {
		offset += 4 - (offset % 4)
	}

	// Check we have enough data for NumResults
	if len(data) < offset+4 {
		return 0, fmt.Errorf("dcerpc: Bind_Ack truncated: missing NumResults field")
	}

	// Read NumResults
	numResults := data[offset]
	offset += 4 // Skip NumResults (1) + Reserved (3)

	if numResults == 0 {
		return 0, fmt.Errorf("dcerpc: Bind_Ack contains no context results")
	}

	// Check we have enough data for at least one result
	// Each result is 24 bytes: Result (2) + Reason (2) + TransferSyntax (16) + SyntaxVer (4)
	if len(data) < offset+24 {
		return 0, fmt.Errorf("dcerpc: Bind_Ack truncated: missing context results")
	}

	// Read first result
	result := binary.LittleEndian.Uint16(data[offset : offset+2])
	reason := binary.LittleEndian.Uint16(data[offset+2 : offset+4])

	if result != ResultAcceptance {
		return 0, fmt.Errorf("dcerpc: Bind rejected: result=%d, reason=%d", result, reason)
	}

	// Return context ID 0 (the main context)
	return 0, nil
}
