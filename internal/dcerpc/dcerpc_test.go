package dcerpc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestHeader tests header encoding and decoding
func TestHeader(t *testing.T) {
	tests := []struct {
		name   string
		header *Header
	}{
		{
			name: "Bind header",
			header: &Header{
				Version:      5,
				VersionMinor: 0,
				PacketType:   PacketTypeBind,
				Flags:        PFCFirstFrag | PFCLastFrag,
				DataRep:      DataRepresentation,
				FragLength:   100,
				AuthLength:   0,
				CallID:       0,
			},
		},
		{
			name: "Request header",
			header: &Header{
				Version:      5,
				VersionMinor: 0,
				PacketType:   PacketTypeRequest,
				Flags:        PFCFirstFrag | PFCLastFrag,
				DataRep:      DataRepresentation,
				FragLength:   200,
				AuthLength:   0,
				CallID:       1,
			},
		},
		{
			name: "Response header",
			header: &Header{
				Version:      5,
				VersionMinor: 0,
				PacketType:   PacketTypeResponse,
				Flags:        PFCFirstFrag | PFCLastFrag,
				DataRep:      DataRepresentation,
				FragLength:   150,
				AuthLength:   0,
				CallID:       1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := EncodeHeader(tt.header)

			// Verify size
			if len(encoded) != HeaderSize {
				t.Errorf("encoded header size = %d, want %d", len(encoded), HeaderSize)
			}

			// Decode
			decoded, err := DecodeHeader(encoded)
			if err != nil {
				t.Fatalf("DecodeHeader() error = %v", err)
			}

			// Compare fields
			if decoded.Version != tt.header.Version {
				t.Errorf("Version = %d, want %d", decoded.Version, tt.header.Version)
			}
			if decoded.VersionMinor != tt.header.VersionMinor {
				t.Errorf("VersionMinor = %d, want %d", decoded.VersionMinor, tt.header.VersionMinor)
			}
			if decoded.PacketType != tt.header.PacketType {
				t.Errorf("PacketType = %d, want %d", decoded.PacketType, tt.header.PacketType)
			}
			if decoded.Flags != tt.header.Flags {
				t.Errorf("Flags = 0x%02x, want 0x%02x", decoded.Flags, tt.header.Flags)
			}
			if decoded.FragLength != tt.header.FragLength {
				t.Errorf("FragLength = %d, want %d", decoded.FragLength, tt.header.FragLength)
			}
			if decoded.AuthLength != tt.header.AuthLength {
				t.Errorf("AuthLength = %d, want %d", decoded.AuthLength, tt.header.AuthLength)
			}
			if decoded.CallID != tt.header.CallID {
				t.Errorf("CallID = %d, want %d", decoded.CallID, tt.header.CallID)
			}
		})
	}
}

// TestDecodeHeaderErrors tests error cases in header decoding
func TestDecodeHeaderErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "too short",
			data:    make([]byte, 10),
			wantErr: true,
		},
		{
			name: "invalid version",
			data: []byte{
				4, 0, // Version 4.0 (invalid)
				PacketTypeBind, 0x03,
				0x10, 0x00, 0x00, 0x00, // DataRep
				0x00, 0x00, // FragLength
				0x00, 0x00, // AuthLength
				0x00, 0x00, 0x00, 0x00, // CallID
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeHeader(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestEncodeBind tests Bind request encoding
func TestEncodeBind(t *testing.T) {
	// SRVSVC interface UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188
	// In DCE/RPC little-endian format: c84f324b-7016-d301-1278-5a47bf6ee188
	srvsvcUUID := [16]byte{
		0xc8, 0x4f, 0x32, 0x4b, // time_low (little-endian)
		0x70, 0x16, // time_mid (little-endian)
		0xd3, 0x01, // time_hi_and_version (little-endian)
		0x12, 0x78, // clock_seq
		0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88, // node
	}

	// Version 3.0 (major=3, minor=0)
	version := uint32(0x00000003)

	// Encode Bind
	bindPDU := EncodeBind(srvsvcUUID, version)

	// Verify header
	if len(bindPDU) < HeaderSize {
		t.Fatalf("Bind PDU too short: got %d bytes", len(bindPDU))
	}

	header, err := DecodeHeader(bindPDU[:HeaderSize])
	if err != nil {
		t.Fatalf("DecodeHeader() error = %v", err)
	}

	// Verify header fields
	if header.Version != VersionMajor {
		t.Errorf("Version = %d, want %d", header.Version, VersionMajor)
	}
	if header.VersionMinor != VersionMinor {
		t.Errorf("VersionMinor = %d, want %d", header.VersionMinor, VersionMinor)
	}
	if header.PacketType != PacketTypeBind {
		t.Errorf("PacketType = %d, want %d", header.PacketType, PacketTypeBind)
	}
	if header.Flags != (PFCFirstFrag | PFCLastFrag) {
		t.Errorf("Flags = 0x%02x, want 0x%02x", header.Flags, PFCFirstFrag|PFCLastFrag)
	}
	if header.FragLength != uint16(len(bindPDU)) {
		t.Errorf("FragLength = %d, want %d", header.FragLength, len(bindPDU))
	}

	// Verify body contains SRVSVC UUID
	if !bytes.Contains(bindPDU, srvsvcUUID[:]) {
		t.Errorf("Bind PDU does not contain SRVSVC UUID")
	}

	// Verify body contains Transfer Syntax UUID
	if !bytes.Contains(bindPDU, TransferSyntaxUUID[:]) {
		t.Errorf("Bind PDU does not contain Transfer Syntax UUID")
	}

	// Verify MaxXmitFrag and MaxRecvFrag
	maxXmitFrag := uint16(bindPDU[16]) | uint16(bindPDU[17])<<8
	maxRecvFrag := uint16(bindPDU[18]) | uint16(bindPDU[19])<<8
	if maxXmitFrag != MaxXmitFrag {
		t.Errorf("MaxXmitFrag = %d, want %d", maxXmitFrag, MaxXmitFrag)
	}
	if maxRecvFrag != MaxRecvFrag {
		t.Errorf("MaxRecvFrag = %d, want %d", maxRecvFrag, MaxRecvFrag)
	}

	t.Logf("Bind PDU size: %d bytes", len(bindPDU))
	t.Logf("Bind PDU hex:\n%s", hex.Dump(bindPDU))
}

// TestEncodeRequest tests Request encoding
func TestEncodeRequest(t *testing.T) {
	contextID := uint16(0)
	opnum := uint16(15) // NetShareEnumAll
	callID := uint32(1)
	data := []byte{0x01, 0x02, 0x03, 0x04}

	// Encode Request
	requestPDU := EncodeRequest(contextID, opnum, data, callID)

	// Verify header
	if len(requestPDU) < HeaderSize {
		t.Fatalf("Request PDU too short: got %d bytes", len(requestPDU))
	}

	header, err := DecodeHeader(requestPDU[:HeaderSize])
	if err != nil {
		t.Fatalf("DecodeHeader() error = %v", err)
	}

	// Verify header fields
	if header.Version != VersionMajor {
		t.Errorf("Version = %d, want %d", header.Version, VersionMajor)
	}
	if header.PacketType != PacketTypeRequest {
		t.Errorf("PacketType = %d, want %d", header.PacketType, PacketTypeRequest)
	}
	if header.CallID != callID {
		t.Errorf("CallID = %d, want %d", header.CallID, callID)
	}
	if header.FragLength != uint16(len(requestPDU)) {
		t.Errorf("FragLength = %d, want %d", header.FragLength, len(requestPDU))
	}

	// Verify body contains request data
	if !bytes.Contains(requestPDU, data) {
		t.Errorf("Request PDU does not contain request data")
	}

	t.Logf("Request PDU size: %d bytes", len(requestPDU))
	t.Logf("Request PDU hex:\n%s", hex.Dump(requestPDU))
}

// TestDecodeResponse tests Response decoding
func TestDecodeResponse(t *testing.T) {
	// Create a mock Response PDU
	responseData := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	bodySize := 8 + len(responseData)
	totalSize := HeaderSize + bodySize

	pdu := make([]byte, totalSize)

	// Header
	header := &Header{
		Version:      VersionMajor,
		VersionMinor: VersionMinor,
		PacketType:   PacketTypeResponse,
		Flags:        PFCFirstFrag | PFCLastFrag,
		DataRep:      DataRepresentation,
		FragLength:   uint16(totalSize),
		AuthLength:   0,
		CallID:       1,
	}
	copy(pdu[:HeaderSize], EncodeHeader(header))

	// Body: AllocHint (4) + ContextID (2) + CancelCount (1) + Reserved (1) + Data
	offset := HeaderSize
	// AllocHint
	pdu[offset] = 0x00
	pdu[offset+1] = 0x00
	pdu[offset+2] = 0x00
	pdu[offset+3] = 0x00
	offset += 4
	// ContextID
	pdu[offset] = 0x00
	pdu[offset+1] = 0x00
	offset += 2
	// CancelCount + Reserved
	pdu[offset] = 0x00
	pdu[offset+1] = 0x00
	offset += 2
	// Data
	copy(pdu[offset:], responseData)

	// Decode
	decodedData, status, err := DecodeResponse(pdu)
	if err != nil {
		t.Fatalf("DecodeResponse() error = %v", err)
	}

	// Verify
	if status != 0 {
		t.Errorf("status = %d, want 0", status)
	}
	if !bytes.Equal(decodedData, responseData) {
		t.Errorf("decoded data = %v, want %v", decodedData, responseData)
	}
}

// TestDecodeBindAck tests Bind_Ack decoding
func TestDecodeBindAck(t *testing.T) {
	// Create a mock Bind_Ack PDU with proper structure
	// Body structure:
	//   MaxXmitFrag (2) + MaxRecvFrag (2) + AssocGroup (4)
	//   + SecAddrLen (2) + SecAddr (variable) + Padding (align to 4)
	//   + NumResults (1) + Reserved (3)
	//   + Results (24 bytes per result: Result(2) + Reason(2) + TransferSyntax(16) + SyntaxVer(4))

	// Calculate size with empty secondary address
	// Body: MaxXmitFrag (2) + MaxRecvFrag (2) + AssocGroup (4) + SecAddrLen (2) + SecAddr (0) + Padding (2 to align to 4) + NumResults+Reserved (4) + Result (24)
	bodySize := 8 + 2 + 0 + 2 + 4 + 24
	totalSize := HeaderSize + bodySize

	pdu := make([]byte, totalSize)

	// Header
	header := &Header{
		Version:      VersionMajor,
		VersionMinor: VersionMinor,
		PacketType:   PacketTypeBindAck,
		Flags:        PFCFirstFrag | PFCLastFrag,
		DataRep:      DataRepresentation,
		FragLength:   uint16(totalSize),
		AuthLength:   0,
		CallID:       0,
	}
	copy(pdu[:HeaderSize], EncodeHeader(header))

	// Body
	offset := HeaderSize
	// MaxXmitFrag
	binary.LittleEndian.PutUint16(pdu[offset:offset+2], MaxXmitFrag)
	offset += 2
	// MaxRecvFrag
	binary.LittleEndian.PutUint16(pdu[offset:offset+2], MaxRecvFrag)
	offset += 2
	// AssocGroup
	binary.LittleEndian.PutUint32(pdu[offset:offset+4], 0x00000001)
	offset += 4
	// SecAddrLen (0 - empty secondary address)
	binary.LittleEndian.PutUint16(pdu[offset:offset+2], 0)
	offset += 2
	// No SecAddr data since length is 0
	// Add padding to align to 4-byte boundary (offset 26 -> 28)
	offset += 2
	// NumResults (1)
	pdu[offset] = 0x01
	offset++
	// Reserved (3)
	offset += 3
	// Result (acceptance = 0)
	binary.LittleEndian.PutUint16(pdu[offset:offset+2], ResultAcceptance)
	offset += 2
	// Reason
	binary.LittleEndian.PutUint16(pdu[offset:offset+2], 0)
	offset += 2
	// TransferSyntax (16 bytes)
	copy(pdu[offset:offset+16], TransferSyntaxUUID[:])
	offset += 16
	// SyntaxVer
	binary.LittleEndian.PutUint32(pdu[offset:offset+4], TransferSyntaxVersion)

	// Decode
	contextID, err := DecodeBindAck(pdu)
	if err != nil {
		t.Fatalf("DecodeBindAck() error = %v", err)
	}

	// Verify
	if contextID != 0 {
		t.Errorf("contextID = %d, want 0", contextID)
	}
}

// TestParseUUID tests UUID parsing
func TestParseUUID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected [16]byte
		wantErr  bool
	}{
		{
			name:  "SRVSVC UUID",
			input: "4b324fc8-1670-01d3-1278-5a47bf6ee188",
			expected: [16]byte{
				0xc8, 0x4f, 0x32, 0x4b, // time_low (little-endian)
				0x70, 0x16, // time_mid (little-endian)
				0xd3, 0x01, // time_hi_and_version (little-endian)
				0x12, 0x78, // clock_seq (big-endian)
				0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88, // node (big-endian)
			},
			wantErr: false,
		},
		{
			name:     "invalid length",
			input:    "4b324fc8-1670-01d3",
			expected: [16]byte{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseUUID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseUUID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("ParseUUID() = %v, want %v", result, tt.expected)
			}
		})
	}
}
