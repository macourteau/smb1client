package smb1

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestHeaderEncodeDecode tests header encoding and decoding
func TestHeaderEncodeDecode(t *testing.T) {
	tests := []struct {
		name   string
		header *Header
	}{
		{
			name: "negotiate command",
			header: &Header{
				Protocol:         [4]byte{0xFF, 'S', 'M', 'B'},
				Command:          SMB_COM_NEGOTIATE,
				Status:           STATUS_SUCCESS,
				Flags:            SMB_FLAGS_CASE_INSENSITIVE,
				Flags2:           SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
				PIDHigh:          0,
				SecurityFeatures: [8]byte{},
				Reserved:         0,
				TID:              0,
				PIDLow:           0xFFFE,
				UID:              0,
				MID:              1,
			},
		},
		{
			name: "session setup command",
			header: &Header{
				Protocol:         [4]byte{0xFF, 'S', 'M', 'B'},
				Command:          SMB_COM_SESSION_SETUP_ANDX,
				Status:           STATUS_MORE_PROCESSING_REQUIRED,
				Flags:            SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS,
				Flags2:           SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE | SMB_FLAGS2_EXTENDED_SECURITY,
				PIDHigh:          0,
				SecurityFeatures: [8]byte{},
				Reserved:         0,
				TID:              0,
				PIDLow:           0xFFFE,
				UID:              100,
				MID:              2,
			},
		},
		{
			name: "tree connect command",
			header: &Header{
				Protocol:         [4]byte{0xFF, 'S', 'M', 'B'},
				Command:          SMB_COM_TREE_CONNECT_ANDX,
				Status:           STATUS_SUCCESS,
				Flags:            SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS,
				Flags2:           SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
				PIDHigh:          0,
				SecurityFeatures: [8]byte{},
				Reserved:         0,
				TID:              2048,
				PIDLow:           0xFFFE,
				UID:              100,
				MID:              3,
			},
		},
		{
			name: "read command with signature",
			header: &Header{
				Protocol:         [4]byte{0xFF, 'S', 'M', 'B'},
				Command:          SMB_COM_READ_ANDX,
				Status:           STATUS_SUCCESS,
				Flags:            SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS,
				Flags2:           SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
				PIDHigh:          0,
				SecurityFeatures: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Reserved:         0,
				TID:              2048,
				PIDLow:           0xFFFE,
				UID:              100,
				MID:              10,
			},
		},
		{
			name: "error response",
			header: &Header{
				Protocol:         [4]byte{0xFF, 'S', 'M', 'B'},
				Command:          SMB_COM_OPEN_ANDX,
				Status:           STATUS_ACCESS_DENIED,
				Flags:            SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS | SMB_FLAGS_REPLY,
				Flags2:           SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
				PIDHigh:          0,
				SecurityFeatures: [8]byte{},
				Reserved:         0,
				TID:              2048,
				PIDLow:           0xFFFE,
				UID:              100,
				MID:              15,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := tt.header.Encode()
			if len(encoded) != HeaderSize {
				t.Fatalf("encoded header size = %d, want %d", len(encoded), HeaderSize)
			}

			// Decode
			decoded, err := DecodeHeader(encoded)
			if err != nil {
				t.Fatalf("DecodeHeader() error = %v", err)
			}

			// Compare all fields
			if decoded.Command != tt.header.Command {
				t.Errorf("Command = 0x%02X, want 0x%02X", decoded.Command, tt.header.Command)
			}
			if decoded.Status != tt.header.Status {
				t.Errorf("Status = 0x%08X, want 0x%08X", decoded.Status, tt.header.Status)
			}
			if decoded.Flags != tt.header.Flags {
				t.Errorf("Flags = 0x%02X, want 0x%02X", decoded.Flags, tt.header.Flags)
			}
			if decoded.Flags2 != tt.header.Flags2 {
				t.Errorf("Flags2 = 0x%04X, want 0x%04X", decoded.Flags2, tt.header.Flags2)
			}
			if decoded.PIDHigh != tt.header.PIDHigh {
				t.Errorf("PIDHigh = %d, want %d", decoded.PIDHigh, tt.header.PIDHigh)
			}
			if decoded.SecurityFeatures != tt.header.SecurityFeatures {
				t.Errorf("SecurityFeatures = %v, want %v", decoded.SecurityFeatures, tt.header.SecurityFeatures)
			}
			if decoded.TID != tt.header.TID {
				t.Errorf("TID = %d, want %d", decoded.TID, tt.header.TID)
			}
			if decoded.PIDLow != tt.header.PIDLow {
				t.Errorf("PIDLow = %d, want %d", decoded.PIDLow, tt.header.PIDLow)
			}
			if decoded.UID != tt.header.UID {
				t.Errorf("UID = %d, want %d", decoded.UID, tt.header.UID)
			}
			if decoded.MID != tt.header.MID {
				t.Errorf("MID = %d, want %d", decoded.MID, tt.header.MID)
			}
		})
	}
}

// TestNewHeader tests the NewHeader constructor
func TestNewHeader(t *testing.T) {
	header := NewHeader(SMB_COM_NEGOTIATE)

	if string(header.Protocol[:]) != ProtocolSMB1 {
		t.Errorf("Protocol = %v, want %v", header.Protocol, []byte(ProtocolSMB1))
	}
	if header.Command != SMB_COM_NEGOTIATE {
		t.Errorf("Command = 0x%02X, want 0x%02X", header.Command, SMB_COM_NEGOTIATE)
	}
	if header.Status != STATUS_SUCCESS {
		t.Errorf("Status = 0x%08X, want 0x%08X", header.Status, STATUS_SUCCESS)
	}
	if header.Flags == 0 {
		t.Error("Flags should have default values, got 0")
	}
	if header.Flags2 == 0 {
		t.Error("Flags2 should have default values, got 0")
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
			data:    make([]byte, 20),
			wantErr: true,
		},
		{
			name:    "invalid protocol signature",
			data:    bytes.Repeat([]byte{0x00}, HeaderSize),
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte{},
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

// TestHeaderMethods tests header helper methods
func TestHeaderMethods(t *testing.T) {
	t.Run("IsResponse", func(t *testing.T) {
		header := NewHeader(SMB_COM_NEGOTIATE)
		if header.IsResponse() {
			t.Error("IsResponse() = true for request, want false")
		}

		header.Flags |= SMB_FLAGS_REPLY
		if !header.IsResponse() {
			t.Error("IsResponse() = false for response, want true")
		}
	})

	t.Run("IsError", func(t *testing.T) {
		header := NewHeader(SMB_COM_NEGOTIATE)
		if header.IsError() {
			t.Error("IsError() = true for success, want false")
		}

		header.Status = STATUS_ACCESS_DENIED
		if !header.IsError() {
			t.Error("IsError() = false for error status, want true")
		}
	})

	t.Run("Error", func(t *testing.T) {
		header := NewHeader(SMB_COM_NEGOTIATE)
		if err := header.Error(); err != nil {
			t.Errorf("Error() = %v for success status, want nil", err)
		}

		header.Status = STATUS_ACCESS_DENIED
		if err := header.Error(); err == nil {
			t.Error("Error() = nil for error status, want error")
		}
	})

	t.Run("String", func(t *testing.T) {
		header := NewHeader(SMB_COM_NEGOTIATE)
		s := header.String()
		if len(s) == 0 {
			t.Error("String() returned empty string")
		}
	})
}

// TestAndXHeaderEncodeDecode tests AndX header encoding and decoding
func TestAndXHeaderEncodeDecode(t *testing.T) {
	tests := []struct {
		name   string
		header *AndXHeader
	}{
		{
			name: "no chaining",
			header: &AndXHeader{
				AndXCommand:  SMB_COM_NO_ANDX_COMMAND,
				AndXReserved: 0,
				AndXOffset:   0,
			},
		},
		{
			name: "with chaining",
			header: &AndXHeader{
				AndXCommand:  SMB_COM_TREE_CONNECT_ANDX,
				AndXReserved: 0,
				AndXOffset:   128,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := tt.header.Encode()
			if len(encoded) != 4 {
				t.Fatalf("encoded AndX header size = %d, want 4", len(encoded))
			}

			// Decode
			decoded, err := DecodeAndXHeader(encoded)
			if err != nil {
				t.Fatalf("DecodeAndXHeader() error = %v", err)
			}

			// Compare
			if decoded.AndXCommand != tt.header.AndXCommand {
				t.Errorf("AndXCommand = 0x%02X, want 0x%02X", decoded.AndXCommand, tt.header.AndXCommand)
			}
			if decoded.AndXReserved != tt.header.AndXReserved {
				t.Errorf("AndXReserved = %d, want %d", decoded.AndXReserved, tt.header.AndXReserved)
			}
			if decoded.AndXOffset != tt.header.AndXOffset {
				t.Errorf("AndXOffset = %d, want %d", decoded.AndXOffset, tt.header.AndXOffset)
			}
		})
	}
}

// TestNewAndXHeader tests the NewAndXHeader constructor
func TestNewAndXHeader(t *testing.T) {
	header := NewAndXHeader()
	if header.AndXCommand != SMB_COM_NO_ANDX_COMMAND {
		t.Errorf("AndXCommand = 0x%02X, want 0x%02X", header.AndXCommand, SMB_COM_NO_ANDX_COMMAND)
	}
	if header.HasChaining() {
		t.Error("HasChaining() = true for new header, want false")
	}
}

// TestPacketEncodeDecode tests full packet encoding and decoding
func TestPacketEncodeDecode(t *testing.T) {
	tests := []struct {
		name       string
		header     *Header
		params     []byte
		data       []byte
		wantParams []byte
		wantData   []byte
	}{
		{
			name:   "empty packet",
			header: NewHeader(SMB_COM_ECHO),
			params: []byte{},
			data:   []byte{},
		},
		{
			name:   "params only",
			header: NewHeader(SMB_COM_NEGOTIATE),
			params: []byte{0x01, 0x00, 0x02, 0x00},
			data:   []byte{},
		},
		{
			name:   "data only",
			header: NewHeader(SMB_COM_WRITE_ANDX),
			params: []byte{},
			data:   []byte("Hello, SMB!"),
		},
		{
			name:   "params and data",
			header: NewHeader(SMB_COM_TRANSACTION2),
			params: []byte{0x01, 0x00, 0x02, 0x00, 0x03, 0x00},
			data:   []byte("Transaction data"),
		},
		{
			name:   "large data",
			header: NewHeader(SMB_COM_WRITE_ANDX),
			params: []byte{0x00, 0x00},
			data:   bytes.Repeat([]byte("X"), 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded, err := EncodePacket(tt.header, tt.params, tt.data)
			if err != nil {
				t.Fatalf("EncodePacket() error = %v", err)
			}

			// Verify minimum size
			minSize := HeaderSize + 1 + len(tt.params) + 2 + len(tt.data)
			if len(encoded) != minSize {
				t.Fatalf("encoded size = %d, want %d", len(encoded), minSize)
			}

			// Decode
			decodedHeader, decodedParams, decodedData, err := DecodePacket(encoded)
			if err != nil {
				t.Fatalf("DecodePacket() error = %v", err)
			}

			// Compare header
			if decodedHeader.Command != tt.header.Command {
				t.Errorf("Command = 0x%02X, want 0x%02X", decodedHeader.Command, tt.header.Command)
			}

			// Compare params
			if !bytes.Equal(decodedParams, tt.params) {
				t.Errorf("params = %v, want %v", decodedParams, tt.params)
			}

			// Compare data
			if !bytes.Equal(decodedData, tt.data) {
				t.Errorf("data = %v, want %v", decodedData, tt.data)
			}
		})
	}
}

// TestEncodePacketErrors tests error cases in packet encoding
func TestEncodePacketErrors(t *testing.T) {
	tests := []struct {
		name    string
		header  *Header
		params  []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "nil header",
			header:  nil,
			params:  []byte{},
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "odd params size",
			header:  NewHeader(SMB_COM_NEGOTIATE),
			params:  []byte{0x01, 0x02, 0x03},
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "params too large",
			header:  NewHeader(SMB_COM_NEGOTIATE),
			params:  bytes.Repeat([]byte{0x00, 0x00}, MaxParametersSize/2+1),
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "data too large",
			header:  NewHeader(SMB_COM_WRITE_ANDX),
			params:  []byte{},
			data:    bytes.Repeat([]byte{0x00}, MaxDataSize+1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodePacket(tt.header, tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePacket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDecodePacketErrors tests error cases in packet decoding
func TestDecodePacketErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "too short",
			data:    make([]byte, 20),
			wantErr: true,
		},
		{
			name:    "truncated params",
			data:    append(NewHeader(SMB_COM_NEGOTIATE).Encode(), 10), // WordCount=10 but no params
			wantErr: true,
		},
		{
			name: "truncated data",
			data: func() []byte {
				buf := NewHeader(SMB_COM_WRITE_ANDX).Encode()
				buf = append(buf, 0)                     // WordCount=0
				buf = append(buf, []byte{0xFF, 0xFF}...) // ByteCount=65535 but no data
				return buf
			}(),
			wantErr: true,
		},
		{
			name:    "invalid protocol",
			data:    bytes.Repeat([]byte{0x00}, 100),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := DecodePacket(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodePacket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestEncodeParameters tests parameter encoding helper
func TestEncodeParameters(t *testing.T) {
	tests := []struct {
		name    string
		values  []interface{}
		want    []byte
		wantErr bool
	}{
		{
			name:   "empty",
			values: []interface{}{},
			want:   []byte{},
		},
		{
			name:   "uint8",
			values: []interface{}{uint8(0x12)},
			want:   []byte{0x12, 0x00}, // Padded to even
		},
		{
			name:   "uint16",
			values: []interface{}{uint16(0x1234)},
			want:   []byte{0x34, 0x12}, // Little-endian
		},
		{
			name:   "uint32",
			values: []interface{}{uint32(0x12345678)},
			want:   []byte{0x78, 0x56, 0x34, 0x12}, // Little-endian
		},
		{
			name:   "uint64",
			values: []interface{}{uint64(0x123456789ABCDEF0)},
			want:   []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12}, // Little-endian
		},
		{
			name:   "bytes",
			values: []interface{}{[]byte{0xAA, 0xBB}},
			want:   []byte{0xAA, 0xBB},
		},
		{
			name:   "mixed types",
			values: []interface{}{uint8(0x01), uint16(0x0203), []byte{0x04, 0x05}},
			want:   []byte{0x01, 0x03, 0x02, 0x04, 0x05, 0x00}, // Padded to even
		},
		{
			name:    "unsupported type",
			values:  []interface{}{"string"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeParameters(tt.values...)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeParameters() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDecodeHelpers tests decode helper functions
func TestDecodeHelpers(t *testing.T) {
	buf := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}

	t.Run("DecodeUint8", func(t *testing.T) {
		v, err := DecodeUint8(buf, 0)
		if err != nil {
			t.Fatalf("DecodeUint8() error = %v", err)
		}
		if v != 0x12 {
			t.Errorf("DecodeUint8() = 0x%02X, want 0x12", v)
		}

		_, err = DecodeUint8(buf, 100)
		if err == nil {
			t.Error("DecodeUint8() with invalid offset should return error")
		}
	})

	t.Run("DecodeUint16", func(t *testing.T) {
		v, err := DecodeUint16(buf, 0)
		if err != nil {
			t.Fatalf("DecodeUint16() error = %v", err)
		}
		if v != 0x3412 { // Little-endian
			t.Errorf("DecodeUint16() = 0x%04X, want 0x3412", v)
		}

		_, err = DecodeUint16(buf, 100)
		if err == nil {
			t.Error("DecodeUint16() with invalid offset should return error")
		}
	})

	t.Run("DecodeUint32", func(t *testing.T) {
		v, err := DecodeUint32(buf, 0)
		if err != nil {
			t.Fatalf("DecodeUint32() error = %v", err)
		}
		if v != 0x78563412 { // Little-endian
			t.Errorf("DecodeUint32() = 0x%08X, want 0x78563412", v)
		}

		_, err = DecodeUint32(buf, 100)
		if err == nil {
			t.Error("DecodeUint32() with invalid offset should return error")
		}
	})

	t.Run("DecodeUint64", func(t *testing.T) {
		v, err := DecodeUint64(buf, 0)
		if err != nil {
			t.Fatalf("DecodeUint64() error = %v", err)
		}
		if v != 0xF0DEBC9A78563412 { // Little-endian
			t.Errorf("DecodeUint64() = 0x%016X, want 0xF0DEBC9A78563412", v)
		}

		_, err = DecodeUint64(buf, 100)
		if err == nil {
			t.Error("DecodeUint64() with invalid offset should return error")
		}
	})

	t.Run("DecodeBytes", func(t *testing.T) {
		v, err := DecodeBytes(buf, 0, 4)
		if err != nil {
			t.Fatalf("DecodeBytes() error = %v", err)
		}
		if !bytes.Equal(v, []byte{0x12, 0x34, 0x56, 0x78}) {
			t.Errorf("DecodeBytes() = %v, want [0x12 0x34 0x56 0x78]", v)
		}

		_, err = DecodeBytes(buf, 0, 100)
		if err == nil {
			t.Error("DecodeBytes() with invalid length should return error")
		}
	})
}

// TestMustEncodePacket tests the panic behavior
func TestMustEncodePacket(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("MustEncodePacket() panicked: %v", r)
			}
		}()
		header := NewHeader(SMB_COM_ECHO)
		_ = MustEncodePacket(header, []byte{}, []byte{})
	})

	t.Run("panic on error", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("MustEncodePacket() should panic with invalid params")
			}
		}()
		header := NewHeader(SMB_COM_ECHO)
		_ = MustEncodePacket(header, []byte{0x01, 0x02, 0x03}, []byte{}) // Odd size
	})
}

// TestPacketWithKnownBinary tests encoding/decoding with known binary data
// This tests against real SMB1 packet structures from protocol documentation
func TestPacketWithKnownBinary(t *testing.T) {
	// Example: SMB_COM_NEGOTIATE request with no params and dialect strings in data
	t.Run("negotiate request", func(t *testing.T) {
		header := NewHeader(SMB_COM_NEGOTIATE)
		header.MID = 1
		header.PIDLow = 0xFFFE

		// No parameters for negotiate
		params := []byte{}

		// Data contains dialect strings (simplified example)
		data := []byte{
			0x02,                                                   // BufferFormat (0x02 = dialect string)
			'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00, // "NT LM 0.12" + null
		}

		encoded, err := EncodePacket(header, params, data)
		if err != nil {
			t.Fatalf("EncodePacket() error = %v", err)
		}

		// Verify structure
		if len(encoded) < HeaderSize+1+2 {
			t.Fatalf("packet too short: %d bytes", len(encoded))
		}

		// Verify WordCount is 0 (no params)
		wordCount := encoded[HeaderSize]
		if wordCount != 0 {
			t.Errorf("WordCount = %d, want 0", wordCount)
		}

		// Verify ByteCount
		byteCountOffset := HeaderSize + 1
		byteCount := binary.LittleEndian.Uint16(encoded[byteCountOffset : byteCountOffset+2])
		if byteCount != uint16(len(data)) {
			t.Errorf("ByteCount = %d, want %d", byteCount, len(data))
		}

		// Decode and verify
		decodedHeader, decodedParams, decodedData, err := DecodePacket(encoded)
		if err != nil {
			t.Fatalf("DecodePacket() error = %v", err)
		}

		if decodedHeader.Command != SMB_COM_NEGOTIATE {
			t.Errorf("Command = 0x%02X, want 0x%02X", decodedHeader.Command, SMB_COM_NEGOTIATE)
		}
		if len(decodedParams) != 0 {
			t.Errorf("params length = %d, want 0", len(decodedParams))
		}
		if !bytes.Equal(decodedData, data) {
			t.Errorf("data mismatch: got %v, want %v", decodedData, data)
		}
	})
}

// TestAndXChaining tests AndX command chaining
func TestAndXChaining(t *testing.T) {
	// Create a SESSION_SETUP_ANDX that chains to TREE_CONNECT_ANDX
	sessionSetupHeader := NewHeader(SMB_COM_SESSION_SETUP_ANDX)
	sessionSetupHeader.MID = 1

	// AndX parameters for session setup (simplified)
	andx := NewAndXHeader()
	andx.AndXCommand = SMB_COM_TREE_CONNECT_ANDX
	andx.AndXOffset = 100 // Offset to next command (example)

	sessionSetupParams := andx.Encode()
	sessionSetupParams = append(sessionSetupParams, []byte{0x00, 0x00}...) // Additional params

	sessionSetupData := []byte("session setup data")

	// Encode first packet
	encoded, err := EncodePacket(sessionSetupHeader, sessionSetupParams, sessionSetupData)
	if err != nil {
		t.Fatalf("EncodePacket() error = %v", err)
	}

	// Decode and verify AndX header
	_, decodedParams, _, err := DecodePacket(encoded)
	if err != nil {
		t.Fatalf("DecodePacket() error = %v", err)
	}

	decodedAndX, err := DecodeAndXHeader(decodedParams)
	if err != nil {
		t.Fatalf("DecodeAndXHeader() error = %v", err)
	}

	if !decodedAndX.HasChaining() {
		t.Error("AndX header should indicate chaining")
	}
	if decodedAndX.AndXCommand != SMB_COM_TREE_CONNECT_ANDX {
		t.Errorf("AndXCommand = 0x%02X, want 0x%02X", decodedAndX.AndXCommand, SMB_COM_TREE_CONNECT_ANDX)
	}
}

// TestMaxSizes tests encoding at maximum sizes
func TestMaxSizes(t *testing.T) {
	t.Run("max params", func(t *testing.T) {
		header := NewHeader(SMB_COM_TRANSACTION2)
		params := bytes.Repeat([]byte{0x00, 0x00}, MaxParametersSize/2)
		data := []byte{}

		encoded, err := EncodePacket(header, params, data)
		if err != nil {
			t.Fatalf("EncodePacket() error = %v", err)
		}

		_, decodedParams, _, err := DecodePacket(encoded)
		if err != nil {
			t.Fatalf("DecodePacket() error = %v", err)
		}

		if len(decodedParams) != len(params) {
			t.Errorf("params length = %d, want %d", len(decodedParams), len(params))
		}
	})

	t.Run("max data", func(t *testing.T) {
		header := NewHeader(SMB_COM_WRITE_ANDX)
		params := []byte{}
		data := bytes.Repeat([]byte{0xAA}, MaxDataSize)

		encoded, err := EncodePacket(header, params, data)
		if err != nil {
			t.Fatalf("EncodePacket() error = %v", err)
		}

		_, _, decodedData, err := DecodePacket(encoded)
		if err != nil {
			t.Fatalf("DecodePacket() error = %v", err)
		}

		if len(decodedData) != len(data) {
			t.Errorf("data length = %d, want %d", len(decodedData), len(data))
		}
	})
}
