package smb1

import (
	"testing"
)

// BenchmarkEncodeHeader benchmarks SMB1 header encoding.
func BenchmarkEncodeHeader(b *testing.B) {
	tests := []struct {
		name   string
		header *Header
	}{
		{
			name: "negotiate_command",
			header: &Header{
				Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
				Command:  SMB_COM_NEGOTIATE,
				Status:   STATUS_SUCCESS,
				Flags:    SMB_FLAGS_CASE_INSENSITIVE,
				Flags2:   SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
				PIDLow:   0xFFFE,
				UID:      0,
				MID:      1,
			},
		},
		{
			name: "session_setup_command",
			header: &Header{
				Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
				Command:  SMB_COM_SESSION_SETUP_ANDX,
				Status:   STATUS_MORE_PROCESSING_REQUIRED,
				Flags:    SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS,
				Flags2:   SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE | SMB_FLAGS2_EXTENDED_SECURITY,
				PIDLow:   0xFFFE,
				UID:      100,
				MID:      2,
			},
		},
		{
			name: "read_command_with_signature",
			header: &Header{
				Protocol:         [4]byte{0xFF, 'S', 'M', 'B'},
				Command:          SMB_COM_READ_ANDX,
				Status:           STATUS_SUCCESS,
				Flags:            SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS,
				Flags2:           SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
				SecurityFeatures: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				TID:              2048,
				PIDLow:           0xFFFE,
				UID:              100,
				MID:              10,
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = tt.header.Encode()
			}
		})
	}
}

// BenchmarkDecodeHeader benchmarks SMB1 header decoding.
func BenchmarkDecodeHeader(b *testing.B) {
	tests := []struct {
		name   string
		header *Header
	}{
		{
			name: "negotiate_response",
			header: &Header{
				Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
				Command:  SMB_COM_NEGOTIATE,
				Status:   STATUS_SUCCESS,
				Flags:    SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_REPLY,
				Flags2:   SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
				PIDLow:   0xFFFE,
				UID:      0,
				MID:      1,
			},
		},
		{
			name: "read_response",
			header: &Header{
				Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
				Command:  SMB_COM_READ_ANDX,
				Status:   STATUS_SUCCESS,
				Flags:    SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS | SMB_FLAGS_REPLY,
				Flags2:   SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
				TID:      2048,
				PIDLow:   0xFFFE,
				UID:      100,
				MID:      10,
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			data := tt.header.Encode()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = DecodeHeader(data)
			}
		})
	}
}

// BenchmarkEncodePacket benchmarks full packet encoding with various data sizes.
func BenchmarkEncodePacket(b *testing.B) {
	header := NewHeader(SMB_COM_WRITE_ANDX)
	header.TID = 2048
	header.UID = 100

	tests := []struct {
		name       string
		paramsSize int
		dataSize   int
	}{
		{"small_1KB", 20, 1024},
		{"medium_64KB", 20, 64 * 1024},
		{"large_128KB", 20, 128 * 1024},
		{"no_data", 20, 0},
		{"large_params", 510, 0},
		{"mixed_4KB", 100, 4096},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			params := make([]byte, tt.paramsSize)
			data := make([]byte, tt.dataSize)
			// Fill with some non-zero data
			for i := range data {
				data[i] = byte(i % 256)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = EncodePacket(header, params, data)
			}
		})
	}
}

// BenchmarkDecodePacket benchmarks full packet decoding with various data sizes.
func BenchmarkDecodePacket(b *testing.B) {
	header := NewHeader(SMB_COM_READ_ANDX)
	header.TID = 2048
	header.UID = 100
	header.MID = 10

	tests := []struct {
		name       string
		paramsSize int
		dataSize   int
	}{
		{"small_1KB", 20, 1024},
		{"medium_64KB", 20, 64 * 1024},
		{"large_128KB", 20, 128 * 1024},
		{"no_data", 20, 0},
		{"large_params", 510, 0},
		{"mixed_4KB", 100, 4096},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			params := make([]byte, tt.paramsSize)
			data := make([]byte, tt.dataSize)
			// Fill with some non-zero data
			for i := range data {
				data[i] = byte(i % 256)
			}
			packet, _ := EncodePacket(header, params, data)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, _, _ = DecodePacket(packet)
			}
		})
	}
}

// BenchmarkEncodeParameters benchmarks parameter encoding with various types.
func BenchmarkEncodeParameters(b *testing.B) {
	tests := []struct {
		name   string
		params []interface{}
	}{
		{
			name:   "simple_uint16",
			params: []interface{}{uint16(0x1234)},
		},
		{
			name:   "mixed_types",
			params: []interface{}{uint8(1), uint16(0x1234), uint32(0x12345678)},
		},
		{
			name: "complex_params",
			params: []interface{}{
				uint8(0xFF),
				uint16(0),
				uint16(0x1000),
				uint32(0),
				uint32(4096),
				uint64(0),
				[]byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name:   "large_byte_slice",
			params: []interface{}{make([]byte, 500)},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = EncodeParameters(tt.params...)
			}
		})
	}
}

// BenchmarkAndXHeaderEncodeDecode benchmarks AndX header operations.
func BenchmarkAndXHeaderEncodeDecode(b *testing.B) {
	b.Run("Encode", func(b *testing.B) {
		andx := NewAndXHeader()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = andx.Encode()
		}
	})

	b.Run("EncodeWithChaining", func(b *testing.B) {
		andx := &AndXHeader{
			AndXCommand: SMB_COM_TREE_CONNECT_ANDX,
			AndXOffset:  64,
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = andx.Encode()
		}
	})

	b.Run("Decode", func(b *testing.B) {
		andx := NewAndXHeader()
		data := andx.Encode()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = DecodeAndXHeader(data)
		}
	})
}

// BenchmarkHeaderRoundTrip benchmarks the complete encode/decode cycle.
func BenchmarkHeaderRoundTrip(b *testing.B) {
	header := &Header{
		Protocol: [4]byte{0xFF, 'S', 'M', 'B'},
		Command:  SMB_COM_READ_ANDX,
		Status:   STATUS_SUCCESS,
		Flags:    SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS,
		Flags2:   SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE,
		TID:      2048,
		PIDLow:   0xFFFE,
		UID:      100,
		MID:      10,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		data := header.Encode()
		_, _ = DecodeHeader(data)
	}
}
