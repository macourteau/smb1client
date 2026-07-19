package smb1

import (
	"testing"
)

// BenchmarkEncodeReadRequest benchmarks encoding READ_ANDX requests with various buffer sizes.
func BenchmarkEncodeReadRequest(b *testing.B) {
	tests := []struct {
		name               string
		supportsLargeFiles bool
		maxCount           uint16
	}{
		{"small_4KB", true, 4 * 1024},
		{"medium_32KB", true, 32 * 1024},
		{"large_max_uint16", true, 65535}, // max uint16
		{"no_large_files_support", false, 16 * 1024},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			req := &ReadRequest{
				AndXCommand:             SMB_COM_NO_ANDX_COMMAND,
				FID:                     0x002A,
				Offset:                  0,
				MaxCountOfBytesToReturn: tt.maxCount,
				MinCountOfBytesToReturn: 0,
				Timeout:                 0,
				Remaining:               0,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _, _ = EncodeReadRequest(req, tt.supportsLargeFiles, false)
			}
		})
	}
}

// BenchmarkEncodeWriteRequest benchmarks encoding WRITE_ANDX requests with various data sizes.
func BenchmarkEncodeWriteRequest(b *testing.B) {
	tests := []struct {
		name               string
		supportsLargeFiles bool
		dataSize           int
	}{
		{"small_4KB", true, 4 * 1024},
		{"medium_64KB", true, 64 * 1024},
		{"large_128KB", true, 128 * 1024},
		{"tiny_512B", true, 512},
		{"no_large_files_32KB", false, 32 * 1024},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			data := make([]byte, tt.dataSize)
			// Fill with some non-zero data
			for i := range data {
				data[i] = byte(i % 256)
			}

			req := &WriteRequest{
				AndXCommand:    SMB_COM_NO_ANDX_COMMAND,
				FID:            0x002A,
				Offset:         0,
				Timeout:        0,
				WriteMode:      0,
				Remaining:      0,
				DataLengthHigh: uint16(len(data) >> 16),
				DataLength:     uint16(len(data) & 0xFFFF),
				DataOffset:     0, // Will be calculated in encode
				Data:           data,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _, _ = EncodeWriteRequest(req, tt.supportsLargeFiles)
			}
		})
	}
}

// BenchmarkEncodeNTCreateRequest benchmarks encoding NT_CREATE_ANDX requests with various filename lengths.
func BenchmarkEncodeNTCreateRequest(b *testing.B) {
	tests := []struct {
		name       string
		fileName   string
		useUnicode bool
	}{
		{"short_ascii", "test.txt", false},
		{"short_unicode", "test.txt", true},
		{"long_ascii", "very/long/path/to/deeply/nested/directory/structure/file.txt", false},
		{"long_unicode", "very/long/path/to/deeply/nested/directory/structure/file.txt", true},
		{"medium_ascii", "documents/reports/2024/annual_report.pdf", false},
		{"medium_unicode", "documents/reports/2024/annual_report.pdf", true},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			var nameLength uint16
			if tt.useUnicode {
				nameLength = uint16(len(tt.fileName) * 2)
			} else {
				nameLength = uint16(len(tt.fileName))
			}

			req := &NTCreateRequest{
				AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
				NameLength:         nameLength,
				Flags:              0,
				RootDirectoryFID:   0,
				DesiredAccess:      GENERIC_READ,
				AllocationSize:     0,
				FileAttributes:     FILE_ATTRIBUTE_NORMAL,
				ShareAccess:        FILE_SHARE_READ,
				CreateDisposition:  FILE_OPEN,
				CreateOptions:      0,
				ImpersonationLevel: SECURITY_IMPERSONATION,
				SecurityFlags:      0,
				FileName:           tt.fileName,
				UseUnicode:         tt.useUnicode,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _, _ = EncodeNTCreateRequest(req)
			}
		})
	}
}

// BenchmarkDecodeReadResponse benchmarks decoding READ_ANDX responses with various data sizes.
func BenchmarkDecodeReadResponse(b *testing.B) {
	tests := []struct {
		name     string
		dataSize int
	}{
		{"small_4KB", 4 * 1024},
		{"medium_64KB", 64 * 1024},
		{"large_128KB", 128 * 1024},
		{"tiny_512B", 512},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Create a valid READ_ANDX response
			data := make([]byte, tt.dataSize)
			for i := range data {
				data[i] = byte(i % 256)
			}

			// Encode parameters for READ_ANDX response (WordCount = 12)
			params := make([]byte, 24)
			params[0] = SMB_COM_NO_ANDX_COMMAND          // AndXCommand
			params[10] = byte(tt.dataSize & 0xFF)        // DataLength (low)
			params[11] = byte((tt.dataSize >> 8) & 0xFF) // DataLength (high)
			params[12] = byte(HeaderSize + 1 + 24 + 2)   // DataOffset (low)
			params[13] = 0                               // DataOffset (high)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = DecodeReadResponse(params, data)
			}
		})
	}
}

// BenchmarkDecodeWriteResponse benchmarks decoding WRITE_ANDX responses.
func BenchmarkDecodeWriteResponse(b *testing.B) {
	tests := []struct {
		name  string
		count uint32
	}{
		{"small_4KB", 4 * 1024},
		{"medium_64KB", 64 * 1024},
		{"large_128KB", 128 * 1024},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Encode parameters for WRITE_ANDX response (WordCount = 6)
			params := make([]byte, 12)
			params[0] = SMB_COM_NO_ANDX_COMMAND       // AndXCommand
			params[4] = byte(tt.count & 0xFF)         // Count (low)
			params[5] = byte((tt.count >> 8) & 0xFF)  // Count (high)
			params[8] = byte((tt.count >> 16) & 0xFF) // CountHigh (low)
			params[9] = byte((tt.count >> 24) & 0xFF) // CountHigh (high)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = DecodeWriteResponse(params, nil)
			}
		})
	}
}

// BenchmarkDecodeNTCreateResponse benchmarks decoding NT_CREATE_ANDX responses.
func BenchmarkDecodeNTCreateResponse(b *testing.B) {
	// Create a valid NT_CREATE_ANDX response
	params := make([]byte, 68)
	params[0] = SMB_COM_NO_ANDX_COMMAND // AndXCommand
	params[4] = 0                       // OpLockLevel
	params[5] = 0x2A                    // FID (low)
	params[6] = 0x00                    // FID (high)
	params[7] = 0x01                    // CreateAction

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = DecodeNTCreateResponse(params, nil)
	}
}

// BenchmarkReadWriteRoundTrip benchmarks the complete encode/decode cycle for read/write operations.
func BenchmarkReadWriteRoundTrip(b *testing.B) {
	b.Run("Read_32KB", func(b *testing.B) {
		req := &ReadRequest{
			AndXCommand:             SMB_COM_NO_ANDX_COMMAND,
			FID:                     0x002A,
			Offset:                  0,
			MaxCountOfBytesToReturn: 32 * 1024,
			MinCountOfBytesToReturn: 0,
			Timeout:                 0,
			Remaining:               0,
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			params, data, _ := EncodeReadRequest(req, true, false)
			_, _ = DecodeReadResponse(params, data)
		}
	})

	b.Run("Write_64KB", func(b *testing.B) {
		data := make([]byte, 64*1024)
		req := &WriteRequest{
			AndXCommand:    SMB_COM_NO_ANDX_COMMAND,
			FID:            0x002A,
			Offset:         0,
			Timeout:        0,
			WriteMode:      0,
			Remaining:      0,
			DataLengthHigh: 0,
			DataLength:     uint16(len(data)),
			DataOffset:     0,
			Data:           data,
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			params, data, _ := EncodeWriteRequest(req, true)
			_, _ = DecodeWriteResponse(params, data)
		}
	})
}
