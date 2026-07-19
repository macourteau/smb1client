package smb1

import (
	"bytes"
	"testing"
)

func TestEncodeSetInformationRequest(t *testing.T) {
	tests := []struct {
		name       string
		req        *SetInformationRequest
		wantErr    bool
		wantParams []byte
		wantData   []byte
	}{
		{
			name: "ascii adds leading backslash",
			req: &SetInformationRequest{
				FileAttributes: 0x0021, // READONLY | ARCHIVE
				LastWriteTime:  0,
				FileName:       "test.txt",
				UseUnicode:     false,
			},
			wantParams: []byte{
				0x21, 0x00, // FileAttributes
				0x00, 0x00, 0x00, 0x00, // LastWriteTime (UTIME, 0 = don't change)
				0x00, 0x00, 0x00, 0x00, 0x00, // Reserved (5 words)
				0x00, 0x00, 0x00, 0x00, 0x00,
			},
			wantData: append(append([]byte{0x04}, []byte("\\test.txt")...), 0x00, 0x04, 0x00),
		},
		{
			name: "ascii nonzero last write time",
			req: &SetInformationRequest{
				FileAttributes: 0x0000,
				LastWriteTime:  0x12345678,
				FileName:       "\\dir\\file.bin",
				UseUnicode:     false,
			},
			wantParams: []byte{
				0x00, 0x00, // FileAttributes
				0x78, 0x56, 0x34, 0x12, // LastWriteTime
				0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00,
			},
			wantData: append(append([]byte{0x04}, []byte("\\dir\\file.bin")...), 0x00, 0x04, 0x00),
		},
		{
			// The data block starts at an odd offset from the SMB header
			// (32 header + 1 word count + 16 params + 2 byte count = 51), so
			// after the BufferFormat byte the UTF-16 string is even-aligned
			// and needs no padding byte.
			name: "unicode no padding",
			req: &SetInformationRequest{
				FileAttributes: 0x0001,
				LastWriteTime:  0,
				FileName:       "ab.txt",
				UseUnicode:     true,
			},
			wantParams: []byte{
				0x01, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00,
			},
			wantData: []byte{
				0x04,       // BufferFormat
				0x5C, 0x00, // '\'
				0x61, 0x00, // 'a'
				0x62, 0x00, // 'b'
				0x2E, 0x00, // '.'
				0x74, 0x00, // 't'
				0x78, 0x00, // 'x'
				0x74, 0x00, // 't'
				0x00, 0x00, // null terminator
				0x04, 0x00, // trailing empty ASCII buffer (X/Open)
			},
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "empty filename",
			req: &SetInformationRequest{
				FileAttributes: 0x0001,
				FileName:       "",
				UseUnicode:     true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeSetInformationRequest(tt.req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("EncodeSetInformationRequest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("EncodeSetInformationRequest() unexpected error: %v", err)
			}

			if !bytes.Equal(params, tt.wantParams) {
				t.Errorf("params = %x, want %x", params, tt.wantParams)
			}
			if !bytes.Equal(data, tt.wantData) {
				t.Errorf("data = %x, want %x", data, tt.wantData)
			}
		})
	}
}

func TestDecodeSetInformationResponse(t *testing.T) {
	tests := []struct {
		name    string
		params  []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty response",
			params:  []byte{},
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "non-empty params",
			params:  []byte{0x01, 0x02},
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DecodeSetInformationResponse(tt.params, tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("DecodeSetInformationResponse() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("DecodeSetInformationResponse() unexpected error: %v", err)
			}
		})
	}
}
