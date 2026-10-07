package smb1

import (
	"bytes"
	"testing"
)

func TestEncodeDeleteDirectoryRequest(t *testing.T) {
	tests := []struct {
		name     string
		req      *DeleteDirectoryRequest
		wantErr  bool
		wantData []byte
	}{
		{
			name:     "ascii adds leading backslash",
			req:      &DeleteDirectoryRequest{DirectoryName: "dir\\sub", UseUnicode: false},
			wantData: append(append([]byte{0x04}, []byte("\\dir\\sub")...), 0x00),
		},
		{
			// The data block starts at an odd offset from the SMB header
			// (32 header + 1 word count + 2 byte count = 35), so after the
			// BufferFormat byte the UTF-16 string is even-aligned and needs
			// no padding byte.
			name: "unicode no padding",
			req:  &DeleteDirectoryRequest{DirectoryName: "\\ab", UseUnicode: true},
			wantData: []byte{
				0x04,       // BufferFormat
				0x5C, 0x00, // '\'
				0x61, 0x00, // 'a'
				0x62, 0x00, // 'b'
				0x00, 0x00, // null terminator
			},
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name:    "empty directory name",
			req:     &DeleteDirectoryRequest{DirectoryName: "", UseUnicode: true},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeDeleteDirectoryRequest(tt.req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("EncodeDeleteDirectoryRequest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("EncodeDeleteDirectoryRequest() unexpected error: %v", err)
			}

			// SMB_COM_DELETE_DIRECTORY has WordCount = 0.
			if len(params) != 0 {
				t.Errorf("params = %x, want empty", params)
			}
			if !bytes.Equal(data, tt.wantData) {
				t.Errorf("data = %x, want %x", data, tt.wantData)
			}
		})
	}
}

func TestDecodeDeleteDirectoryResponse(t *testing.T) {
	if err := DecodeDeleteDirectoryResponse([]byte{}, []byte{}); err != nil {
		t.Errorf("empty response: unexpected error %v", err)
	}
	if err := DecodeDeleteDirectoryResponse([]byte{0x01, 0x02}, nil); err == nil {
		t.Errorf("non-empty params: expected error, got nil")
	}
}
