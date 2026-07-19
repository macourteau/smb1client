package smb1

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncodeRenameRequest(t *testing.T) {
	tests := []struct {
		name            string
		req             *RenameRequest
		wantErr         bool
		wantSearchAttrs uint16
		wantOldFileName string
		wantNewFileName string
	}{
		{
			name: "ascii rename with leading backslash",
			req: &RenameRequest{
				SearchAttributes: 0x0016,
				OldFileName:      "old.txt",
				NewFileName:      "new.txt",
				UseUnicode:       false,
			},
			wantSearchAttrs: 0x0016,
			wantOldFileName: "\\old.txt",
			wantNewFileName: "\\new.txt",
		},
		{
			name: "unicode rename with leading backslash",
			req: &RenameRequest{
				SearchAttributes: 0x0016,
				OldFileName:      "old.txt",
				NewFileName:      "new.txt",
				UseUnicode:       true,
			},
			wantSearchAttrs: 0x0016,
			wantOldFileName: "\\old.txt",
			wantNewFileName: "\\new.txt",
		},
		{
			name: "unicode rename already has leading backslash",
			req: &RenameRequest{
				SearchAttributes: 0x0016,
				OldFileName:      "\\old.txt",
				NewFileName:      "\\new.txt",
				UseUnicode:       true,
			},
			wantSearchAttrs: 0x0016,
			wantOldFileName: "\\old.txt",
			wantNewFileName: "\\new.txt",
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "empty old filename",
			req: &RenameRequest{
				SearchAttributes: 0x0016,
				OldFileName:      "",
				NewFileName:      "new.txt",
				UseUnicode:       true,
			},
			wantErr: true,
		},
		{
			name: "empty new filename",
			req: &RenameRequest{
				SearchAttributes: 0x0016,
				OldFileName:      "old.txt",
				NewFileName:      "",
				UseUnicode:       true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeRenameRequest(tt.req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("EncodeRenameRequest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("EncodeRenameRequest() unexpected error: %v", err)
			}

			// Verify parameters (SearchAttributes)
			if len(params) != 2 {
				t.Errorf("params length = %d, want 2", len(params))
			}
			searchAttrs := uint16(params[0]) | uint16(params[1])<<8
			if searchAttrs != tt.wantSearchAttrs {
				t.Errorf("SearchAttributes = 0x%04X, want 0x%04X", searchAttrs, tt.wantSearchAttrs)
			}

			// Verify data section structure
			if len(data) < 2 {
				t.Fatalf("data too short: got %d bytes", len(data))
			}

			// First byte should be buffer format (0x04)
			if data[0] != 0x04 {
				t.Errorf("first buffer format = 0x%02X, want 0x04", data[0])
			}

			// For debugging, print the hex dump
			t.Logf("Params: %s", hex.EncodeToString(params))
			t.Logf("Data: %s", hex.EncodeToString(data))

			// Verify the filenames are present in the data
			if tt.req.UseUnicode {
				// For Unicode, we expect UTF-16LE encoding with null terminators
				// Check that the old filename with backslash is encoded
				expectedOldStart := []byte{0x5C, 0x00} // backslash in UTF-16LE
				found := false
				for i := 0; i < len(data)-1; i++ {
					if bytes.Equal(data[i:i+2], expectedOldStart) {
						found = true
						break
					}
				}
				if !found && tt.wantOldFileName != "" {
					t.Errorf("Unicode old filename should start with backslash (\\x5C\\x00)")
				}
			}
		})
	}
}

func TestDecodeRenameResponse(t *testing.T) {
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
			resp, err := DecodeRenameResponse(tt.params, tt.data)

			if tt.wantErr {
				if err == nil {
					t.Errorf("DecodeRenameResponse() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("DecodeRenameResponse() unexpected error: %v", err)
			}

			if resp == nil {
				t.Errorf("DecodeRenameResponse() returned nil response")
			}
		})
	}
}
