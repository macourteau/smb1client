package smb1

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncodeRAPRequest(t *testing.T) {
	tests := []struct {
		name         string
		functionCode uint16
		paramDesc    string
		dataDesc     string
		params       []byte
		data         []byte
		wantErr      bool
	}{
		{
			name:         "NetShareEnum basic request",
			functionCode: RAP_NetShareEnum,
			paramDesc:    ParamDescriptorNetShareEnum,
			dataDesc:     DataDescriptorNetShareEnumLevel1,
			params:       []byte{0x01, 0x00, 0xFF, 0xFF}, // Level 1, buffer size 65535
			data:         nil,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, _, err := EncodeRAPRequest(tt.functionCode, tt.paramDesc, tt.dataDesc, tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeRAPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Verify function code
			if len(params) < 2 {
				t.Fatal("params too short for function code")
			}
			gotFuncCode := binary.LittleEndian.Uint16(params[0:2])
			if gotFuncCode != tt.functionCode {
				t.Errorf("function code = 0x%04X, want 0x%04X", gotFuncCode, tt.functionCode)
			}

			// Verify parameter descriptor is present
			paramDescBytes := []byte(tt.paramDesc + "\x00")
			if !bytes.Contains(params, paramDescBytes) {
				t.Errorf("parameter descriptor %q not found in params", tt.paramDesc)
			}

			// Verify data descriptor is present
			dataDescBytes := []byte(tt.dataDesc + "\x00")
			if !bytes.Contains(params, dataDescBytes) {
				t.Errorf("data descriptor %q not found in params", tt.dataDesc)
			}

			// Verify function-specific params are appended
			if !bytes.HasSuffix(params, tt.params) {
				t.Error("function-specific params not appended correctly")
			}
		})
	}
}

func TestEncodeNetShareEnumRequest(t *testing.T) {
	tests := []struct {
		name      string
		req       *NetShareEnumRequest
		wantErr   bool
		wantLevel uint16
	}{
		{
			name: "level 1 request",
			req: &NetShareEnumRequest{
				InfoLevel:  1,
				ReceiveBuf: 65535,
			},
			wantErr:   false,
			wantLevel: 1,
		},
		{
			name: "unsupported level",
			req: &NetShareEnumRequest{
				InfoLevel:  2,
				ReceiveBuf: 65535,
			},
			wantErr: true,
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeNetShareEnumRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeNetShareEnumRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Verify function code
			if len(params) < 2 {
				t.Fatal("params too short")
			}
			funcCode := binary.LittleEndian.Uint16(params[0:2])
			if funcCode != RAP_NetShareEnum {
				t.Errorf("function code = 0x%04X, want 0x%04X", funcCode, RAP_NetShareEnum)
			}

			// Verify data is nil
			if data != nil {
				t.Error("data should be nil for NetShareEnum request")
			}
		})
	}
}

func TestDecodeRAPResponse(t *testing.T) {
	tests := []struct {
		name       string
		params     []byte
		data       []byte
		wantStatus uint16
		wantErr    bool
	}{
		{
			name:       "success status",
			params:     []byte{0x00, 0x00, 0x12, 0x34, 0x56, 0x78}, // status=0, converter=0x3412, extra
			data:       []byte{0x01, 0x02, 0x03},
			wantStatus: 0,
			wantErr:    false,
		},
		{
			name:       "error status",
			params:     []byte{0x05, 0x00, 0x00, 0x00}, // status=5, converter=0
			data:       nil,
			wantStatus: 5,
			wantErr:    false,
		},
		{
			name:    "params too short",
			params:  []byte{0x00, 0x00}, // only 2 bytes
			data:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, remainingParams, _, err := DecodeRAPResponse(tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeRAPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}

			// Verify remaining params start at offset 2 (after status)
			if len(tt.params) > 2 && !bytes.Equal(remainingParams, tt.params[2:]) {
				t.Error("remaining params not correctly extracted")
			}
		})
	}
}

func TestDecodeNetShareEnumResponse(t *testing.T) {
	// Create a sample response for level 1 with 2 shares
	// Response format: Status(2) + Converter(2) + EntryCount(2) + Available(2) + Data
	params := make([]byte, 8)
	binary.LittleEndian.PutUint16(params[0:2], 0)    // Status = success
	binary.LittleEndian.PutUint16(params[2:4], 1000) // Converter
	binary.LittleEndian.PutUint16(params[4:6], 2)    // EntryCount = 2
	binary.LittleEndian.PutUint16(params[6:8], 2)    // Available = 2

	// Create data section with 2 share entries
	// Each entry: Name(13) + Pad(1) + Type(2) + CommentOffset(4) = 20 bytes
	data := make([]byte, 100) // 2 entries + space for comments

	// Share 1: "TestShare"
	copy(data[0:13], []byte("TestShare\x00\x00\x00\x00"))
	data[13] = 0 // padding
	binary.LittleEndian.PutUint16(data[14:16], ShareTypeDisk)
	binary.LittleEndian.PutUint32(data[16:20], 1040) // Comment pointer (converter + 40)

	// Share 2: "Public"
	copy(data[20:33], []byte("Public\x00\x00\x00\x00\x00\x00\x00"))
	data[33] = 0 // padding
	binary.LittleEndian.PutUint16(data[34:36], ShareTypeDisk)
	binary.LittleEndian.PutUint32(data[36:40], 1060) // Comment pointer (converter + 60)

	// Add comments at the specified offsets (relative to data start)
	// Comment 1 at offset 40 (pointer value 1000 + 40 = 1040)
	copy(data[40:51], []byte("Test share\x00"))
	// Comment 2 at offset 60 (pointer value 1000 + 60 = 1060)
	copy(data[60:73], []byte("Public files\x00"))

	tests := []struct {
		name      string
		params    []byte
		data      []byte
		infoLevel uint16
		wantCount uint16
		wantErr   bool
	}{
		{
			name:      "level 1 with 2 shares",
			params:    params,
			data:      data,
			infoLevel: 1,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "unsupported level",
			params:    params,
			data:      data,
			infoLevel: 2,
			wantErr:   true,
		},
		{
			name:      "error status",
			params:    []byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // status=5
			data:      nil,
			infoLevel: 1,
			wantErr:   true,
		},
		{
			name:      "params too short",
			params:    []byte{0x00, 0x00},
			data:      nil,
			infoLevel: 1,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := DecodeNetShareEnumResponse(tt.params, tt.data, tt.infoLevel)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeNetShareEnumResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if resp.EntryCount != tt.wantCount {
				t.Errorf("EntryCount = %d, want %d", resp.EntryCount, tt.wantCount)
			}

			if len(resp.Shares) != int(tt.wantCount) {
				t.Errorf("len(Shares) = %d, want %d", len(resp.Shares), tt.wantCount)
			}

			// Verify share names
			if tt.wantCount > 0 {
				if resp.Shares[0].Name != "TestShare" {
					t.Errorf("Share[0].Name = %q, want %q", resp.Shares[0].Name, "TestShare")
				}
				if resp.Shares[0].Type != ShareTypeDisk {
					t.Errorf("Share[0].Type = 0x%04X, want 0x%04X", resp.Shares[0].Type, ShareTypeDisk)
				}
				if resp.Shares[0].Comment != "Test share" {
					t.Errorf("Share[0].Comment = %q, want %q", resp.Shares[0].Comment, "Test share")
				}
			}

			if tt.wantCount > 1 {
				if resp.Shares[1].Name != "Public" {
					t.Errorf("Share[1].Name = %q, want %q", resp.Shares[1].Name, "Public")
				}
				if resp.Shares[1].Comment != "Public files" {
					t.Errorf("Share[1].Comment = %q, want %q", resp.Shares[1].Comment, "Public files")
				}
			}
		})
	}
}

func TestParseNullPaddedString(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "with null terminator",
			data: []byte("Test\x00\x00\x00\x00"),
			want: "Test",
		},
		{
			name: "full field",
			data: []byte("TestShareName"),
			want: "TestShareName",
		},
		{
			name: "empty",
			data: []byte("\x00\x00\x00"),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNullPaddedString(tt.data)
			if got != tt.want {
				t.Errorf("parseNullPaddedString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseNullTerminatedString(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name:    "with null terminator",
			data:    []byte("Test\x00extra"),
			want:    "Test",
			wantErr: false,
		},
		{
			name:    "empty string",
			data:    []byte("\x00"),
			want:    "",
			wantErr: false,
		},
		{
			name:    "no null terminator",
			data:    []byte("Test"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNullTerminatedString(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseNullTerminatedString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("parseNullTerminatedString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEncodeTransactionRequest(t *testing.T) {
	tests := []struct {
		name     string
		pipeName string
		params   []byte
		data     []byte
		wantErr  bool
	}{
		{
			name:     "LANMAN pipe",
			pipeName: `\PIPE\LANMAN`,
			params:   []byte{0x01, 0x02, 0x03},
			data:     []byte{0x04, 0x05},
			wantErr:  false,
		},
		{
			name:     "empty pipe name",
			pipeName: "",
			params:   nil,
			data:     nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allParams, dataSection, err := EncodeTransactionRequest(tt.pipeName, tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeTransactionRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Verify parameters section has correct structure
			if len(allParams) < 32 {
				t.Errorf("allParams too short: got %d bytes, want at least 32", len(allParams))
			}

			// Verify TotalParameterCount matches
			totalParamCount := binary.LittleEndian.Uint16(allParams[0:2])
			if int(totalParamCount) != len(tt.params) {
				t.Errorf("TotalParameterCount = %d, want %d", totalParamCount, len(tt.params))
			}

			// Verify TotalDataCount matches
			totalDataCount := binary.LittleEndian.Uint16(allParams[2:4])
			if int(totalDataCount) != len(tt.data) {
				t.Errorf("TotalDataCount = %d, want %d", totalDataCount, len(tt.data))
			}

			// Verify SetupCount is 2 (TRANSACTION uses 2 setup words)
			setupCount := allParams[26]
			if setupCount != 2 {
				t.Errorf("SetupCount = %d, want 2", setupCount)
			}

			// Verify pipe name is in data section
			pipeNameBytes := []byte(tt.pipeName + "\x00")
			if !bytes.Contains(dataSection, pipeNameBytes) {
				t.Errorf("pipe name %q not found in data section", tt.pipeName)
			}
		})
	}
}

func TestShareTypeConstants(t *testing.T) {
	// Verify share type constants are correct
	tests := []struct {
		name  string
		value uint16
		want  uint16
	}{
		{"ShareTypeDisk", ShareTypeDisk, 0x0000},
		{"ShareTypePrintQ", ShareTypePrintQ, 0x0001},
		{"ShareTypeDevice", ShareTypeDevice, 0x0002},
		{"ShareTypeIPC", ShareTypeIPC, 0x0003},
		{"ShareTypeTemporary", ShareTypeTemporary, 0x4000},
		{"ShareTypeHidden", ShareTypeHidden, 0x8000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = 0x%04X, want 0x%04X", tt.name, tt.value, tt.want)
			}
		})
	}
}
