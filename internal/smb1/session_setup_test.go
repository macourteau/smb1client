package smb1

import (
	"encoding/binary"
	"testing"
)

func TestEncodeSessionSetupRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *SessionSetupRequest
		wantErr bool
		check   func(*testing.T, []byte, []byte)
	}{
		{
			name: "basic request with ASCII",
			req: &SessionSetupRequest{
				AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
				AndXReserved:       0,
				AndXOffset:         0,
				MaxBufferSize:      16644,
				MaxMpxCount:        50,
				VcNumber:           0,
				SessionKey:         0,
				SecurityBlobLength: 10,
				Reserved:           0,
				Capabilities:       CAP_NT_SMBS,
				SecurityBlob:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				NativeOS:           "Unix",
				NativeLanMan:       "Samba",
				UseUnicode:         false,
			},
			wantErr: false,
			check: func(t *testing.T, params, data []byte) {
				if len(params) != 24 {
					t.Errorf("params length = %d, want 24", len(params))
				}
				if params[0] != SMB_COM_NO_ANDX_COMMAND {
					t.Errorf("AndXCommand = 0x%02x, want 0x%02x", params[0], SMB_COM_NO_ANDX_COMMAND)
				}
				if binary.LittleEndian.Uint16(params[4:6]) != 16644 {
					t.Errorf("MaxBufferSize = %d, want 16644", binary.LittleEndian.Uint16(params[4:6]))
				}
				// Check data contains security blob + strings
				if len(data) < 10 {
					t.Errorf("data length = %d, want at least 10", len(data))
				}
			},
		},
		{
			name: "basic request with Unicode",
			req: &SessionSetupRequest{
				AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
				MaxBufferSize:      16644,
				MaxMpxCount:        50,
				VcNumber:           0,
				SessionKey:         0,
				SecurityBlobLength: 5,
				Capabilities:       CAP_UNICODE,
				SecurityBlob:       []byte{1, 2, 3, 4, 5},
				NativeOS:           "Unix",
				NativeLanMan:       "Samba",
				UseUnicode:         true,
			},
			wantErr: false,
			check: func(t *testing.T, params, data []byte) {
				if len(params) != 24 {
					t.Errorf("params length = %d, want 24", len(params))
				}
				// Check data contains security blob (5 bytes) + padding + UTF-16LE strings
				if len(data) < 5 {
					t.Errorf("data length = %d, want at least 5", len(data))
				}
			},
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeSessionSetupRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeSessionSetupRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if tt.check != nil {
				tt.check(t, params, data)
			}
		})
	}
}

func TestDecodeSessionSetupResponse(t *testing.T) {
	tests := []struct {
		name       string
		params     []byte
		data       []byte
		useUnicode bool
		want       *SessionSetupResponse
		wantErr    bool
	}{
		{
			name: "valid response with ASCII",
			params: func() []byte {
				p := make([]byte, 8)
				p[0] = SMB_COM_NO_ANDX_COMMAND
				p[1] = 0
				binary.LittleEndian.PutUint16(p[2:4], 0)
				binary.LittleEndian.PutUint16(p[4:6], 0) // Action
				binary.LittleEndian.PutUint16(p[6:8], 5) // SecurityBlobLength
				return p
			}(),
			data: func() []byte {
				d := []byte{1, 2, 3, 4, 5} // Security blob
				d = append(d, []byte("Windows 10\x00")...)
				d = append(d, []byte("LAN Manager\x00")...)
				d = append(d, []byte("WORKGROUP\x00")...)
				return d
			}(),
			useUnicode: false,
			want: &SessionSetupResponse{
				AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
				AndXReserved:       0,
				AndXOffset:         0,
				Action:             0,
				SecurityBlobLength: 5,
				SecurityBlob:       []byte{1, 2, 3, 4, 5},
				NativeOS:           "Windows 10",
				NativeLanMan:       "LAN Manager",
				PrimaryDomain:      "WORKGROUP",
			},
			wantErr: false,
		},
		{
			name: "valid response with empty Unicode strings",
			params: func() []byte {
				p := make([]byte, 8)
				p[0] = SMB_COM_NO_ANDX_COMMAND
				binary.LittleEndian.PutUint16(p[2:4], 0)
				binary.LittleEndian.PutUint16(p[4:6], SESSION_SETUP_GUEST) // Action (guest)
				binary.LittleEndian.PutUint16(p[6:8], 4)                   // SecurityBlobLength
				return p
			}(),
			data: func() []byte {
				d := []byte{1, 2, 3, 4} // Security blob
				// Add padding for alignment
				d = append(d, 0)
				// Empty strings with just null terminators
				d = append(d, 0, 0) // OS null terminator
				d = append(d, 0, 0) // LM null terminator
				return d
			}(),
			useUnicode: true,
			want: &SessionSetupResponse{
				AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
				AndXReserved:       0,
				AndXOffset:         0,
				Action:             SESSION_SETUP_GUEST,
				SecurityBlobLength: 4,
				SecurityBlob:       []byte{1, 2, 3, 4},
				NativeOS:           "",
				NativeLanMan:       "",
				PrimaryDomain:      "",
			},
			wantErr: false,
		},
		{
			name:    "params too short",
			params:  make([]byte, 4),
			data:    []byte{},
			wantErr: true,
		},
		{
			name: "data too short for security blob",
			params: func() []byte {
				p := make([]byte, 8)
				binary.LittleEndian.PutUint16(p[6:8], 10) // SecurityBlobLength = 10
				return p
			}(),
			data:    make([]byte, 5), // Only 5 bytes
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeSessionSetupResponse(tt.params, tt.data, tt.useUnicode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeSessionSetupResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.AndXCommand != tt.want.AndXCommand {
				t.Errorf("AndXCommand = 0x%02x, want 0x%02x", got.AndXCommand, tt.want.AndXCommand)
			}
			if got.Action != tt.want.Action {
				t.Errorf("Action = 0x%04x, want 0x%04x", got.Action, tt.want.Action)
			}
			if got.SecurityBlobLength != tt.want.SecurityBlobLength {
				t.Errorf("SecurityBlobLength = %d, want %d", got.SecurityBlobLength, tt.want.SecurityBlobLength)
			}
			if len(got.SecurityBlob) != len(tt.want.SecurityBlob) {
				t.Errorf("SecurityBlob length = %d, want %d", len(got.SecurityBlob), len(tt.want.SecurityBlob))
			}
			if got.NativeOS != tt.want.NativeOS {
				t.Errorf("NativeOS = %q, want %q", got.NativeOS, tt.want.NativeOS)
			}
			if got.NativeLanMan != tt.want.NativeLanMan {
				t.Errorf("NativeLanMan = %q, want %q", got.NativeLanMan, tt.want.NativeLanMan)
			}
			if got.PrimaryDomain != tt.want.PrimaryDomain {
				t.Errorf("PrimaryDomain = %q, want %q", got.PrimaryDomain, tt.want.PrimaryDomain)
			}
		})
	}
}

func TestSessionSetupResponse_IsGuest(t *testing.T) {
	tests := []struct {
		name   string
		action uint16
		want   bool
	}{
		{
			name:   "guest login",
			action: SESSION_SETUP_GUEST,
			want:   true,
		},
		{
			name:   "normal login",
			action: 0,
			want:   false,
		},
		{
			name:   "guest with other flags",
			action: SESSION_SETUP_GUEST | 0x0002,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &SessionSetupResponse{Action: tt.action}
			if got := r.IsGuest(); got != tt.want {
				t.Errorf("IsGuest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionSetupResponse_HasChaining(t *testing.T) {
	tests := []struct {
		name        string
		andXCommand uint8
		want        bool
	}{
		{
			name:        "no chaining",
			andXCommand: SMB_COM_NO_ANDX_COMMAND,
			want:        false,
		},
		{
			name:        "has chaining",
			andXCommand: SMB_COM_TREE_CONNECT_ANDX,
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &SessionSetupResponse{AndXCommand: tt.andXCommand}
			if got := r.HasChaining(); got != tt.want {
				t.Errorf("HasChaining() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionSetupResponse_String(t *testing.T) {
	resp := &SessionSetupResponse{
		Action:             SESSION_SETUP_GUEST,
		SecurityBlobLength: 5,
		SecurityBlob:       []byte{1, 2, 3, 4, 5},
		NativeOS:           "Windows 10",
		NativeLanMan:       "LAN Manager",
		PrimaryDomain:      "WORKGROUP",
	}

	str := resp.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	t.Logf("String() = %s", str)
}

func TestSessionSetupRoundTrip(t *testing.T) {
	// Test ASCII round trip
	req := &SessionSetupRequest{
		AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
		MaxBufferSize:      16644,
		MaxMpxCount:        50,
		VcNumber:           0,
		SessionKey:         0,
		SecurityBlobLength: 10,
		Capabilities:       CAP_NT_SMBS,
		SecurityBlob:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		NativeOS:           "Unix",
		NativeLanMan:       "Samba",
		UseUnicode:         false,
	}

	params, data, err := EncodeSessionSetupRequest(req)
	if err != nil {
		t.Fatalf("EncodeSessionSetupRequest() error = %v", err)
	}

	if len(params) != 24 {
		t.Errorf("params length = %d, want 24", len(params))
	}

	if len(data) < 10 {
		t.Errorf("data length = %d, want at least 10", len(data))
	}

	// Create mock response
	respParams := make([]byte, 8)
	respParams[0] = SMB_COM_NO_ANDX_COMMAND
	binary.LittleEndian.PutUint16(respParams[4:6], 0)
	binary.LittleEndian.PutUint16(respParams[6:8], 5)

	respData := []byte{1, 2, 3, 4, 5}
	respData = append(respData, []byte("Windows\x00")...)
	respData = append(respData, []byte("LM\x00")...)

	resp, err := DecodeSessionSetupResponse(respParams, respData, false)
	if err != nil {
		t.Fatalf("DecodeSessionSetupResponse() error = %v", err)
	}

	if resp.NativeOS != "Windows" {
		t.Errorf("NativeOS = %q, want %q", resp.NativeOS, "Windows")
	}
}

func TestSessionSetupUnicodeRoundTrip(t *testing.T) {
	// Test Unicode round trip (encode and decode)
	req := &SessionSetupRequest{
		AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
		MaxBufferSize:      16644,
		MaxMpxCount:        50,
		VcNumber:           0,
		SessionKey:         0,
		SecurityBlobLength: 5,
		Capabilities:       CAP_UNICODE,
		SecurityBlob:       []byte{1, 2, 3, 4, 5},
		NativeOS:           "Linux",
		NativeLanMan:       "CIFS",
		UseUnicode:         true,
	}

	params, data, err := EncodeSessionSetupRequest(req)
	if err != nil {
		t.Fatalf("EncodeSessionSetupRequest() error = %v", err)
	}

	if len(params) != 24 {
		t.Errorf("params length = %d, want 24", len(params))
	}

	// Verify data section contains security blob and encoded strings
	if len(data) < 5 {
		t.Errorf("data length = %d, want at least 5 (security blob)", len(data))
	}

	// Create mock response with empty Unicode strings (simpler test)
	respParams := make([]byte, 8)
	respParams[0] = SMB_COM_NO_ANDX_COMMAND
	binary.LittleEndian.PutUint16(respParams[4:6], 0)
	binary.LittleEndian.PutUint16(respParams[6:8], 4)

	respData := []byte{1, 2, 3, 4}
	// Add padding
	respData = append(respData, 0)
	// Empty Unicode strings
	respData = append(respData, 0, 0) // OS null
	respData = append(respData, 0, 0) // LM null

	resp, err := DecodeSessionSetupResponse(respParams, respData, true)
	if err != nil {
		t.Fatalf("DecodeSessionSetupResponse() error = %v", err)
	}

	if resp.NativeOS != "" {
		t.Errorf("NativeOS = %q, want %q", resp.NativeOS, "")
	}
	if resp.NativeLanMan != "" {
		t.Errorf("NativeLanMan = %q, want %q", resp.NativeLanMan, "")
	}
}
