package smb1

import (
	"encoding/binary"
	"testing"
)

func TestEncodeTreeConnectRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *TreeConnectRequest
		wantErr bool
		check   func(*testing.T, []byte, []byte)
	}{
		{
			name: "basic request with ASCII",
			req: &TreeConnectRequest{
				AndXCommand:    SMB_COM_NO_ANDX_COMMAND,
				Flags:          0,
				PasswordLength: 0,
				Password:       []byte{},
				Path:           "\\\\server\\share",
				Service:        SERVICE_ANY,
				UseUnicode:     false,
			},
			wantErr: false,
			check: func(t *testing.T, params, data []byte) {
				if len(params) != 8 {
					t.Errorf("params length = %d, want 8", len(params))
				}
				if params[0] != SMB_COM_NO_ANDX_COMMAND {
					t.Errorf("AndXCommand = 0x%02x, want 0x%02x", params[0], SMB_COM_NO_ANDX_COMMAND)
				}
			},
		},
		{
			name: "basic request with Unicode",
			req: &TreeConnectRequest{
				AndXCommand: SMB_COM_NO_ANDX_COMMAND,
				Flags:       TREE_CONNECT_ANDX_EXTENDED_RESPONSE,
				Path:        "\\\\server\\share",
				Service:     SERVICE_DISK_SHARE,
				UseUnicode:  true,
			},
			wantErr: false,
			check: func(t *testing.T, params, data []byte) {
				if len(params) != 8 {
					t.Errorf("params length = %d, want 8", len(params))
				}
				flags := binary.LittleEndian.Uint16(params[4:6])
				if flags != TREE_CONNECT_ANDX_EXTENDED_RESPONSE {
					t.Errorf("Flags = 0x%04x, want 0x%04x", flags, TREE_CONNECT_ANDX_EXTENDED_RESPONSE)
				}
			},
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "empty path",
			req: &TreeConnectRequest{
				Path:       "",
				Service:    SERVICE_ANY,
				UseUnicode: false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeTreeConnectRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeTreeConnectRequest() error = %v, wantErr %v", err, tt.wantErr)
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

func TestDecodeTreeConnectResponse(t *testing.T) {
	tests := []struct {
		name       string
		params     []byte
		data       []byte
		useUnicode bool
		want       *TreeConnectResponse
		wantErr    bool
	}{
		{
			name: "valid response with ASCII",
			params: func() []byte {
				p := make([]byte, 6)
				p[0] = SMB_COM_NO_ANDX_COMMAND
				p[1] = 0
				binary.LittleEndian.PutUint16(p[2:4], 0)
				binary.LittleEndian.PutUint16(p[4:6], SMB_SUPPORT_SEARCH_BITS)
				return p
			}(),
			data: func() []byte {
				d := []byte("A:\x00") // Service
				d = append(d, []byte("NTFS\x00")...)
				return d
			}(),
			useUnicode: false,
			want: &TreeConnectResponse{
				AndXCommand:      SMB_COM_NO_ANDX_COMMAND,
				AndXReserved:     0,
				AndXOffset:       0,
				OptionalSupport:  SMB_SUPPORT_SEARCH_BITS,
				Service:          "A:",
				NativeFileSystem: "NTFS",
			},
			wantErr: false,
		},
		{
			name: "valid response with Unicode",
			params: func() []byte {
				p := make([]byte, 6)
				p[0] = SMB_COM_NO_ANDX_COMMAND
				binary.LittleEndian.PutUint16(p[2:4], 0)
				binary.LittleEndian.PutUint16(p[4:6], SMB_SHARE_IS_IN_DFS)
				return p
			}(),
			data: func() []byte {
				d := []byte("IPC\x00") // Service (always ASCII)
				// Add padding for alignment
				// "FAT" in UTF-16LE with null terminator
				d = append(d, 'F', 0, 'A', 0, 'T', 0, 0, 0)
				return d
			}(),
			useUnicode: true,
			want: &TreeConnectResponse{
				AndXCommand:      SMB_COM_NO_ANDX_COMMAND,
				OptionalSupport:  SMB_SHARE_IS_IN_DFS,
				Service:          "IPC",
				NativeFileSystem: "FAT",
			},
			wantErr: false,
		},
		{
			name:    "params too short",
			params:  make([]byte, 4),
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeTreeConnectResponse(tt.params, tt.data, tt.useUnicode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeTreeConnectResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.AndXCommand != tt.want.AndXCommand {
				t.Errorf("AndXCommand = 0x%02x, want 0x%02x", got.AndXCommand, tt.want.AndXCommand)
			}
			if got.OptionalSupport != tt.want.OptionalSupport {
				t.Errorf("OptionalSupport = 0x%04x, want 0x%04x", got.OptionalSupport, tt.want.OptionalSupport)
			}
			if got.Service != tt.want.Service {
				t.Errorf("Service = %q, want %q", got.Service, tt.want.Service)
			}
			if got.NativeFileSystem != tt.want.NativeFileSystem {
				t.Errorf("NativeFileSystem = %q, want %q", got.NativeFileSystem, tt.want.NativeFileSystem)
			}
		})
	}
}

func TestEncodeTreeDisconnectRequest(t *testing.T) {
	params, data, err := EncodeTreeDisconnectRequest()
	if err != nil {
		t.Fatalf("EncodeTreeDisconnectRequest() error = %v", err)
	}

	if len(params) != 0 {
		t.Errorf("params length = %d, want 0", len(params))
	}

	if len(data) != 0 {
		t.Errorf("data length = %d, want 0", len(data))
	}
}

func TestDecodeTreeDisconnectResponse(t *testing.T) {
	tests := []struct {
		name    string
		params  []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid empty response",
			params:  []byte{},
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "invalid response with params",
			params:  []byte{1, 2},
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "invalid response with data",
			params:  []byte{},
			data:    []byte{1, 2},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeTreeDisconnectResponse(tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeTreeDisconnectResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTreeConnectResponse_HasChaining(t *testing.T) {
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
			andXCommand: SMB_COM_NT_CREATE_ANDX,
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &TreeConnectResponse{AndXCommand: tt.andXCommand}
			if got := r.HasChaining(); got != tt.want {
				t.Errorf("HasChaining() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTreeConnectResponse_IsInDFS(t *testing.T) {
	tests := []struct {
		name            string
		optionalSupport uint16
		want            bool
	}{
		{
			name:            "is in DFS",
			optionalSupport: SMB_SHARE_IS_IN_DFS,
			want:            true,
		},
		{
			name:            "not in DFS",
			optionalSupport: SMB_SUPPORT_SEARCH_BITS,
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &TreeConnectResponse{OptionalSupport: tt.optionalSupport}
			if got := r.IsInDFS(); got != tt.want {
				t.Errorf("IsInDFS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTreeConnectResponse_SupportsSearchBits(t *testing.T) {
	tests := []struct {
		name            string
		optionalSupport uint16
		want            bool
	}{
		{
			name:            "supports search bits",
			optionalSupport: SMB_SUPPORT_SEARCH_BITS,
			want:            true,
		},
		{
			name:            "does not support search bits",
			optionalSupport: SMB_SHARE_IS_IN_DFS,
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &TreeConnectResponse{OptionalSupport: tt.optionalSupport}
			if got := r.SupportsSearchBits(); got != tt.want {
				t.Errorf("SupportsSearchBits() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTreeConnectResponse_String(t *testing.T) {
	resp := &TreeConnectResponse{
		OptionalSupport:  SMB_SHARE_IS_IN_DFS | SMB_SUPPORT_SEARCH_BITS,
		Service:          "A:",
		NativeFileSystem: "NTFS",
	}

	str := resp.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	t.Logf("String() = %s", str)
}

func TestTreeConnectRoundTrip(t *testing.T) {
	// Test ASCII round trip
	req := &TreeConnectRequest{
		AndXCommand: SMB_COM_NO_ANDX_COMMAND,
		Flags:       0,
		Path:        "\\\\192.168.1.100\\share",
		Service:     SERVICE_DISK_SHARE,
		UseUnicode:  false,
	}

	params, _, err := EncodeTreeConnectRequest(req)
	if err != nil {
		t.Fatalf("EncodeTreeConnectRequest() error = %v", err)
	}

	if len(params) != 8 {
		t.Errorf("params length = %d, want 8", len(params))
	}

	// Create mock response
	respParams := make([]byte, 6)
	respParams[0] = SMB_COM_NO_ANDX_COMMAND
	binary.LittleEndian.PutUint16(respParams[4:6], SMB_SUPPORT_SEARCH_BITS)

	respData := []byte("A:\x00NTFS\x00")

	resp, err := DecodeTreeConnectResponse(respParams, respData, false)
	if err != nil {
		t.Fatalf("DecodeTreeConnectResponse() error = %v", err)
	}

	if resp.Service != "A:" {
		t.Errorf("Service = %q, want %q", resp.Service, "A:")
	}
	if resp.NativeFileSystem != "NTFS" {
		t.Errorf("NativeFileSystem = %q, want %q", resp.NativeFileSystem, "NTFS")
	}
}

func TestTreeConnectUnicodeRoundTrip(t *testing.T) {
	// Test Unicode round trip
	req := &TreeConnectRequest{
		AndXCommand: SMB_COM_NO_ANDX_COMMAND,
		Flags:       TREE_CONNECT_ANDX_EXTENDED_RESPONSE,
		Path:        "\\\\server\\share$",
		Service:     SERVICE_IPC,
		UseUnicode:  true,
	}

	_, _, err := EncodeTreeConnectRequest(req)
	if err != nil {
		t.Fatalf("EncodeTreeConnectRequest() error = %v", err)
	}

	// Create mock response with Unicode
	respParams := make([]byte, 6)
	respParams[0] = SMB_COM_NO_ANDX_COMMAND
	binary.LittleEndian.PutUint16(respParams[4:6], 0)

	respData := []byte("IPC\x00")
	// No file system for IPC

	resp, err := DecodeTreeConnectResponse(respParams, respData, true)
	if err != nil {
		t.Fatalf("DecodeTreeConnectResponse() error = %v", err)
	}

	if resp.Service != "IPC" {
		t.Errorf("Service = %q, want %q", resp.Service, "IPC")
	}
}

func TestTreeDisconnectRoundTrip(t *testing.T) {
	params, data, err := EncodeTreeDisconnectRequest()
	if err != nil {
		t.Fatalf("EncodeTreeDisconnectRequest() error = %v", err)
	}

	_, err = DecodeTreeDisconnectResponse(params, data)
	if err != nil {
		t.Fatalf("DecodeTreeDisconnectResponse() error = %v", err)
	}
}
