package smb1

import (
	"encoding/binary"
	"testing"
)

func TestEncodeNegotiateRequest(t *testing.T) {
	tests := []struct {
		name      string
		dialects  []string
		wantErr   bool
		checkData func(*testing.T, []byte)
	}{
		{
			name:     "default dialects",
			dialects: DefaultDialects,
			wantErr:  false,
			checkData: func(t *testing.T, data []byte) {
				// Should contain all three dialects with 0x02 prefix and null terminator
				expectedDialects := []string{"NT LM 0.12", "NT LANMAN 1.0", "LANMAN1.0"}
				offset := 0
				for _, dialect := range expectedDialects {
					if offset >= len(data) {
						t.Fatalf("data too short at offset %d", offset)
					}
					if data[offset] != 0x02 {
						t.Errorf("expected buffer format 0x02 at offset %d, got 0x%02x", offset, data[offset])
					}
					offset++
					dialectBytes := []byte(dialect)
					if offset+len(dialectBytes) >= len(data) {
						t.Fatalf("data too short for dialect %q at offset %d", dialect, offset)
					}
					for i, b := range dialectBytes {
						if data[offset+i] != b {
							t.Errorf("dialect mismatch at offset %d+%d: expected %q, got %q", offset, i, dialect, string(data[offset:offset+len(dialectBytes)]))
							break
						}
					}
					offset += len(dialectBytes)
					if data[offset] != 0x00 {
						t.Errorf("expected null terminator at offset %d, got 0x%02x", offset, data[offset])
					}
					offset++
				}
			},
		},
		{
			name:     "single dialect",
			dialects: []string{"NT LM 0.12"},
			wantErr:  false,
			checkData: func(t *testing.T, data []byte) {
				expected := []byte{0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00}
				if len(data) != len(expected) {
					t.Errorf("expected data length %d, got %d", len(expected), len(data))
				}
				for i := range expected {
					if i >= len(data) {
						break
					}
					if data[i] != expected[i] {
						t.Errorf("data mismatch at offset %d: expected 0x%02x, got 0x%02x", i, expected[i], data[i])
					}
				}
			},
		},
		{
			name:     "multiple dialects",
			dialects: []string{"PC NETWORK PROGRAM 1.0", "LANMAN1.0"},
			wantErr:  false,
			checkData: func(t *testing.T, data []byte) {
				// Check structure but not exact content
				if len(data) < 2 {
					t.Fatal("data too short")
				}
			},
		},
		{
			name:     "empty dialects",
			dialects: []string{},
			wantErr:  true,
		},
		{
			name:     "nil dialects",
			dialects: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeNegotiateRequest(tt.dialects)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeNegotiateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Params should be empty for negotiate
			if len(params) != 0 {
				t.Errorf("expected empty params, got %d bytes", len(params))
			}

			if tt.checkData != nil {
				tt.checkData(t, data)
			}
		})
	}
}

func TestDecodeNegotiateResponse(t *testing.T) {
	tests := []struct {
		name    string
		params  []byte
		data    []byte
		want    *NegotiateResponse
		wantErr bool
	}{
		{
			name: "valid NT LM 0.12 response with unicode",
			params: func() []byte {
				p := make([]byte, 34)
				binary.LittleEndian.PutUint16(p[0:2], 5)                                         // DialectIndex
				p[2] = NEGOTIATE_USER_SECURITY | NEGOTIATE_ENCRYPT_PASSWORDS                     // SecurityMode
				binary.LittleEndian.PutUint16(p[3:5], 50)                                        // MaxMpxCount
				binary.LittleEndian.PutUint16(p[5:7], 1)                                         // MaxNumberVcs
				binary.LittleEndian.PutUint32(p[7:11], 16644)                                    // MaxBufferSize
				binary.LittleEndian.PutUint32(p[11:15], 65536)                                   // MaxRawSize
				binary.LittleEndian.PutUint32(p[15:19], 0)                                       // SessionKey
				binary.LittleEndian.PutUint32(p[19:23], CAP_UNICODE|CAP_LARGE_FILES|CAP_NT_SMBS) // Capabilities
				binary.LittleEndian.PutUint64(p[23:31], 0)                                       // SystemTime
				binary.LittleEndian.PutUint16(p[31:33], 0)                                       // ServerTimeZone
				p[33] = 8                                                                        // ChallengeLength
				return p
			}(),
			data: func() []byte {
				// Challenge (8 bytes) + domain (UTF-16LE "WORKGROUP\0") + server (UTF-16LE "SERVER\0")
				d := make([]byte, 8)
				for i := range d {
					d[i] = byte(i + 1)
				}
				// Add "WORKGROUP" in UTF-16LE with null terminator
				domain := []byte{
					'W', 0, 'O', 0, 'R', 0, 'K', 0, 'G', 0, 'R', 0, 'O', 0, 'U', 0, 'P', 0, 0, 0,
				}
				d = append(d, domain...)
				// Add "SERVER" in UTF-16LE with null terminator
				server := []byte{
					'S', 0, 'E', 0, 'R', 0, 'V', 0, 'E', 0, 'R', 0, 0, 0,
				}
				d = append(d, server...)
				return d
			}(),
			want: &NegotiateResponse{
				DialectIndex:    5,
				SecurityMode:    NEGOTIATE_USER_SECURITY | NEGOTIATE_ENCRYPT_PASSWORDS,
				MaxMpxCount:     50,
				MaxNumberVcs:    1,
				MaxBufferSize:   16644,
				MaxRawSize:      65536,
				SessionKey:      0,
				Capabilities:    CAP_UNICODE | CAP_LARGE_FILES | CAP_NT_SMBS,
				SystemTime:      0,
				ServerTimeZone:  0,
				ChallengeLength: 8,
				Challenge:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
				DomainName:      "WORKGROUP",
				ServerName:      "SERVER",
			},
			wantErr: false,
		},
		{
			name: "valid NT LM 0.12 response with ASCII",
			params: func() []byte {
				p := make([]byte, 34)
				binary.LittleEndian.PutUint16(p[0:2], 0)             // DialectIndex
				p[2] = NEGOTIATE_USER_SECURITY                       // SecurityMode
				binary.LittleEndian.PutUint16(p[3:5], 10)            // MaxMpxCount
				binary.LittleEndian.PutUint16(p[5:7], 1)             // MaxNumberVcs
				binary.LittleEndian.PutUint32(p[7:11], 4356)         // MaxBufferSize
				binary.LittleEndian.PutUint32(p[11:15], 65535)       // MaxRawSize
				binary.LittleEndian.PutUint32(p[15:19], 0)           // SessionKey
				binary.LittleEndian.PutUint32(p[19:23], CAP_NT_SMBS) // Capabilities (no unicode)
				binary.LittleEndian.PutUint64(p[23:31], 0)           // SystemTime
				// ServerTimeZone is int16, -60 minutes from UTC
				timeZone := int16(-60)
				binary.LittleEndian.PutUint16(p[31:33], uint16(timeZone))
				p[33] = 8 // ChallengeLength
				return p
			}(),
			data: func() []byte {
				d := make([]byte, 8)
				for i := range d {
					d[i] = byte(i)
				}
				d = append(d, []byte("DOMAIN\x00")...)
				d = append(d, []byte("SVR\x00")...)
				return d
			}(),
			want: &NegotiateResponse{
				DialectIndex:    0,
				SecurityMode:    NEGOTIATE_USER_SECURITY,
				MaxMpxCount:     10,
				MaxNumberVcs:    1,
				MaxBufferSize:   4356,
				MaxRawSize:      65535,
				SessionKey:      0,
				Capabilities:    CAP_NT_SMBS,
				SystemTime:      0,
				ServerTimeZone:  -60,
				ChallengeLength: 8,
				Challenge:       []byte{0, 1, 2, 3, 4, 5, 6, 7},
				DomainName:      "DOMAIN",
				ServerName:      "SVR",
			},
			wantErr: false,
		},
		{
			name: "dialect not supported",
			params: func() []byte {
				p := make([]byte, 34)
				binary.LittleEndian.PutUint16(p[0:2], 0xFFFF) // DialectIndex = -1
				p[33] = 0                                     // ChallengeLength
				return p
			}(),
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "params too short",
			params:  make([]byte, 20),
			data:    []byte{},
			wantErr: true,
		},
		{
			name: "data too short for challenge",
			params: func() []byte {
				p := make([]byte, 34)
				binary.LittleEndian.PutUint16(p[0:2], 0) // DialectIndex
				p[33] = 8                                // ChallengeLength
				return p
			}(),
			data:    make([]byte, 4), // Only 4 bytes, need 8
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeNegotiateResponse(tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeNegotiateResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.DialectIndex != tt.want.DialectIndex {
				t.Errorf("DialectIndex = %d, want %d", got.DialectIndex, tt.want.DialectIndex)
			}
			if got.SecurityMode != tt.want.SecurityMode {
				t.Errorf("SecurityMode = 0x%02x, want 0x%02x", got.SecurityMode, tt.want.SecurityMode)
			}
			if got.MaxMpxCount != tt.want.MaxMpxCount {
				t.Errorf("MaxMpxCount = %d, want %d", got.MaxMpxCount, tt.want.MaxMpxCount)
			}
			if got.MaxNumberVcs != tt.want.MaxNumberVcs {
				t.Errorf("MaxNumberVcs = %d, want %d", got.MaxNumberVcs, tt.want.MaxNumberVcs)
			}
			if got.MaxBufferSize != tt.want.MaxBufferSize {
				t.Errorf("MaxBufferSize = %d, want %d", got.MaxBufferSize, tt.want.MaxBufferSize)
			}
			if got.MaxRawSize != tt.want.MaxRawSize {
				t.Errorf("MaxRawSize = %d, want %d", got.MaxRawSize, tt.want.MaxRawSize)
			}
			if got.SessionKey != tt.want.SessionKey {
				t.Errorf("SessionKey = %d, want %d", got.SessionKey, tt.want.SessionKey)
			}
			if got.Capabilities != tt.want.Capabilities {
				t.Errorf("Capabilities = 0x%08x, want 0x%08x", got.Capabilities, tt.want.Capabilities)
			}
			if got.ChallengeLength != tt.want.ChallengeLength {
				t.Errorf("ChallengeLength = %d, want %d", got.ChallengeLength, tt.want.ChallengeLength)
			}
			if len(got.Challenge) != len(tt.want.Challenge) {
				t.Errorf("Challenge length = %d, want %d", len(got.Challenge), len(tt.want.Challenge))
			} else {
				for i := range got.Challenge {
					if got.Challenge[i] != tt.want.Challenge[i] {
						t.Errorf("Challenge[%d] = 0x%02x, want 0x%02x", i, got.Challenge[i], tt.want.Challenge[i])
					}
				}
			}
			if got.DomainName != tt.want.DomainName {
				t.Errorf("DomainName = %q, want %q", got.DomainName, tt.want.DomainName)
			}
			if got.ServerName != tt.want.ServerName {
				t.Errorf("ServerName = %q, want %q", got.ServerName, tt.want.ServerName)
			}
		})
	}
}

func TestNegotiateResponse_SupportsExtendedSecurity(t *testing.T) {
	tests := []struct {
		name         string
		capabilities uint32
		want         bool
	}{
		{
			name:         "supports extended security",
			capabilities: CAP_EXTENDED_SECURITY | CAP_UNICODE,
			want:         true,
		},
		{
			name:         "does not support extended security",
			capabilities: CAP_UNICODE | CAP_LARGE_FILES,
			want:         false,
		},
		{
			name:         "no capabilities",
			capabilities: 0,
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &NegotiateResponse{Capabilities: tt.capabilities}
			if got := r.SupportsExtendedSecurity(); got != tt.want {
				t.Errorf("SupportsExtendedSecurity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNegotiateResponse_SupportsUnicode(t *testing.T) {
	tests := []struct {
		name         string
		capabilities uint32
		want         bool
	}{
		{
			name:         "supports unicode",
			capabilities: CAP_UNICODE | CAP_LARGE_FILES,
			want:         true,
		},
		{
			name:         "does not support unicode",
			capabilities: CAP_LARGE_FILES | CAP_NT_SMBS,
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &NegotiateResponse{Capabilities: tt.capabilities}
			if got := r.SupportsUnicode(); got != tt.want {
				t.Errorf("SupportsUnicode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNegotiateResponse_SupportsLargeFiles(t *testing.T) {
	tests := []struct {
		name         string
		capabilities uint32
		want         bool
	}{
		{
			name:         "supports large files",
			capabilities: CAP_LARGE_FILES | CAP_UNICODE,
			want:         true,
		},
		{
			name:         "does not support large files",
			capabilities: CAP_UNICODE | CAP_NT_SMBS,
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &NegotiateResponse{Capabilities: tt.capabilities}
			if got := r.SupportsLargeFiles(); got != tt.want {
				t.Errorf("SupportsLargeFiles() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNegotiateResponse_RequiresEncryption(t *testing.T) {
	tests := []struct {
		name         string
		securityMode uint8
		want         bool
	}{
		{
			name:         "requires encryption",
			securityMode: NEGOTIATE_USER_SECURITY | NEGOTIATE_ENCRYPT_PASSWORDS,
			want:         true,
		},
		{
			name:         "does not require encryption",
			securityMode: NEGOTIATE_USER_SECURITY,
			want:         false,
		},
		{
			name:         "no security mode",
			securityMode: 0,
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &NegotiateResponse{SecurityMode: tt.securityMode}
			if got := r.RequiresEncryption(); got != tt.want {
				t.Errorf("RequiresEncryption() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNegotiateResponse_String(t *testing.T) {
	resp := &NegotiateResponse{
		DialectIndex:    5,
		SecurityMode:    0x03,
		MaxMpxCount:     50,
		MaxBufferSize:   16644,
		Capabilities:    CAP_UNICODE | CAP_LARGE_FILES,
		Challenge:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		DomainName:      "WORKGROUP",
		ServerName:      "SERVER",
		ChallengeLength: 8,
	}

	str := resp.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	t.Logf("String() = %s", str)
}

func TestNegotiateRoundTrip(t *testing.T) {
	// Test that we can encode a request and decode a response
	dialects := DefaultDialects
	params, data, err := EncodeNegotiateRequest(dialects)
	if err != nil {
		t.Fatalf("EncodeNegotiateRequest() error = %v", err)
	}

	// Verify params is empty
	if len(params) != 0 {
		t.Errorf("expected empty params, got %d bytes", len(params))
	}

	// Verify data contains dialects
	if len(data) == 0 {
		t.Fatal("expected non-empty data")
	}

	// Create a mock response
	respParams := make([]byte, 34)
	binary.LittleEndian.PutUint16(respParams[0:2], 0) // Select first dialect
	respParams[2] = NEGOTIATE_USER_SECURITY | NEGOTIATE_ENCRYPT_PASSWORDS
	binary.LittleEndian.PutUint16(respParams[3:5], 50)
	binary.LittleEndian.PutUint16(respParams[5:7], 1)
	binary.LittleEndian.PutUint32(respParams[7:11], 16644)
	binary.LittleEndian.PutUint32(respParams[11:15], 65536)
	binary.LittleEndian.PutUint32(respParams[15:19], 0)
	binary.LittleEndian.PutUint32(respParams[19:23], CAP_UNICODE|CAP_LARGE_FILES|CAP_NT_SMBS|CAP_EXTENDED_SECURITY)
	binary.LittleEndian.PutUint64(respParams[23:31], 0)
	binary.LittleEndian.PutUint16(respParams[31:33], 0)
	respParams[33] = 8

	respData := make([]byte, 8)
	for i := range respData {
		respData[i] = byte(i + 1)
	}

	resp, err := DecodeNegotiateResponse(respParams, respData)
	if err != nil {
		t.Fatalf("DecodeNegotiateResponse() error = %v", err)
	}

	if resp.DialectIndex != 0 {
		t.Errorf("DialectIndex = %d, want 0", resp.DialectIndex)
	}

	if !resp.SupportsExtendedSecurity() {
		t.Error("expected server to support extended security")
	}

	if !resp.SupportsUnicode() {
		t.Error("expected server to support Unicode")
	}

	if !resp.SupportsLargeFiles() {
		t.Error("expected server to support large files")
	}

	if !resp.RequiresEncryption() {
		t.Error("expected server to require encryption")
	}
}
