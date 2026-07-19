package srvsvc

import (
	"bytes"
	"testing"

	"github.com/macourteau/smb1client/internal/dcerpc"
)

// TestEncodeNetShareEnumAllRequest tests the encoding of NetShareEnumAll requests.
func TestEncodeNetShareEnumAllRequest(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
		validate   func(t *testing.T, data []byte)
	}{
		{
			name:       "IP address",
			serverName: "198.51.100.2",
			validate: func(t *testing.T, data []byte) {
				offset := 0

				// Server name pointer (should be non-zero)
				serverPtr := dcerpc.UnmarshalUint32(data[offset : offset+4])
				if serverPtr == 0 {
					t.Error("Server name pointer should be non-zero")
				}
				offset += 4

				// CRITICAL: In NDR, top-level [in] pointer parameters have their deferred
				// data appear immediately after the referent ID.
				// Verify UNC name is encoded correctly (should be "\\198.51.100.2" in UTF-16LE)
				expectedName := "\\\\198.51.100.2"
				nameOffset := offset
				decodedName, err := dcerpc.UnmarshalConformantVaryingString(data, &nameOffset)
				if err != nil {
					t.Errorf("Failed to decode server name: %v", err)
				}
				if decodedName != expectedName {
					t.Errorf("Server name = %q, want %q", decodedName, expectedName)
				}
				// Align after the string (conformant varying strings need 4-byte alignment)
				offset = dcerpc.AlignOffset(nameOffset, dcerpc.Align4)

				// Level should be 1
				if len(data) < offset+4 {
					t.Fatal("Buffer too short for level")
				}
				level := dcerpc.UnmarshalUint32(data[offset : offset+4])
				if level != 1 {
					t.Errorf("Level = %d, want 1", level)
				}
				offset += 4

				// InfoStruct level should be 1
				if len(data) < offset+4 {
					t.Fatal("Buffer too short for infostruct level")
				}
				infoLevel := dcerpc.UnmarshalUint32(data[offset : offset+4])
				if infoLevel != 1 {
					t.Errorf("InfoStruct level = %d, want 1", infoLevel)
				}
				offset += 4

				// Container pointer should be non-zero
				if len(data) < offset+4 {
					t.Fatal("Buffer too short for container pointer")
				}
				containerPtr := dcerpc.UnmarshalUint32(data[offset : offset+4])
				if containerPtr == 0 {
					t.Error("Container pointer should be non-zero")
				}
				offset += 4

				// EntriesRead should be 0
				if len(data) < offset+4 {
					t.Fatal("Buffer too short for entries read")
				}
				entriesRead := dcerpc.UnmarshalUint32(data[offset : offset+4])
				if entriesRead != 0 {
					t.Errorf("EntriesRead = %d, want 0", entriesRead)
				}
				offset += 4

				// Buffer pointer should be null
				if len(data) < offset+4 {
					t.Fatal("Buffer too short for buffer pointer")
				}
				bufferPtr := dcerpc.UnmarshalUint32(data[offset : offset+4])
				if bufferPtr != 0 {
					t.Errorf("Buffer pointer = 0x%08x, want 0", bufferPtr)
				}
				offset += 4

				// PrefMaxLen should be 0xFFFFFFFF
				if len(data) < offset+4 {
					t.Fatal("Buffer too short for PrefMaxLen")
				}
				prefMaxLen := dcerpc.UnmarshalUint32(data[offset : offset+4])
				if prefMaxLen != 0xFFFFFFFF {
					t.Errorf("PrefMaxLen = 0x%08x, want 0xFFFFFFFF", prefMaxLen)
				}
				offset += 4

				// ResumeHandle pointer should be non-zero
				if len(data) < offset+4 {
					t.Fatal("Buffer too short for resume handle pointer")
				}
				resumePtr := dcerpc.UnmarshalUint32(data[offset : offset+4])
				if resumePtr == 0 {
					t.Error("Resume handle pointer should be non-zero")
				}
				offset += 4

				// DEFERRED DATA SECTION (for embedded pointers)
				// ResumeHandle value should be 0
				if len(data) < offset+4 {
					t.Fatal("Buffer too short for resume handle")
				}
				resumeHandle := dcerpc.UnmarshalUint32(data[offset : offset+4])
				if resumeHandle != 0 {
					t.Errorf("ResumeHandle = %d, want 0", resumeHandle)
				}
			},
		},
		{
			name:       "hostname",
			serverName: "TESTSERVER",
			validate: func(t *testing.T, data []byte) {
				// Just verify the encoding succeeds and contains expected server name
				// Full structure validation is done in IP address test
				if len(data) == 0 {
					t.Error("Encoded data is empty")
				}
			},
		},
		{
			name:       "already UNC format",
			serverName: "\\\\SERVER",
			validate: func(t *testing.T, data []byte) {
				// Just verify the encoding succeeds
				if len(data) == 0 {
					t.Error("Encoded data is empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := EncodeNetShareEnumAllRequest(tt.serverName)
			if len(data) == 0 {
				t.Fatal("EncodeNetShareEnumAllRequest returned empty data")
			}
			tt.validate(t, data)
		})
	}
}

// TestDecodeNetShareEnumAllResponse tests the decoding of NetShareEnumAll responses.
func TestDecodeNetShareEnumAllResponse(t *testing.T) {
	tests := []struct {
		name      string
		buildData func() []byte
		expected  []ShareInfo1
		wantErr   bool
	}{
		{
			name: "three shares",
			buildData: func() []byte {
				buf := make([]byte, 0, 1024)

				// Level: 1
				buf = append(buf, dcerpc.MarshalUint32(1)...)

				// InfoStruct Level: 1
				buf = append(buf, dcerpc.MarshalUint32(1)...)

				// Container pointer (non-null)
				buf = append(buf, dcerpc.MarshalUint32(0x00020000)...)

				// EntriesRead: 3
				buf = append(buf, dcerpc.MarshalUint32(3)...)

				// Buffer pointer (non-null)
				buf = append(buf, dcerpc.MarshalUint32(0x00020004)...)

				// Array conformance: 3
				buf = append(buf, dcerpc.MarshalUint32(3)...)

				// Share 1: "Disk Images"
				buf = append(buf, dcerpc.MarshalUint32(0x00020008)...) // Name pointer
				buf = append(buf, dcerpc.MarshalUint32(0)...)          // Type: disk
				buf = append(buf, dcerpc.MarshalUint32(0x0002000c)...) // Comment pointer

				// Share 2: "USB Images"
				buf = append(buf, dcerpc.MarshalUint32(0x00020010)...) // Name pointer
				buf = append(buf, dcerpc.MarshalUint32(0)...)          // Type: disk
				buf = append(buf, dcerpc.MarshalUint32(0x00020014)...) // Comment pointer

				// Share 3: "IPC$"
				buf = append(buf, dcerpc.MarshalUint32(0x00020018)...)                    // Name pointer
				buf = append(buf, dcerpc.MarshalUint32(ShareTypeIPC|ShareTypeSpecial)...) // Type: IPC | Special
				buf = append(buf, dcerpc.MarshalUint32(0x0002001c)...)                    // Comment pointer

				// Deferred strings (each string needs 4-byte alignment)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("Disk Images")...)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("Example NAS Internal Storage (Test)")...)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("USB Images")...)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("Example NAS USB Disk Storage (Test)")...)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("IPC$")...)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("IPC Service (Example NAS Test Server)")...)

				// Align before TotalEntries
				buf = dcerpc.Pad(buf, dcerpc.Align4)

				// TotalEntries: 3
				buf = append(buf, dcerpc.MarshalUint32(3)...)

				// ResumeHandle pointer (null)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// Return code: 0 (success)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				return buf
			},
			expected: []ShareInfo1{
				{Name: "Disk Images", Type: 0, Comment: "Example NAS Internal Storage (Test)"},
				{Name: "USB Images", Type: 0, Comment: "Example NAS USB Disk Storage (Test)"},
				{Name: "IPC$", Type: ShareTypeIPC | ShareTypeSpecial, Comment: "IPC Service (Example NAS Test Server)"},
			},
			wantErr: false,
		},
		{
			name: "empty share list",
			buildData: func() []byte {
				buf := make([]byte, 0, 64)

				// Level: 1
				buf = append(buf, dcerpc.MarshalUint32(1)...)

				// InfoStruct Level: 1
				buf = append(buf, dcerpc.MarshalUint32(1)...)

				// Container pointer (non-null)
				buf = append(buf, dcerpc.MarshalUint32(0x00020000)...)

				// EntriesRead: 0
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// Buffer pointer (null)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// TotalEntries: 0
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// ResumeHandle pointer (null)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// Return code: 0 (success)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				return buf
			},
			expected: []ShareInfo1{},
			wantErr:  false,
		},
		{
			name: "null container pointer",
			buildData: func() []byte {
				buf := make([]byte, 0, 32)

				// Level: 1
				buf = append(buf, dcerpc.MarshalUint32(1)...)

				// InfoStruct Level: 1
				buf = append(buf, dcerpc.MarshalUint32(1)...)

				// Container pointer (null)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// TotalEntries: 0
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// ResumeHandle pointer (null)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// Return code: 0 (success)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				return buf
			},
			expected: []ShareInfo1{},
			wantErr:  false,
		},
		{
			name: "error response",
			buildData: func() []byte {
				buf := make([]byte, 0, 32)

				// Level: 1
				buf = append(buf, dcerpc.MarshalUint32(1)...)

				// InfoStruct Level: 1
				buf = append(buf, dcerpc.MarshalUint32(1)...)

				// Container pointer (null)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// TotalEntries: 0
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// ResumeHandle pointer (null)
				buf = append(buf, dcerpc.MarshalUint32(0)...)

				// Return code: 0x00000005 (ERROR_ACCESS_DENIED)
				buf = append(buf, dcerpc.MarshalUint32(0x00000005)...)

				return buf
			},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.buildData()
			shares, err := DecodeNetShareEnumAllResponse(data)

			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeNetShareEnumAllResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(shares) != len(tt.expected) {
					t.Errorf("Got %d shares, want %d", len(shares), len(tt.expected))
					return
				}

				for i, share := range shares {
					expected := tt.expected[i]
					if share.Name != expected.Name {
						t.Errorf("Share %d: Name = %q, want %q", i, share.Name, expected.Name)
					}
					if share.Type != expected.Type {
						t.Errorf("Share %d: Type = 0x%08x, want 0x%08x", i, share.Type, expected.Type)
					}
					if share.Comment != expected.Comment {
						t.Errorf("Share %d: Comment = %q, want %q", i, share.Comment, expected.Comment)
					}
				}
			}
		})
	}
}

// TestShareTypes tests share type constants.
func TestShareTypes(t *testing.T) {
	tests := []struct {
		name      string
		shareType uint32
		expected  string
	}{
		{
			name:      "disk share",
			shareType: ShareTypeDisk,
			expected:  "Disk",
		},
		{
			name:      "print queue",
			shareType: ShareTypePrintQ,
			expected:  "PrintQueue",
		},
		{
			name:      "device",
			shareType: ShareTypeDevice,
			expected:  "Device",
		},
		{
			name:      "IPC",
			shareType: ShareTypeIPC,
			expected:  "IPC",
		},
		{
			name:      "special IPC",
			shareType: ShareTypeIPC | ShareTypeSpecial,
			expected:  "IPC|Special",
		},
		{
			name:      "temporary disk",
			shareType: ShareTypeDisk | ShareTypeTemporary,
			expected:  "Disk|Temporary",
		},
		{
			name:      "special temporary disk",
			shareType: ShareTypeDisk | ShareTypeSpecial | ShareTypeTemporary,
			expected:  "Disk|Special|Temporary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShareTypeName(tt.shareType)
			if result != tt.expected {
				t.Errorf("ShareTypeName(0x%08x) = %q, want %q", tt.shareType, result, tt.expected)
			}
		})
	}
}

// TestEncodeServerName tests server name encoding through the request encoder.
func TestEncodeServerName(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedName string
	}{
		{
			name:         "IP address",
			input:        "198.51.100.2",
			expectedName: "\\\\198.51.100.2",
		},
		{
			name:         "hostname",
			input:        "SERVER",
			expectedName: "\\\\SERVER",
		},
		{
			name:         "single backslash prefix",
			input:        "\\SERVER",
			expectedName: "\\\\SERVER",
		},
		{
			name:         "already UNC format",
			input:        "\\\\SERVER",
			expectedName: "\\\\SERVER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode using EncodeServerName helper
			encoded := EncodeServerName(tt.input)

			// Should start with non-zero pointer
			if len(encoded) < 4 {
				t.Fatal("Encoded data too short")
			}
			ptr := dcerpc.UnmarshalUint32(encoded[0:4])
			if ptr == 0 {
				t.Error("Server name pointer should be non-zero")
			}

			// Decode the string (immediately after pointer)
			offset := 4
			decoded, err := dcerpc.UnmarshalConformantVaryingString(encoded, &offset)
			if err != nil {
				t.Errorf("Failed to decode server name: %v", err)
			}

			if decoded != tt.expectedName {
				t.Errorf("Decoded name = %q, want %q", decoded, tt.expectedName)
			}
		})
	}
}

// TestDecodeShareInfo1Array tests array decoding.
func TestDecodeShareInfo1Array(t *testing.T) {
	tests := []struct {
		name      string
		buildData func() []byte
		count     uint32
		expected  []ShareInfo1
		wantErr   bool
	}{
		{
			name: "two shares",
			buildData: func() []byte {
				buf := make([]byte, 0, 512)

				// Array conformance: 2
				buf = append(buf, dcerpc.MarshalUint32(2)...)

				// Share 1: "Share1"
				buf = append(buf, dcerpc.MarshalUint32(0x00020000)...)    // Name pointer
				buf = append(buf, dcerpc.MarshalUint32(ShareTypeDisk)...) // Type
				buf = append(buf, dcerpc.MarshalUint32(0x00020004)...)    // Comment pointer

				// Share 2: "Share2"
				buf = append(buf, dcerpc.MarshalUint32(0x00020008)...)      // Name pointer
				buf = append(buf, dcerpc.MarshalUint32(ShareTypePrintQ)...) // Type
				buf = append(buf, dcerpc.MarshalUint32(0x0002000c)...)      // Comment pointer

				// Deferred strings (with alignment)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("Share1")...)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("Comment 1")...)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("Share2")...)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("Comment 2")...)

				return buf
			},
			count: 2,
			expected: []ShareInfo1{
				{Name: "Share1", Type: ShareTypeDisk, Comment: "Comment 1"},
				{Name: "Share2", Type: ShareTypePrintQ, Comment: "Comment 2"},
			},
			wantErr: false,
		},
		{
			name: "empty array",
			buildData: func() []byte {
				buf := make([]byte, 0, 4)
				// Array conformance: 0
				buf = append(buf, dcerpc.MarshalUint32(0)...)
				return buf
			},
			count:    0,
			expected: []ShareInfo1{},
			wantErr:  false,
		},
		{
			name: "null comment",
			buildData: func() []byte {
				buf := make([]byte, 0, 256)

				// Array conformance: 1
				buf = append(buf, dcerpc.MarshalUint32(1)...)

				// Share with null comment
				buf = append(buf, dcerpc.MarshalUint32(0x00020000)...)   // Name pointer
				buf = append(buf, dcerpc.MarshalUint32(ShareTypeIPC)...) // Type
				buf = append(buf, dcerpc.MarshalUint32(0)...)            // Comment pointer (null)

				// Deferred strings (with alignment)
				buf = dcerpc.Pad(buf, dcerpc.Align4)
				buf = append(buf, dcerpc.MarshalConformantVaryingString("IPC$")...)

				return buf
			},
			count: 1,
			expected: []ShareInfo1{
				{Name: "IPC$", Type: ShareTypeIPC, Comment: ""},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.buildData()
			offset := 0
			shares, err := DecodeShareInfo1Array(data, &offset, tt.count)

			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeShareInfo1Array() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(shares) != len(tt.expected) {
					t.Errorf("Got %d shares, want %d", len(shares), len(tt.expected))
					return
				}

				for i, share := range shares {
					expected := tt.expected[i]
					if share.Name != expected.Name {
						t.Errorf("Share %d: Name = %q, want %q", i, share.Name, expected.Name)
					}
					if share.Type != expected.Type {
						t.Errorf("Share %d: Type = 0x%08x, want 0x%08x", i, share.Type, expected.Type)
					}
					if share.Comment != expected.Comment {
						t.Errorf("Share %d: Comment = %q, want %q", i, share.Comment, expected.Comment)
					}
				}
			}
		})
	}
}

// TestRoundTrip tests encoding a request and decoding a mock response.
func TestRoundTrip(t *testing.T) {
	// Encode a request
	request := EncodeNetShareEnumAllRequest("198.51.100.2")
	if len(request) == 0 {
		t.Fatal("Failed to encode request")
	}

	// Build a mock response
	response := func() []byte {
		buf := make([]byte, 0, 512)

		// Level: 1
		buf = append(buf, dcerpc.MarshalUint32(1)...)

		// InfoStruct Level: 1
		buf = append(buf, dcerpc.MarshalUint32(1)...)

		// Container pointer (non-null)
		buf = append(buf, dcerpc.MarshalUint32(0x00020000)...)

		// EntriesRead: 2
		buf = append(buf, dcerpc.MarshalUint32(2)...)

		// Buffer pointer (non-null)
		buf = append(buf, dcerpc.MarshalUint32(0x00020004)...)

		// Array conformance: 2
		buf = append(buf, dcerpc.MarshalUint32(2)...)

		// Share 1
		buf = append(buf, dcerpc.MarshalUint32(0x00020008)...) // Name pointer
		buf = append(buf, dcerpc.MarshalUint32(0)...)          // Type
		buf = append(buf, dcerpc.MarshalUint32(0x0002000c)...) // Comment pointer

		// Share 2
		buf = append(buf, dcerpc.MarshalUint32(0x00020010)...)                    // Name pointer
		buf = append(buf, dcerpc.MarshalUint32(ShareTypeIPC|ShareTypeSpecial)...) // Type
		buf = append(buf, dcerpc.MarshalUint32(0x00020014)...)                    // Comment pointer

		// Deferred strings (with alignment)
		buf = dcerpc.Pad(buf, dcerpc.Align4)
		buf = append(buf, dcerpc.MarshalConformantVaryingString("TestShare")...)
		buf = dcerpc.Pad(buf, dcerpc.Align4)
		buf = append(buf, dcerpc.MarshalConformantVaryingString("Test share comment")...)
		buf = dcerpc.Pad(buf, dcerpc.Align4)
		buf = append(buf, dcerpc.MarshalConformantVaryingString("IPC$")...)
		buf = dcerpc.Pad(buf, dcerpc.Align4)
		buf = append(buf, dcerpc.MarshalConformantVaryingString("IPC Service")...)

		// Align before TotalEntries
		buf = dcerpc.Pad(buf, dcerpc.Align4)

		// TotalEntries: 2
		buf = append(buf, dcerpc.MarshalUint32(2)...)

		// ResumeHandle pointer (null)
		buf = append(buf, dcerpc.MarshalUint32(0)...)

		// Return code: 0
		buf = append(buf, dcerpc.MarshalUint32(0)...)

		return buf
	}()

	// Decode the response
	shares, err := DecodeNetShareEnumAllResponse(response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify results
	if len(shares) != 2 {
		t.Fatalf("Got %d shares, want 2", len(shares))
	}

	expected := []ShareInfo1{
		{Name: "TestShare", Type: 0, Comment: "Test share comment"},
		{Name: "IPC$", Type: ShareTypeIPC | ShareTypeSpecial, Comment: "IPC Service"},
	}

	for i, share := range shares {
		exp := expected[i]
		if share.Name != exp.Name {
			t.Errorf("Share %d: Name = %q, want %q", i, share.Name, exp.Name)
		}
		if share.Type != exp.Type {
			t.Errorf("Share %d: Type = 0x%08x, want 0x%08x", i, share.Type, exp.Type)
		}
		if share.Comment != exp.Comment {
			t.Errorf("Share %d: Comment = %q, want %q", i, share.Comment, exp.Comment)
		}
	}
}

// TestInterfaceConstants tests that the interface UUID and version are correct.
func TestInterfaceConstants(t *testing.T) {
	// Verify UUID matches expected value
	expected := []byte{
		0xc8, 0x4f, 0x32, 0x4b, // time_low
		0x70, 0x16, // time_mid
		0xd3, 0x01, // time_hi_and_version
		0x12, 0x78, // clock_seq
		0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88, // node
	}

	if !bytes.Equal(InterfaceUUID[:], expected) {
		t.Errorf("InterfaceUUID = %v, want %v", InterfaceUUID, expected)
	}

	// Verify version
	if InterfaceVersion != 0x00000003 {
		t.Errorf("InterfaceVersion = 0x%08x, want 0x00000003", InterfaceVersion)
	}

	// Verify operation number
	if OpNetShareEnumAll != 15 {
		t.Errorf("OpNetShareEnumAll = %d, want 15", OpNetShareEnumAll)
	}
}
