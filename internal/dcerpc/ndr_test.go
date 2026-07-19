package dcerpc

import (
	"bytes"
	"testing"
)

// TestMarshalUint tests integer marshaling
func TestMarshalUint(t *testing.T) {
	tests := []struct {
		name     string
		marshal  func() []byte
		expected []byte
	}{
		{
			name:     "uint16 1234",
			marshal:  func() []byte { return MarshalUint16(1234) },
			expected: []byte{0xd2, 0x04},
		},
		{
			name:     "uint32 12345678",
			marshal:  func() []byte { return MarshalUint32(12345678) },
			expected: []byte{0x4e, 0x61, 0xbc, 0x00},
		},
		{
			name:     "uint64 1234567890",
			marshal:  func() []byte { return MarshalUint64(1234567890) },
			expected: []byte{0xd2, 0x02, 0x96, 0x49, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.marshal()
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("marshal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestUnmarshalUint tests integer unmarshaling
func TestUnmarshalUint(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		unmarshal func([]byte) interface{}
		expected  interface{}
	}{
		{
			name:      "uint16 1234",
			data:      []byte{0xd2, 0x04},
			unmarshal: func(b []byte) interface{} { return UnmarshalUint16(b) },
			expected:  uint16(1234),
		},
		{
			name:      "uint32 12345678",
			data:      []byte{0x4e, 0x61, 0xbc, 0x00},
			unmarshal: func(b []byte) interface{} { return UnmarshalUint32(b) },
			expected:  uint32(12345678),
		},
		{
			name:      "uint64 1234567890",
			data:      []byte{0xd2, 0x02, 0x96, 0x49, 0x00, 0x00, 0x00, 0x00},
			unmarshal: func(b []byte) interface{} { return UnmarshalUint64(b) },
			expected:  uint64(1234567890),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.unmarshal(tt.data)
			if result != tt.expected {
				t.Errorf("unmarshal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestMarshalConformantVaryingString tests Unicode string marshaling
func TestMarshalConformantVaryingString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		validate func([]byte) bool
	}{
		{
			name:  "simple ASCII string",
			input: "hello",
			validate: func(b []byte) bool {
				// Check header (12 bytes)
				if len(b) < 12 {
					return false
				}
				// MaxCount should be 6 (5 chars + null terminator)
				maxCount := UnmarshalUint32(b[0:4])
				if maxCount != 6 {
					return false
				}
				// Offset should be 0
				offset := UnmarshalUint32(b[4:8])
				if offset != 0 {
					return false
				}
				// ActualCount should be 6
				actualCount := UnmarshalUint32(b[8:12])
				if actualCount != 6 {
					return false
				}
				// Check data length (6 UTF-16 chars = 12 bytes)
				expectedLen := 12 + 12
				return len(b) == expectedLen
			},
		},
		{
			name:  "empty string",
			input: "",
			validate: func(b []byte) bool {
				// Check header
				if len(b) < 12 {
					return false
				}
				// MaxCount should be 1 (just null terminator)
				maxCount := UnmarshalUint32(b[0:4])
				if maxCount != 1 {
					return false
				}
				// ActualCount should be 1
				actualCount := UnmarshalUint32(b[8:12])
				if actualCount != 1 {
					return false
				}
				// Total length: 12 (header) + 2 (null terminator)
				return len(b) == 14
			},
		},
		{
			name:  "Unicode string",
			input: "hello世界",
			validate: func(b []byte) bool {
				// Check header
				if len(b) < 12 {
					return false
				}
				// MaxCount should include all characters + null terminator
				maxCount := UnmarshalUint32(b[0:4])
				// "hello" (5) + "世界" (2) + null (1) = 8
				if maxCount != 8 {
					return false
				}
				return true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MarshalConformantVaryingString(tt.input)
			if !tt.validate(result) {
				t.Errorf("MarshalConformantVaryingString() validation failed for input %q", tt.input)
				t.Logf("Result length: %d bytes", len(result))
				t.Logf("Result: %v", result)
			}
		})
	}
}

// TestUnmarshalConformantVaryingString tests Unicode string unmarshaling
func TestUnmarshalConformantVaryingString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "simple ASCII string",
			input:   "hello",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: false,
		},
		{
			name:    "Unicode string",
			input:   "hello世界",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			marshaled := MarshalConformantVaryingString(tt.input)

			// Unmarshal
			offset := 0
			result, err := UnmarshalConformantVaryingString(marshaled, &offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalConformantVaryingString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result != tt.input {
				t.Errorf("UnmarshalConformantVaryingString() = %q, want %q", result, tt.input)
			}
		})
	}
}

// TestMarshalPointer tests pointer marshaling
func TestMarshalPointer(t *testing.T) {
	tests := []struct {
		name       string
		referentID uint32
		data       []byte
		validate   func([]byte) bool
	}{
		{
			name:       "null pointer",
			referentID: 0,
			data:       nil,
			validate: func(b []byte) bool {
				// Should be just 4 bytes (referent ID = 0)
				if len(b) != 4 {
					return false
				}
				return UnmarshalUint32(b) == 0
			},
		},
		{
			name:       "non-null pointer",
			referentID: 0x00020000,
			data:       []byte{0x01, 0x02, 0x03, 0x04},
			validate: func(b []byte) bool {
				// Should be 4 bytes (referent ID) + 4 bytes (data)
				if len(b) != 8 {
					return false
				}
				// Check referent ID
				if UnmarshalUint32(b[0:4]) != 0x00020000 {
					return false
				}
				// Check data
				return bytes.Equal(b[4:8], []byte{0x01, 0x02, 0x03, 0x04})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MarshalPointer(tt.referentID, tt.data)
			if !tt.validate(result) {
				t.Errorf("MarshalPointer() validation failed")
				t.Logf("Result: %v", result)
			}
		})
	}
}

// TestUnmarshalPointer tests pointer unmarshaling
func TestUnmarshalPointer(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint32
		wantErr  bool
	}{
		{
			name:     "null pointer",
			data:     []byte{0x00, 0x00, 0x00, 0x00},
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "non-null pointer",
			data:     []byte{0x00, 0x00, 0x02, 0x00},
			expected: 0x00020000,
			wantErr:  false,
		},
		{
			name:     "buffer too short",
			data:     []byte{0x00, 0x00},
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset := 0
			result, err := UnmarshalPointer(tt.data, &offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalPointer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("UnmarshalPointer() = 0x%08x, want 0x%08x", result, tt.expected)
			}
		})
	}
}

// TestAlignOffset tests alignment calculation
func TestAlignOffset(t *testing.T) {
	tests := []struct {
		offset    int
		alignment int
		expected  int
	}{
		{0, 4, 0},
		{1, 4, 4},
		{2, 4, 4},
		{3, 4, 4},
		{4, 4, 4},
		{5, 4, 8},
		{0, 8, 0},
		{1, 8, 8},
		{7, 8, 8},
		{8, 8, 8},
		{9, 8, 16},
		{10, 2, 10},
		{11, 2, 12},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := AlignOffset(tt.offset, tt.alignment)
			if result != tt.expected {
				t.Errorf("AlignOffset(%d, %d) = %d, want %d", tt.offset, tt.alignment, result, tt.expected)
			}
		})
	}
}

// TestPad tests padding function
func TestPad(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		alignment int
		expected  int
	}{
		{
			name:      "already aligned",
			input:     make([]byte, 4),
			alignment: 4,
			expected:  4,
		},
		{
			name:      "needs padding",
			input:     make([]byte, 5),
			alignment: 4,
			expected:  8,
		},
		{
			name:      "needs padding to 8",
			input:     make([]byte, 10),
			alignment: 8,
			expected:  16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Pad(tt.input, tt.alignment)
			if len(result) != tt.expected {
				t.Errorf("Pad() length = %d, want %d", len(result), tt.expected)
			}
		})
	}
}

// TestMarshalUniquePointer tests unique pointer marshaling
func TestMarshalUniquePointer(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		isNull bool
	}{
		{
			name:   "null pointer",
			data:   nil,
			isNull: true,
		},
		{
			name:   "empty data",
			data:   []byte{},
			isNull: true,
		},
		{
			name:   "non-null pointer",
			data:   []byte{0x01, 0x02, 0x03, 0x04},
			isNull: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MarshalUniquePointer(tt.data)
			referentID := UnmarshalUint32(result[0:4])

			if tt.isNull {
				if referentID != 0 {
					t.Errorf("MarshalUniquePointer() referent ID = 0x%08x, want 0 for null pointer", referentID)
				}
			} else {
				if referentID == 0 {
					t.Errorf("MarshalUniquePointer() referent ID = 0, want non-zero for non-null pointer")
				}
				if !bytes.Equal(result[4:], tt.data) {
					t.Errorf("MarshalUniquePointer() data mismatch")
				}
			}
		})
	}
}
