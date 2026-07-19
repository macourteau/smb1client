package utf16le

import (
	"bytes"
	"strings"
	"testing"
)

// TestEncodedStringLen tests the EncodedStringLen function with various inputs
func TestEncodedStringLen(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "empty string",
			input:    "",
			expected: 0,
		},
		{
			name:     "ascii string",
			input:    "hello",
			expected: 10, // 5 chars * 2 bytes each
		},
		{
			name:     "single ascii char",
			input:    "A",
			expected: 2,
		},
		{
			name:     "ascii with spaces",
			input:    "Hello World",
			expected: 22, // 11 chars * 2 bytes each
		},
		{
			name:     "latin extended",
			input:    "Café",
			expected: 8, // 4 chars * 2 bytes each
		},
		{
			name:     "chinese characters",
			input:    "你好",
			expected: 4, // 2 chars * 2 bytes each
		},
		{
			name:     "cyrillic",
			input:    "Привет",
			expected: 12, // 6 chars * 2 bytes each
		},
		{
			name:     "arabic",
			input:    "مرحبا",
			expected: 10, // 5 chars * 2 bytes each
		},
		{
			name:     "emoji basic",
			input:    "😀",
			expected: 4, // 1 emoji requires surrogate pair (4 bytes)
		},
		{
			name:     "emoji complex",
			input:    "😀🎉",
			expected: 8, // 2 emojis * 4 bytes each
		},
		{
			name:     "mixed ascii and unicode",
			input:    "Hello 你好",
			expected: 16, // 6 ascii chars + space (14 bytes) + 2 chinese chars (4 bytes) = 8 UTF-16 units
		},
		{
			name:     "mixed with emoji",
			input:    "Hello 🌍",
			expected: 16, // 6 ascii chars (12 bytes) + 1 emoji (4 bytes)
		},
		{
			name:     "string with newline",
			input:    "line1\nline2",
			expected: 22, // 11 chars * 2 bytes each
		},
		{
			name:     "string with tab",
			input:    "col1\tcol2",
			expected: 18, // 9 chars * 2 bytes each
		},
		{
			name:     "very long ascii string",
			input:    strings.Repeat("A", 1000),
			expected: 2000,
		},
		{
			name:     "very long unicode string",
			input:    strings.Repeat("你", 1000),
			expected: 2000,
		},
		{
			name:     "all surrogate pair chars",
			input:    "𝕳𝖊𝖑𝖑𝖔", // Mathematical Fraktur characters
			expected: 20,      // 5 chars * 4 bytes each (all in supplementary plane)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodedStringLen(tt.input)
			if got != tt.expected {
				t.Errorf("EncodedStringLen(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

// TestEncodeString tests the EncodeString function with various inputs
func TestEncodeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []byte{},
		},
		{
			name:  "single ascii char",
			input: "A",
			expected: []byte{
				0x41, 0x00, // 'A' = U+0041
			},
		},
		{
			name:  "ascii string",
			input: "hello",
			expected: []byte{
				0x68, 0x00, // 'h'
				0x65, 0x00, // 'e'
				0x6c, 0x00, // 'l'
				0x6c, 0x00, // 'l'
				0x6f, 0x00, // 'o'
			},
		},
		{
			name:  "Hello World",
			input: "Hello World",
			expected: []byte{
				0x48, 0x00, // 'H'
				0x65, 0x00, // 'e'
				0x6c, 0x00, // 'l'
				0x6c, 0x00, // 'l'
				0x6f, 0x00, // 'o'
				0x20, 0x00, // ' '
				0x57, 0x00, // 'W'
				0x6f, 0x00, // 'o'
				0x72, 0x00, // 'r'
				0x6c, 0x00, // 'l'
				0x64, 0x00, // 'd'
			},
		},
		{
			name:  "latin extended",
			input: "Café",
			expected: []byte{
				0x43, 0x00, // 'C'
				0x61, 0x00, // 'a'
				0x66, 0x00, // 'f'
				0xe9, 0x00, // 'é' = U+00E9
			},
		},
		{
			name:  "chinese characters",
			input: "你好",
			expected: []byte{
				0x60, 0x4f, // '你' = U+4F60
				0x7d, 0x59, // '好' = U+597D
			},
		},
		{
			name:  "cyrillic",
			input: "Привет",
			expected: []byte{
				0x1f, 0x04, // 'П' = U+041F
				0x40, 0x04, // 'р' = U+0440
				0x38, 0x04, // 'и' = U+0438
				0x32, 0x04, // 'в' = U+0432
				0x35, 0x04, // 'е' = U+0435
				0x42, 0x04, // 'т' = U+0442
			},
		},
		{
			name:  "emoji",
			input: "😀",
			expected: []byte{
				0x3d, 0xd8, // high surrogate
				0x00, 0xde, // low surrogate
			},
		},
		{
			name:  "string with newline",
			input: "line1\nline2",
			expected: []byte{
				0x6c, 0x00, // 'l'
				0x69, 0x00, // 'i'
				0x6e, 0x00, // 'n'
				0x65, 0x00, // 'e'
				0x31, 0x00, // '1'
				0x0a, 0x00, // '\n'
				0x6c, 0x00, // 'l'
				0x69, 0x00, // 'i'
				0x6e, 0x00, // 'n'
				0x65, 0x00, // 'e'
				0x32, 0x00, // '2'
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Allocate buffer with exact size
			dst := make([]byte, EncodedStringLen(tt.input))
			n := EncodeString(dst, tt.input)

			if n != len(tt.expected) {
				t.Errorf("EncodeString(%q) returned %d bytes, want %d", tt.input, n, len(tt.expected))
			}

			if !bytes.Equal(dst, tt.expected) {
				t.Errorf("EncodeString(%q) = %v, want %v", tt.input, dst, tt.expected)
			}
		})
	}
}

// TestEncodeStringBufferSizes tests EncodeString with various buffer sizes
func TestEncodeStringBufferSizes(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		bufferSize int
		wantBytes  int
	}{
		{
			name:       "exact size buffer",
			input:      "hello",
			bufferSize: 10,
			wantBytes:  10,
		},
		{
			name:       "oversized buffer",
			input:      "hi",
			bufferSize: 100,
			wantBytes:  4,
		},
		{
			name:       "empty string with buffer",
			input:      "",
			bufferSize: 10,
			wantBytes:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := make([]byte, tt.bufferSize)
			n := EncodeString(dst, tt.input)

			if n != tt.wantBytes {
				t.Errorf("EncodeString(%q) returned %d bytes, want %d", tt.input, n, tt.wantBytes)
			}

			// Verify round-trip
			decoded := DecodeToString(dst[:n])
			if decoded != tt.input {
				t.Errorf("Round-trip failed: got %q, want %q", decoded, tt.input)
			}
		})
	}
}

// TestEncodeStringToBytes tests the EncodeStringToBytes function
func TestEncodeStringToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "empty string returns nil",
			input:    "",
			expected: nil,
		},
		{
			name:  "single char",
			input: "A",
			expected: []byte{
				0x41, 0x00,
			},
		},
		{
			name:  "ascii string",
			input: "hello",
			expected: []byte{
				0x68, 0x00, // 'h'
				0x65, 0x00, // 'e'
				0x6c, 0x00, // 'l'
				0x6c, 0x00, // 'l'
				0x6f, 0x00, // 'o'
			},
		},
		{
			name:  "unicode string",
			input: "你好",
			expected: []byte{
				0x60, 0x4f, // '你' = U+4F60
				0x7d, 0x59, // '好' = U+597D
			},
		},
		{
			name:  "emoji",
			input: "🎉",
			expected: []byte{
				0x3c, 0xd8, // high surrogate
				0x89, 0xdf, // low surrogate
			},
		},
		{
			name:  "mixed content",
			input: "Hi 你",
			expected: []byte{
				0x48, 0x00, // 'H'
				0x69, 0x00, // 'i'
				0x20, 0x00, // ' '
				0x60, 0x4f, // '你'
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeStringToBytes(tt.input)

			if !bytes.Equal(got, tt.expected) {
				t.Errorf("EncodeStringToBytes(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// TestDecodeToString tests the DecodeToString function
func TestDecodeToString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty bytes",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "nil bytes",
			input:    nil,
			expected: "",
		},
		{
			name: "single ascii char",
			input: []byte{
				0x41, 0x00, // 'A'
			},
			expected: "A",
		},
		{
			name: "ascii string",
			input: []byte{
				0x68, 0x00, // 'h'
				0x65, 0x00, // 'e'
				0x6c, 0x00, // 'l'
				0x6c, 0x00, // 'l'
				0x6f, 0x00, // 'o'
			},
			expected: "hello",
		},
		{
			name: "Hello World",
			input: []byte{
				0x48, 0x00, // 'H'
				0x65, 0x00, // 'e'
				0x6c, 0x00, // 'l'
				0x6c, 0x00, // 'l'
				0x6f, 0x00, // 'o'
				0x20, 0x00, // ' '
				0x57, 0x00, // 'W'
				0x6f, 0x00, // 'o'
				0x72, 0x00, // 'r'
				0x6c, 0x00, // 'l'
				0x64, 0x00, // 'd'
			},
			expected: "Hello World",
		},
		{
			name: "latin extended",
			input: []byte{
				0x43, 0x00, // 'C'
				0x61, 0x00, // 'a'
				0x66, 0x00, // 'f'
				0xe9, 0x00, // 'é'
			},
			expected: "Café",
		},
		{
			name: "chinese characters",
			input: []byte{
				0x60, 0x4f, // '你'
				0x7d, 0x59, // '好'
			},
			expected: "你好",
		},
		{
			name: "cyrillic",
			input: []byte{
				0x1f, 0x04, // 'П'
				0x40, 0x04, // 'р'
				0x38, 0x04, // 'и'
				0x32, 0x04, // 'в'
				0x35, 0x04, // 'е'
				0x42, 0x04, // 'т'
			},
			expected: "Привет",
		},
		{
			name: "emoji",
			input: []byte{
				0x3d, 0xd8, // high surrogate
				0x00, 0xde, // low surrogate
			},
			expected: "😀",
		},
		{
			name: "null terminated string",
			input: []byte{
				0x68, 0x00, // 'h'
				0x69, 0x00, // 'i'
				0x00, 0x00, // null terminator
			},
			expected: "hi",
		},
		{
			name: "null terminated unicode",
			input: []byte{
				0x60, 0x4f, // '你'
				0x7d, 0x59, // '好'
				0x00, 0x00, // null terminator
			},
			expected: "你好",
		},
		{
			name: "string with newline",
			input: []byte{
				0x6c, 0x00, // 'l'
				0x69, 0x00, // 'i'
				0x6e, 0x00, // 'n'
				0x65, 0x00, // 'e'
				0x31, 0x00, // '1'
				0x0a, 0x00, // '\n'
				0x6c, 0x00, // 'l'
				0x69, 0x00, // 'i'
				0x6e, 0x00, // 'n'
				0x65, 0x00, // 'e'
				0x32, 0x00, // '2'
			},
			expected: "line1\nline2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeToString(tt.input)

			if got != tt.expected {
				t.Errorf("DecodeToString(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestRoundTrip tests encoding and decoding in both directions
func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"ascii", "Hello, World!"},
		{"ascii with special chars", "Test\t\n\r!@#$%^&*()"},
		{"latin extended", "Café naïve résumé"},
		{"chinese", "你好世界"},
		{"japanese", "こんにちは"},
		{"korean", "안녕하세요"},
		{"cyrillic", "Привет мир"},
		{"arabic", "مرحبا بالعالم"},
		{"hebrew", "שלום עולם"},
		{"emoji basic", "😀🎉🌍"},
		{"emoji complex", "👨‍👩‍👧‍👦"},
		{"mixed ascii unicode", "Hello 世界 مرحبا"},
		{"mixed with emoji", "Test 😀 123 你好"},
		{"numbers and symbols", "0123456789 !@#$%^&*()"},
		{"long ascii", strings.Repeat("abcdefghijklmnopqrstuvwxyz", 100)},
		{"long unicode", strings.Repeat("你好世界", 100)},
		{"long mixed", strings.Repeat("Hello世界", 100)},
		{"very long", strings.Repeat("Test 😀 你好\n", 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test EncodeStringToBytes -> DecodeToString
			encoded := EncodeStringToBytes(tt.input)
			decoded := DecodeToString(encoded)

			if decoded != tt.input {
				t.Errorf("Round-trip EncodeStringToBytes->DecodeToString failed for %q: got %q", tt.input, decoded)
			}

			// Test EncodeString -> DecodeToString
			if tt.input != "" {
				dst := make([]byte, EncodedStringLen(tt.input))
				n := EncodeString(dst, tt.input)
				decoded2 := DecodeToString(dst[:n])

				if decoded2 != tt.input {
					t.Errorf("Round-trip EncodeString->DecodeToString failed for %q: got %q", tt.input, decoded2)
				}
			}
		})
	}
}

// TestRoundTripWithNullTermination tests that null-terminated strings decode correctly
func TestRoundTripWithNullTermination(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"ascii", "hello"},
		{"unicode", "你好"},
		{"mixed", "Test 你好"},
		{"emoji", "😀🎉"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode and add null terminator
			encoded := EncodeStringToBytes(tt.input)
			encodedWithNull := append(encoded, 0x00, 0x00)

			// Decode should strip the null terminator
			decoded := DecodeToString(encodedWithNull)

			if decoded != tt.input {
				t.Errorf("Round-trip with null termination failed for %q: got %q", tt.input, decoded)
			}
		})
	}
}

// TestEncodedStringLenConsistency tests that EncodedStringLen matches actual encoding
func TestEncodedStringLenConsistency(t *testing.T) {
	tests := []string{
		"",
		"A",
		"hello",
		"Hello, World!",
		"Café",
		"你好世界",
		"😀🎉",
		"Hello 世界 مرحبا",
		strings.Repeat("test", 1000),
		strings.Repeat("你好", 1000),
		"𝕳𝖊𝖑𝖑𝖔", // Mathematical Fraktur (surrogate pairs)
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			expectedLen := EncodedStringLen(input)
			actualBytes := EncodeStringToBytes(input)
			actualLen := len(actualBytes)

			if input == "" {
				// Empty string returns nil, so len is 0
				if actualBytes != nil {
					t.Errorf("Empty string should return nil, got %v", actualBytes)
				}
				if expectedLen != 0 {
					t.Errorf("EncodedStringLen(\"\") = %d, want 0", expectedLen)
				}
			} else {
				if expectedLen != actualLen {
					t.Errorf("EncodedStringLen(%q) = %d, but EncodeStringToBytes returned %d bytes",
						input, expectedLen, actualLen)
				}
			}
		})
	}
}

// TestDecodeOddLength tests decoding with odd-length byte arrays (invalid UTF-16LE)
func TestDecodeOddLength(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "1 byte",
			input:    []byte{0x41},
			expected: "", // Incomplete UTF-16LE unit
		},
		{
			name: "3 bytes",
			input: []byte{
				0x41, 0x00, // 'A'
				0x42, // incomplete
			},
			expected: "A", // Decodes what it can
		},
		{
			name: "5 bytes",
			input: []byte{
				0x68, 0x00, // 'h'
				0x69, 0x00, // 'i'
				0x21, // incomplete
			},
			expected: "hi", // Decodes complete units
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeToString(tt.input)
			if got != tt.expected {
				t.Errorf("DecodeToString(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestLargeString tests encoding/decoding of very large strings
func TestLargeString(t *testing.T) {
	// Test 1MB of ASCII
	t.Run("1MB ASCII", func(t *testing.T) {
		input := strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789", 30000) // ~1MB
		encoded := EncodeStringToBytes(input)
		decoded := DecodeToString(encoded)

		if decoded != input {
			t.Errorf("Large ASCII round-trip failed: length mismatch got %d, want %d",
				len(decoded), len(input))
		}
	})

	// Test 1MB of Unicode
	t.Run("1MB Unicode", func(t *testing.T) {
		input := strings.Repeat("你好世界", 90000) // ~1MB
		encoded := EncodeStringToBytes(input)
		decoded := DecodeToString(encoded)

		if decoded != input {
			t.Errorf("Large Unicode round-trip failed: length mismatch got %d, want %d",
				len(decoded), len(input))
		}
	})

	// Test mixed content
	t.Run("1MB Mixed", func(t *testing.T) {
		input := strings.Repeat("Hello世界😀\n", 30000) // ~1MB
		encoded := EncodeStringToBytes(input)
		decoded := DecodeToString(encoded)

		if decoded != input {
			t.Errorf("Large mixed round-trip failed: length mismatch got %d, want %d",
				len(decoded), len(input))
		}
	})
}

// TestSpecialCharacters tests various special characters
func TestSpecialCharacters(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"null character", "hello\x00world"},
		{"backslash", "path\\to\\file"},
		{"forward slash", "path/to/file"},
		{"quotes", `"quoted" and 'single'`},
		{"control chars", "line1\r\nline2\tindented"},
		{"unicode control", "test\u200Bhidden"},
		{"zero width joiner", "👨‍👩‍👧‍👦"},
		{"combining diacritics", "é"}, // e + combining acute
		{"bidi marks", "Hello\u202Eworld\u202C"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeStringToBytes(tt.input)
			decoded := DecodeToString(encoded)

			if decoded != tt.input {
				t.Errorf("Round-trip failed for %q: got %q", tt.input, decoded)
			}
		})
	}
}

// TestAllASCIICharacters tests encoding/decoding of all ASCII characters
func TestAllASCIICharacters(t *testing.T) {
	// Build string with all ASCII characters (0-127)
	var sb strings.Builder
	for i := 0; i < 128; i++ {
		sb.WriteByte(byte(i))
	}
	input := sb.String()

	encoded := EncodeStringToBytes(input)
	decoded := DecodeToString(encoded)

	if decoded != input {
		t.Errorf("All ASCII characters round-trip failed")
		// Find first mismatch
		for i := 0; i < len(input) && i < len(decoded); i++ {
			if input[i] != decoded[i] {
				t.Errorf("First mismatch at position %d: got %#x, want %#x",
					i, decoded[i], input[i])
				break
			}
		}
	}
}

// TestEmptyAndNilConsistency tests consistency between empty string and nil handling
func TestEmptyAndNilConsistency(t *testing.T) {
	// Empty string encoding
	emptyEncoded := EncodeStringToBytes("")
	if emptyEncoded != nil {
		t.Errorf("EncodeStringToBytes(\"\") should return nil, got %v", emptyEncoded)
	}

	// Nil bytes decoding
	nilDecoded := DecodeToString(nil)
	if nilDecoded != "" {
		t.Errorf("DecodeToString(nil) should return \"\", got %q", nilDecoded)
	}

	// Empty bytes decoding
	emptyDecoded := DecodeToString([]byte{})
	if emptyDecoded != "" {
		t.Errorf("DecodeToString([]byte{}) should return \"\", got %q", emptyDecoded)
	}
}

// BenchmarkEncodeStringToBytes benchmarks the EncodeStringToBytes function
func BenchmarkEncodeStringToBytes(b *testing.B) {
	tests := []struct {
		name  string
		input string
	}{
		{"short ascii", "hello"},
		{"medium ascii", strings.Repeat("hello", 100)},
		{"long ascii", strings.Repeat("hello", 10000)},
		{"short unicode", "你好"},
		{"medium unicode", strings.Repeat("你好", 100)},
		{"long unicode", strings.Repeat("你好", 10000)},
		{"emoji", "😀🎉🌍"},
		{"mixed", "Hello 世界 😀"},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = EncodeStringToBytes(tt.input)
			}
		})
	}
}

// BenchmarkDecodeToString benchmarks the DecodeToString function
func BenchmarkDecodeToString(b *testing.B) {
	tests := []struct {
		name  string
		input string
	}{
		{"short ascii", "hello"},
		{"medium ascii", strings.Repeat("hello", 100)},
		{"long ascii", strings.Repeat("hello", 10000)},
		{"short unicode", "你好"},
		{"medium unicode", strings.Repeat("你好", 100)},
		{"long unicode", strings.Repeat("你好", 10000)},
		{"emoji", "😀🎉🌍"},
		{"mixed", "Hello 世界 😀"},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			encoded := EncodeStringToBytes(tt.input)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = DecodeToString(encoded)
			}
		})
	}
}

// BenchmarkRoundTrip benchmarks the full encode/decode cycle
func BenchmarkRoundTrip(b *testing.B) {
	tests := []struct {
		name  string
		input string
	}{
		{"short ascii", "hello"},
		{"medium ascii", strings.Repeat("hello", 100)},
		{"short unicode", "你好"},
		{"medium unicode", strings.Repeat("你好", 100)},
		{"mixed", "Hello 世界 😀"},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				encoded := EncodeStringToBytes(tt.input)
				_ = DecodeToString(encoded)
			}
		})
	}
}
