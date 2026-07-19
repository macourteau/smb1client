package smb1

import (
	"strings"
	"testing"
)

// TestValidateFilePath tests the path validation logic for security and correctness.
func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError bool
		errorMsg  string // substring to check in error message
	}{
		// Valid paths
		{
			name:      "simple_filename",
			path:      "file.txt",
			wantError: false,
		},
		{
			name:      "nested_path",
			path:      "folder\\subfolder\\file.txt",
			wantError: false,
		},
		{
			name:      "deeply_nested",
			path:      "a\\b\\c\\d\\e\\file.txt",
			wantError: false,
		},
		{
			name:      "path_with_dots_in_filename",
			path:      "my.file.with.dots.txt",
			wantError: false,
		},
		{
			name:      "path_with_current_dir",
			path:      ".\\file.txt",
			wantError: false,
		},
		{
			name:      "path_with_multiple_current_dirs",
			path:      ".\\.\\.\\file.txt",
			wantError: false,
		},
		{
			name:      "valid_parent_then_child",
			path:      "a\\b\\..\\c\\file.txt",
			wantError: false,
		},
		{
			name:      "valid_multiple_ups_downs",
			path:      "a\\b\\c\\..\\..\\d\\file.txt",
			wantError: false,
		},

		// Directory traversal attacks - basic
		{
			name:      "parent_directory_simple",
			path:      "..\\file.txt",
			wantError: true,
			errorMsg:  "traverse above root",
		},
		{
			name:      "parent_directory_multiple",
			path:      "..\\..\\file.txt",
			wantError: true,
			errorMsg:  "traverse above root",
		},
		{
			name:      "parent_in_middle",
			path:      "folder\\..\\..\\file.txt",
			wantError: true,
			errorMsg:  "traverse above root",
		},
		{
			name:      "parent_balanced_at_end",
			path:      "folder\\..",
			wantError: false, // depth: 0→1→0, ends at root (valid)
		},
		{
			name:      "only_parent_refs",
			path:      "..\\..\\..",
			wantError: true,
			errorMsg:  "traverse above root",
		},

		// Null byte attacks
		{
			name:      "null_byte_at_end",
			path:      "file.txt\x00",
			wantError: true,
			errorMsg:  "null bytes",
		},
		{
			name:      "null_byte_in_middle",
			path:      "file\x00.txt",
			wantError: true,
			errorMsg:  "null bytes",
		},
		{
			name:      "null_byte_with_traversal",
			path:      "..\x00\\file.txt",
			wantError: true,
			errorMsg:  "null bytes",
		},
		{
			name:      "multiple_null_bytes",
			path:      "fi\x00le\x00.txt",
			wantError: true,
			errorMsg:  "null bytes",
		},

		// Absolute paths
		{
			name:      "absolute_path_simple",
			path:      "\\file.txt",
			wantError: true,
			errorMsg:  "absolute paths not allowed",
		},
		{
			name:      "absolute_path_nested",
			path:      "\\folder\\file.txt",
			wantError: true,
			errorMsg:  "absolute paths not allowed",
		},
		{
			name:      "unc_path",
			path:      "\\\\server\\share\\file.txt",
			wantError: true,
			errorMsg:  "absolute paths not allowed",
		},

		// Forward slashes (should be normalized first)
		{
			name:      "forward_slash_simple",
			path:      "folder/file.txt",
			wantError: true,
			errorMsg:  "forward slashes",
		},
		{
			name:      "mixed_slashes",
			path:      "folder\\sub/file.txt",
			wantError: true,
			errorMsg:  "forward slashes",
		},

		// Empty paths
		{
			name:      "empty_path",
			path:      "",
			wantError: true,
			errorMsg:  "empty path",
		},

		// Edge cases with multiple separators
		{
			name:      "double_backslash",
			path:      "folder\\\\file.txt",
			wantError: false, // Empty components are skipped
		},
		{
			name:      "triple_backslash",
			path:      "folder\\\\\\file.txt",
			wantError: false,
		},

		// Complex combinations
		{
			name:      "dots_in_path_component",
			path:      "folder\\..file.txt",
			wantError: false, // "..file.txt" is a valid filename
		},
		{
			name:      "dots_at_end_of_component",
			path:      "folder\\file..",
			wantError: false, // "file.." is a valid filename
		},
		{
			name:      "current_and_parent_mix",
			path:      ".\\folder\\.\\..\\file.txt",
			wantError: false, // depth: 0→0→1→1→0→1 (valid)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePath(tt.path)

			if tt.wantError {
				if err == nil {
					t.Errorf("validateFilePath(%q) expected error, got nil", tt.path)
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("validateFilePath(%q) error = %v, want error containing %q", tt.path, err, tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateFilePath(%q) unexpected error: %v", tt.path, err)
				}
			}
		})
	}
}

// TestValidateFilePathSecurityVectors tests specific security attack vectors.
func TestValidateFilePathSecurityVectors(t *testing.T) {
	// These are real-world attack patterns that should be blocked
	// They all attempt to escape above the share root
	attackVectors := []string{
		// Direct parent traversal (depth goes negative)
		"..",
		"..\\",
		"..\\..\\",
		"..\\..\\..\\",
		"..\\..\\..\\..\\",
		"..\\..\\..\\..\\..\\",
		// Balanced then escape
		"folder\\..\\..\\",
		"..\\..",
		"..\\..\\sensitive.txt",
		"public\\..\\..\\private\\file.txt",
		"uploads\\..\\..\\..\\etc\\passwd",
		// Null byte attacks
		"\x00",
		"file\x00.txt",
		"..\x00",
		"..\\\x00file.txt",
		// Absolute paths
		"\\",
		"\\folder",
		"\\folder\\file.txt",
		"\\\\server\\share",
	}

	for _, attack := range attackVectors {
		t.Run("block_"+attack, func(t *testing.T) {
			err := validateFilePath(attack)
			if err == nil {
				t.Errorf("validateFilePath(%q) should block attack vector, but returned nil", attack)
			}
		})
	}
}

// TestValidateFilePathAllowsLegitimate tests that valid paths are not blocked.
func TestValidateFilePathAllowsLegitimate(t *testing.T) {
	legitimatePaths := []string{
		"file.txt",
		"document.pdf",
		"folder\\file.txt",
		"folder\\subfolder\\file.txt",
		"a\\b\\c\\d\\e\\f\\g\\h\\file.txt",
		"my.file.with.dots.txt",
		"file-with-dashes.txt",
		"file_with_underscores.txt",
		"FILE.TXT",
		"MixedCase.File.txt",
		".hidden",
		"folder\\.hidden",
		"..file",                       // filename starting with ".."
		"file..",                       // filename ending with ".."
		"...file",                      // filename with three dots
		".\\file.txt",                  // current directory reference
		".\\.\\.\\file.txt",            // multiple current directory references
		"a\\b\\..\\c\\file.txt",        // valid up-then-down
		"a\\b\\c\\..\\..\\d\\file.txt", // balanced navigation
	}

	for _, path := range legitimatePaths {
		t.Run("allow_"+path, func(t *testing.T) {
			err := validateFilePath(path)
			if err != nil {
				t.Errorf("validateFilePath(%q) should allow legitimate path, but returned error: %v", path, err)
			}
		})
	}
}

// TestNormalizePathBeforeValidation tests that normalization happens before validation.
func TestNormalizePathBeforeValidation(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		wantNormalized string
	}{
		{
			name:           "forward_to_backslash",
			path:           "folder/file.txt",
			wantNormalized: "folder\\file.txt",
		},
		{
			name:           "trim_spaces",
			path:           "  folder\\file.txt  ",
			wantNormalized: "folder\\file.txt",
		},
		{
			name:           "mixed_slashes",
			path:           "folder/sub\\file.txt",
			wantNormalized: "folder\\sub\\file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalizePath(tt.path)
			if normalized != tt.wantNormalized {
				t.Errorf("normalizePath(%q) = %q, want %q", tt.path, normalized, tt.wantNormalized)
			}

			// After normalization, validation should pass for valid paths
			err := validateFilePath(normalized)
			if err != nil {
				t.Errorf("validateFilePath(normalizePath(%q)) should pass, got error: %v", tt.path, err)
			}
		})
	}
}

// TestNormalizePathDisabled verifies the NORMALIZE_PATH=false mode: forward
// slashes pass through normalizePath untouched and are then rejected by
// validateFilePath, mirroring go-smb2's behavior. Whitespace trimming is
// unrelated to separator handling and still applies.
func TestNormalizePathDisabled(t *testing.T) {
	NORMALIZE_PATH = false
	defer func() { NORMALIZE_PATH = true }()

	if got := normalizePath("folder/file.txt"); got != "folder/file.txt" {
		t.Errorf("normalizePath(%q) = %q, want the path unchanged", "folder/file.txt", got)
	}
	if got := normalizePath("  folder\\file.txt  "); got != "folder\\file.txt" {
		t.Errorf("normalizePath with whitespace = %q, want %q", got, "folder\\file.txt")
	}

	err := validateFilePath(normalizePath("folder/file.txt"))
	if err == nil || !strings.Contains(err.Error(), "forward slashes") {
		t.Errorf("validateFilePath after disabled normalization = %v, want forward-slash rejection", err)
	}
}

// TestPathValidationDepthTracking tests the depth tracking logic specifically.
func TestPathValidationDepthTracking(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError bool
		depth     string // description of expected depth behavior
	}{
		{
			name:      "depth_0_to_1",
			path:      "file.txt",
			wantError: false,
			depth:     "starts at 0, goes to 1",
		},
		{
			name:      "depth_0_to_3",
			path:      "a\\b\\c",
			wantError: false,
			depth:     "starts at 0, goes to 3",
		},
		{
			name:      "depth_0_to_neg1",
			path:      "..",
			wantError: true,
			depth:     "starts at 0, goes to -1 (invalid)",
		},
		{
			name:      "depth_1_to_0",
			path:      "a\\..",
			wantError: false,
			depth:     "starts at 0, goes to 1, back to 0",
		},
		{
			name:      "depth_2_to_1",
			path:      "a\\b\\..",
			wantError: false,
			depth:     "starts at 0, goes to 2, back to 1",
		},
		{
			name:      "depth_1_to_neg1",
			path:      "a\\..\\..",
			wantError: true,
			depth:     "starts at 0, goes to 1, to 0, to -1 (invalid)",
		},
		{
			name:      "depth_balanced",
			path:      "a\\b\\..\\c",
			wantError: false,
			depth:     "starts at 0, goes to 2, to 1, to 2",
		},
		{
			name:      "depth_complex_valid",
			path:      "a\\b\\c\\..\\..\\d\\e",
			wantError: false,
			depth:     "starts at 0, goes to 3, to 2, to 1, to 3",
		},
		{
			name:      "depth_complex_invalid",
			path:      "a\\..\\..\\b",
			wantError: true,
			depth:     "starts at 0, goes to 1, to 0, to -1 (invalid)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePath(tt.path)
			if tt.wantError && err == nil {
				t.Errorf("validateFilePath(%q) expected error (%s), got nil", tt.path, tt.depth)
			}
			if !tt.wantError && err != nil {
				t.Errorf("validateFilePath(%q) unexpected error (%s): %v", tt.path, tt.depth, err)
			}
		})
	}
}
