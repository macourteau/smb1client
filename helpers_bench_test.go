package smb1

import (
	"testing"
)

// BenchmarkNormalizePath benchmarks the path normalization function
// which is called on every file operation.
func BenchmarkNormalizePath(b *testing.B) {
	tests := []struct {
		name string
		path string
	}{
		{"short_unix", "/path/to/file"},
		{"short_windows", "\\path\\to\\file"},
		{"long_unix", "/very/long/path/with/many/components/to/deeply/nested/file.txt"},
		{"long_windows", "\\very\\long\\path\\with\\many\\components\\to\\deeply\\nested\\file.txt"},
		{"mixed_slashes", "/path\\mixed/slashes\\file.txt"},
		{"with_spaces", "  /path/to/file.txt  "},
		{"already_normalized", "\\normalized\\path\\file.txt"},
		{"deeply_nested", "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/file.txt"},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = normalizePath(tt.path)
			}
		})
	}
}

// BenchmarkValidateFilePath benchmarks the file path validation function
// which checks path safety on every operation.
func BenchmarkValidateFilePath(b *testing.B) {
	tests := []struct {
		name string
		path string
	}{
		{"valid_simple", "file.txt"},
		{"valid_nested", "folder\\subfolder\\file.txt"},
		{"valid_deep", "a\\b\\c\\d\\e\\f\\g\\h\\i\\j\\file.txt"},
		{"invalid_absolute", "\\absolute\\path"},
		{"invalid_parent", "..\\parent\\file.txt"},
		{"invalid_null", "file\x00.txt"},
		{"invalid_forward_slash", "path/to/file.txt"},
		{"valid_long_filename", "this_is_a_very_long_filename_with_many_characters_in_it.txt"},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = validateFilePath(tt.path)
			}
		})
	}
}

// BenchmarkValidateMountPath benchmarks UNC path validation.
func BenchmarkValidateMountPath(b *testing.B) {
	tests := []struct {
		name string
		path string
	}{
		{"valid_simple", "\\\\server\\share"},
		{"valid_with_path", "\\\\server\\share\\folder\\file.txt"},
		{"valid_long_server", "\\\\very-long-server-name.example.com\\share"},
		{"invalid_no_prefix", "server\\share"},
		{"invalid_no_share", "\\\\server"},
		{"invalid_empty", ""},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = validateMountPath(tt.path)
			}
		})
	}
}
