package smb1

import (
	"os"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// TestUnixModeToFileAttributes tests Unix mode to Windows attributes conversion
func TestUnixModeToFileAttributes(t *testing.T) {
	tests := []struct {
		name      string
		mode      os.FileMode
		wantAttrs uint32
	}{
		{
			name:      "regular file with write permission",
			mode:      0644,
			wantAttrs: smb1.FILE_ATTRIBUTE_NORMAL,
		},
		{
			name:      "read-only file",
			mode:      0444,
			wantAttrs: smb1.FILE_ATTRIBUTE_NORMAL | smb1.FILE_ATTRIBUTE_READONLY,
		},
		{
			name:      "directory",
			mode:      os.ModeDir | 0755,
			wantAttrs: smb1.FILE_ATTRIBUTE_DIRECTORY,
		},
		{
			name:      "read-only directory",
			mode:      os.ModeDir | 0555,
			wantAttrs: smb1.FILE_ATTRIBUTE_DIRECTORY | smb1.FILE_ATTRIBUTE_READONLY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := UnixModeToFileAttributes(tt.mode)
			if attrs != tt.wantAttrs {
				t.Errorf("UnixModeToFileAttributes(%v) = 0x%X, want 0x%X", tt.mode, attrs, tt.wantAttrs)
			}
		})
	}
}

// TestFileAttributesToUnixMode tests Windows attributes to Unix mode conversion
func TestFileAttributesToUnixMode(t *testing.T) {
	tests := []struct {
		name     string
		attrs    uint32
		wantMode os.FileMode
	}{
		{
			name:     "normal file",
			attrs:    smb1.FILE_ATTRIBUTE_NORMAL,
			wantMode: 0644,
		},
		{
			name:     "read-only file",
			attrs:    smb1.FILE_ATTRIBUTE_READONLY,
			wantMode: 0444,
		},
		{
			name:     "directory",
			attrs:    smb1.FILE_ATTRIBUTE_DIRECTORY,
			wantMode: os.ModeDir | 0755,
		},
		{
			name:     "read-only directory",
			attrs:    smb1.FILE_ATTRIBUTE_DIRECTORY | smb1.FILE_ATTRIBUTE_READONLY,
			wantMode: os.ModeDir | 0555,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := FileAttributesToUnixMode(tt.attrs)
			if mode != tt.wantMode {
				t.Errorf("FileAttributesToUnixMode(0x%X) = %v, want %v", tt.attrs, mode, tt.wantMode)
			}
		})
	}
}

// TestToWindowsPath tests Unix to Windows path conversion
func TestToWindowsPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "unix path with forward slashes",
			path: "dir/subdir/file.txt",
			want: "dir\\subdir\\file.txt",
		},
		{
			name: "already windows path",
			path: "dir\\subdir\\file.txt",
			want: "dir\\subdir\\file.txt",
		},
		{
			name: "mixed slashes",
			path: "dir/subdir\\file.txt",
			want: "dir\\subdir\\file.txt",
		},
		{
			name: "path with spaces",
			path: "  /path/to/file  ",
			want: "\\path\\to\\file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToWindowsPath(tt.path)
			if got != tt.want {
				t.Errorf("ToWindowsPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestToUnixPath tests Windows to Unix path conversion
func TestToUnixPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "windows path with backslashes",
			path: "dir\\subdir\\file.txt",
			want: "dir/subdir/file.txt",
		},
		{
			name: "already unix path",
			path: "dir/subdir/file.txt",
			want: "dir/subdir/file.txt",
		},
		{
			name: "mixed slashes",
			path: "dir\\subdir/file.txt",
			want: "dir/subdir/file.txt",
		},
		{
			name: "path with spaces",
			path: "  \\path\\to\\file  ",
			want: "/path/to/file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToUnixPath(tt.path)
			if got != tt.want {
				t.Errorf("ToUnixPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestNormalizeShareName tests share name normalization
func TestNormalizeShareName(t *testing.T) {
	tests := []struct {
		name       string
		shareName  string
		serverAddr string
		want       string
	}{
		{
			name:       "just share name",
			shareName:  "MyShare",
			serverAddr: "192.168.1.100",
			want:       "\\\\192.168.1.100\\MyShare",
		},
		{
			name:       "full UNC path",
			shareName:  "\\\\server\\MyShare",
			serverAddr: "192.168.1.100",
			want:       "\\\\server\\MyShare",
		},
		{
			name:       "unix-style UNC path",
			shareName:  "//server/MyShare",
			serverAddr: "192.168.1.100",
			want:       "\\\\server\\MyShare",
		},
		{
			name:       "server and share without slashes",
			shareName:  "server\\MyShare",
			serverAddr: "192.168.1.100",
			want:       "\\\\server\\MyShare",
		},
		{
			name:       "unix-style without leading slashes",
			shareName:  "server/MyShare",
			serverAddr: "192.168.1.100",
			want:       "\\\\server\\MyShare",
		},
		{
			name:       "server with port",
			shareName:  "MyShare",
			serverAddr: "192.168.1.100:445",
			want:       "\\\\192.168.1.100\\MyShare",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeShareName(tt.shareName, tt.serverAddr)
			if got != tt.want {
				t.Errorf("NormalizeShareName(%q, %q) = %q, want %q", tt.shareName, tt.serverAddr, got, tt.want)
			}
		})
	}
}

// TestTimeConversion tests time conversion between FILETIME and Go time
func TestTimeConversion(t *testing.T) {
	// Test known values
	tests := []struct {
		name     string
		filetime uint64
	}{
		{
			name:     "arbitrary time",
			filetime: 132857376000000000, // 2022-01-01 00:00:00 UTC
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert FILETIME to time.Time
			goTime := FileTimeToTime(tt.filetime)

			// Convert back to FILETIME
			backToFiletime := TimeToFileTime(goTime)

			// Should be close (within 100ns due to rounding)
			diff := int64(backToFiletime) - int64(tt.filetime)
			if diff < 0 {
				diff = -diff
			}
			if diff > 10 { // allow small rounding error
				t.Errorf("Time conversion round-trip failed: %d -> %v -> %d (diff: %d)",
					tt.filetime, goTime, backToFiletime, diff)
			}
		})
	}

	// Test current time round-trip
	t.Run("current time round-trip", func(t *testing.T) {
		now := time.Now()
		ft := TimeToFileTime(now)
		backToTime := FileTimeToTime(ft)

		// Should be within 1 microsecond
		diff := now.Sub(backToTime)
		if diff < 0 {
			diff = -diff
		}
		if diff > time.Microsecond {
			t.Errorf("Current time round-trip failed: %v -> %d -> %v (diff: %v)",
				now, ft, backToTime, diff)
		}
	})
}

// TestValidateShareName tests share name validation
func TestValidateShareName(t *testing.T) {
	tests := []struct {
		name      string
		shareName string
		wantErr   bool
	}{
		{
			name:      "valid share name",
			shareName: "MyShare",
			wantErr:   false,
		},
		{
			name:      "empty share name",
			shareName: "",
			wantErr:   true,
		},
		{
			name:      "too long share name",
			shareName: "This_is_a_very_long_share_name_that_exceeds_the_maximum_allowed_length_of_80_characters_for_SMB_shares",
			wantErr:   true,
		},
		{
			name:      "invalid character forward slash",
			shareName: "My/Share",
			wantErr:   true,
		},
		{
			name:      "invalid character colon",
			shareName: "My:Share",
			wantErr:   true,
		},
		{
			name:      "invalid character asterisk",
			shareName: "My*Share",
			wantErr:   true,
		},
		{
			name:      "invalid character question mark",
			shareName: "My?Share",
			wantErr:   true,
		},
		{
			name:      "invalid character quote",
			shareName: "My\"Share",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateShareName(tt.shareName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateShareName(%q) error = %v, wantErr %v", tt.shareName, err, tt.wantErr)
			}
		})
	}
}

// TestIsHiddenFile tests hidden file detection
func TestIsHiddenFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		attrs    uint32
		want     bool
	}{
		{
			name:     "regular file",
			filename: "file.txt",
			attrs:    smb1.FILE_ATTRIBUTE_NORMAL,
			want:     false,
		},
		{
			name:     "hidden attribute",
			filename: "file.txt",
			attrs:    smb1.FILE_ATTRIBUTE_HIDDEN,
			want:     true,
		},
		{
			name:     "unix hidden file",
			filename: ".hidden",
			attrs:    smb1.FILE_ATTRIBUTE_NORMAL,
			want:     true,
		},
		{
			name:     "both hidden attribute and dot prefix",
			filename: ".hidden",
			attrs:    smb1.FILE_ATTRIBUTE_HIDDEN,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsHiddenFile(tt.filename, tt.attrs)
			if got != tt.want {
				t.Errorf("IsHiddenFile(%q, 0x%X) = %v, want %v", tt.filename, tt.attrs, got, tt.want)
			}
		})
	}
}

// TestIsSystemFile tests system file detection
func TestIsSystemFile(t *testing.T) {
	tests := []struct {
		name  string
		attrs uint32
		want  bool
	}{
		{
			name:  "regular file",
			attrs: smb1.FILE_ATTRIBUTE_NORMAL,
			want:  false,
		},
		{
			name:  "system file",
			attrs: smb1.FILE_ATTRIBUTE_SYSTEM,
			want:  true,
		},
		{
			name:  "system and hidden",
			attrs: smb1.FILE_ATTRIBUTE_SYSTEM | smb1.FILE_ATTRIBUTE_HIDDEN,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSystemFile(tt.attrs)
			if got != tt.want {
				t.Errorf("IsSystemFile(0x%X) = %v, want %v", tt.attrs, got, tt.want)
			}
		})
	}
}

// TestIsArchiveFile tests archive file detection
func TestIsArchiveFile(t *testing.T) {
	tests := []struct {
		name  string
		attrs uint32
		want  bool
	}{
		{
			name:  "regular file",
			attrs: smb1.FILE_ATTRIBUTE_NORMAL,
			want:  false,
		},
		{
			name:  "archive file",
			attrs: smb1.FILE_ATTRIBUTE_ARCHIVE,
			want:  true,
		},
		{
			name:  "archive and normal",
			attrs: smb1.FILE_ATTRIBUTE_ARCHIVE | smb1.FILE_ATTRIBUTE_NORMAL,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsArchiveFile(tt.attrs)
			if got != tt.want {
				t.Errorf("IsArchiveFile(0x%X) = %v, want %v", tt.attrs, got, tt.want)
			}
		})
	}
}
