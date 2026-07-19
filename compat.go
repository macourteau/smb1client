package smb1

import (
	"os"
	"strings"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// go-smb2 source compatibility: the old names remain usable as aliases.

type Client = Session          // deprecated type name
type RemoteFileSystem = Share  // deprecated type name
type RemoteFile = File         // deprecated type name
type RemoteFileStat = FileStat // deprecated type name

const MaxReadSizeLimit = 0x100000 // deprecated constant

// FileMode conversion between Unix and Windows

// UnixModeToFileAttributes converts Unix file mode to Windows file attributes.
// This provides a best-effort mapping from Unix permissions to Windows attributes.
func UnixModeToFileAttributes(mode os.FileMode) uint32 {
	var attrs uint32

	// Directory flag
	if mode.IsDir() {
		attrs |= smb1.FILE_ATTRIBUTE_DIRECTORY
	} else {
		attrs |= smb1.FILE_ATTRIBUTE_NORMAL
	}

	// Read-only flag (if not writable by owner)
	if mode&0200 == 0 {
		attrs |= smb1.FILE_ATTRIBUTE_READONLY
	}

	// Hidden files (Unix convention: files starting with .)
	// This is handled at the application layer, not here

	return attrs
}

// FileAttributesToUnixMode converts Windows file attributes to Unix file mode.
// This provides a best-effort mapping from Windows attributes to Unix permissions.
func FileAttributesToUnixMode(attrs uint32) os.FileMode {
	var mode os.FileMode = 0644 // default file permissions

	// Directory
	if attrs&smb1.FILE_ATTRIBUTE_DIRECTORY != 0 {
		mode = os.ModeDir | 0755
	}

	// Read-only flag
	if attrs&smb1.FILE_ATTRIBUTE_READONLY != 0 {
		mode &^= 0222 // remove write permissions
	}

	return mode
}

// Path normalization

// ToWindowsPath converts a Unix-style path to Windows-style path.
// It replaces forward slashes with backslashes and normalizes the path.
func ToWindowsPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, "/", "\\")
	return path
}

// ToUnixPath converts a Windows-style path to Unix-style path.
// It replaces backslashes with forward slashes.
func ToUnixPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, "\\", "/")
	return path
}

// NormalizeShareName normalizes a share name for mounting.
// It accepts various formats and converts them to the canonical UNC format.
//
// Accepted formats:
//   - "ShareName" - just the share name
//   - "\\server\ShareName" - full UNC path
//   - "//server/ShareName" - Unix-style UNC path
//   - "server\ShareName" - UNC without leading slashes
//   - "server/ShareName" - Unix-style without leading slashes
//
// Returns a normalized UNC path in the format: \\server\ShareName
func NormalizeShareName(shareName, serverAddr string) string {
	shareName = strings.TrimSpace(shareName)

	// Convert Unix-style slashes to Windows-style
	shareName = strings.ReplaceAll(shareName, "/", "\\")

	// If it starts with \\, it's already in UNC format
	if strings.HasPrefix(shareName, `\\`) {
		return shareName
	}

	// If it contains a backslash, assume it's server\share format
	if strings.Contains(shareName, `\`) {
		return `\\` + shareName
	}

	// Otherwise, it's just a share name, prepend server address
	// Remove port from server address if present
	if idx := strings.LastIndex(serverAddr, ":"); idx != -1 {
		serverAddr = serverAddr[:idx]
	}

	return `\\` + serverAddr + `\` + shareName
}

// Time conversion helpers

// FileTimeToTime converts Windows FILETIME (100-nanosecond intervals since 1601-01-01)
// to Go time.Time.
func FileTimeToTime(ft uint64) time.Time {
	return convertFileTimeToTime(ft)
}

// TimeToFileTime converts Go time.Time to Windows FILETIME format.
// Returns a 64-bit value representing 100-nanosecond intervals since January 1, 1601 UTC.
func TimeToFileTime(t time.Time) uint64 {
	return convertTimeToFileTime(t)
}

// Share name validation

// ValidateShareName validates that a share name is valid for SMB.
// Valid share names:
//   - Must not be empty
//   - Must not contain invalid characters: / \ : * ? " < > |
//   - Must not be longer than 80 characters (Windows limit)
func ValidateShareName(name string) error {
	if name == "" {
		return &InternalError{"empty share name"}
	}

	if len(name) > 80 {
		return &InternalError{"share name too long (max 80 characters)"}
	}

	// Check for invalid characters
	invalidChars := `/:*?"<>|\`
	if strings.ContainsAny(name, invalidChars) {
		return &InternalError{"share name contains invalid characters"}
	}

	return nil
}

// IsHiddenFile returns true if the file should be considered hidden.
// On Windows, this checks the HIDDEN attribute.
// On Unix systems, files starting with "." are considered hidden.
func IsHiddenFile(name string, attrs uint32) bool {
	// Check Windows hidden attribute
	if attrs&smb1.FILE_ATTRIBUTE_HIDDEN != 0 {
		return true
	}

	// Check Unix convention (files starting with .)
	if strings.HasPrefix(name, ".") {
		return true
	}

	return false
}

// IsSystemFile returns true if the file is a system file.
// On Windows, this checks the SYSTEM attribute.
func IsSystemFile(attrs uint32) bool {
	return attrs&smb1.FILE_ATTRIBUTE_SYSTEM != 0
}

// IsArchiveFile returns true if the file has the archive bit set.
// This indicates the file has been modified since last backup.
func IsArchiveFile(attrs uint32) bool {
	return attrs&smb1.FILE_ATTRIBUTE_ARCHIVE != 0
}
