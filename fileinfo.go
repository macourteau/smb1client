package smb1

import (
	"os"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// FileStat implements os.FileInfo for SMB1 files.
// It contains file metadata returned by SMB1 file operations.
type FileStat struct {
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
	EndOfFile      int64  // File size
	AllocationSize int64  // Allocated size on disk
	FileAttributes uint32 // SMB file attributes
	FileName       string // File name
}

// Name returns the base name of the file.
func (fs *FileStat) Name() string {
	return fs.FileName
}

// Size returns the file size in bytes.
func (fs *FileStat) Size() int64 {
	return fs.EndOfFile
}

// Mode returns the file mode and permission bits.
// SMB file attributes are converted to Unix-style permissions.
func (fs *FileStat) Mode() os.FileMode {
	return attributesToMode(fs.FileAttributes)
}

// ModTime returns the last write time.
func (fs *FileStat) ModTime() time.Time {
	return fs.LastWriteTime
}

// IsDir reports whether the file is a directory.
func (fs *FileStat) IsDir() bool {
	return (fs.FileAttributes & smb1.FILE_ATTRIBUTE_DIRECTORY) != 0
}

// Sys returns the underlying data source (returns self).
func (fs *FileStat) Sys() interface{} {
	return fs
}

// attributesToMode converts SMB file attributes to os.FileMode.
// This provides Unix-style permission bits from Windows file attributes.
func attributesToMode(attrs uint32) os.FileMode {
	var mode os.FileMode

	// Directory flag
	if (attrs & smb1.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		mode |= os.ModeDir | 0755 // Directories get execute permission
	} else {
		mode |= 0644 // Regular files
	}

	// Read-only flag (no write permission)
	if (attrs & smb1.FILE_ATTRIBUTE_READONLY) != 0 {
		mode &^= 0222 // Remove all write permissions
	}

	// Hidden files (no special Unix mode bit)
	// System files (no special Unix mode bit)
	// Archive (no special Unix mode bit)

	// Reparse point (symlink)
	if (attrs & smb1.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		mode |= os.ModeSymlink
	}

	// Device
	if (attrs & smb1.FILE_ATTRIBUTE_DEVICE) != 0 {
		mode |= os.ModeDevice
	}

	return mode
}

// convertFileTimeToTime converts a Windows FILETIME to time.Time.
// FILETIME is a 64-bit value representing the number of 100-nanosecond
// intervals since January 1, 1601 UTC.
func convertFileTimeToTime(filetime uint64) time.Time {
	if filetime == 0 {
		return time.Time{}
	}

	// Windows epoch: January 1, 1601 UTC
	// Unix epoch: January 1, 1970 UTC
	// Difference: 116444736000000000 * 100ns = 11644473600 seconds

	const windowsToUnixEpoch = 116444736000000000

	// Reject invalid timestamps from malicious or buggy servers to prevent
	// integer underflow. If filetime < windowsToUnixEpoch, the subtraction
	// would wrap around (uint64 overflow), producing an invalid time.
	if filetime < windowsToUnixEpoch {
		return time.Time{}
	}

	// Convert 100-nanosecond intervals to nanoseconds
	nsec := int64(filetime-windowsToUnixEpoch) * 100

	return time.Unix(0, nsec)
}

// convertTimeToFileTime converts time.Time to Windows FILETIME format.
// Returns a 64-bit value representing 100-nanosecond intervals since
// January 1, 1601 UTC.
func convertTimeToFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}

	const windowsToUnixEpoch = 116444736000000000

	// Convert to nanoseconds since Unix epoch
	nsec := t.UnixNano()

	// Convert to 100-nanosecond intervals and add Windows epoch offset
	return uint64(nsec/100) + windowsToUnixEpoch
}

// Ensure FileStat implements os.FileInfo
var _ os.FileInfo = (*FileStat)(nil)
