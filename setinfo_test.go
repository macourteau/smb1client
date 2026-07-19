package smb1

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// The mode-to-attribute mapping is go-smb2's: the owner-write bit alone
// decides read-only, everything else is preserved. The one deliberate
// difference is the zero guard — 0 means "leave unchanged" on the wire, so
// clearing the last attribute must substitute FILE_ATTRIBUTE_NORMAL or the
// clear silently does not happen.
func TestChmodAttributes(t *testing.T) {
	tests := []struct {
		name  string
		attrs uint32
		mode  os.FileMode
		want  uint32
	}{
		{
			name:  "set readonly preserves others",
			attrs: smb1.FILE_ATTRIBUTE_ARCHIVE | smb1.FILE_ATTRIBUTE_HIDDEN,
			mode:  0444,
			want:  smb1.FILE_ATTRIBUTE_ARCHIVE | smb1.FILE_ATTRIBUTE_HIDDEN | smb1.FILE_ATTRIBUTE_READONLY,
		},
		{
			name:  "clear readonly preserves others",
			attrs: smb1.FILE_ATTRIBUTE_ARCHIVE | smb1.FILE_ATTRIBUTE_READONLY,
			mode:  0644,
			want:  smb1.FILE_ATTRIBUTE_ARCHIVE,
		},
		{
			name:  "set readonly when already readonly",
			attrs: smb1.FILE_ATTRIBUTE_READONLY,
			mode:  0,
			want:  smb1.FILE_ATTRIBUTE_READONLY,
		},
		{
			name:  "clear last attribute substitutes NORMAL",
			attrs: smb1.FILE_ATTRIBUTE_READONLY,
			mode:  0644,
			want:  smb1.FILE_ATTRIBUTE_NORMAL,
		},
		{
			name:  "set readonly from NORMAL",
			attrs: smb1.FILE_ATTRIBUTE_NORMAL,
			mode:  0444,
			want:  smb1.FILE_ATTRIBUTE_NORMAL | smb1.FILE_ATTRIBUTE_READONLY,
		},
		{
			// Only the owner-write bit matters; group/other write bits do not
			// keep the file writable, matching go-smb2.
			name:  "group write alone still readonly",
			attrs: smb1.FILE_ATTRIBUTE_ARCHIVE,
			mode:  0044 | 0020,
			want:  smb1.FILE_ATTRIBUTE_ARCHIVE | smb1.FILE_ATTRIBUTE_READONLY,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := chmodAttributes(tc.attrs, tc.mode); got != tc.want {
				t.Errorf("chmodAttributes(%#x, %o) = %#x, want %#x", tc.attrs, tc.mode, got, tc.want)
			}
		})
	}
}

// Symlink and Readlink exist for go-smb2 signature parity only; SMB1 cannot
// perform them, and the refusal must be detectable with errors.Is and carry
// the go-smb2-shaped error type for each operation.
func TestSymlinkUnsupported(t *testing.T) {
	fs := &Share{}

	err := fs.Symlink("target.txt", "link.txt")
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Symlink error = %v, want errors.ErrUnsupported", err)
	}
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) {
		t.Fatalf("Symlink error type = %T, want *os.LinkError", err)
	}
	if linkErr.Op != "symlink" || linkErr.Old != "target.txt" || linkErr.New != "link.txt" {
		t.Errorf("Symlink error fields = %q/%q/%q, want symlink/target.txt/link.txt",
			linkErr.Op, linkErr.Old, linkErr.New)
	}
}

func TestReadlinkUnsupported(t *testing.T) {
	fs := &Share{}

	_, err := fs.Readlink("link.txt")
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Readlink error = %v, want errors.ErrUnsupported", err)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("Readlink error type = %T, want *os.PathError", err)
	}
	if pathErr.Op != "readlink" || pathErr.Path != "link.txt" {
		t.Errorf("Readlink error fields = %q/%q, want readlink/link.txt", pathErr.Op, pathErr.Path)
	}
}

// Path validation runs before any wire traffic, so invalid names fail on a
// zero Share for both set-info operations.
func TestSetInfoInvalidPath(t *testing.T) {
	fs := &Share{}

	tests := []struct {
		name string
		call func(path string) error
	}{
		{"chtimes", func(path string) error { return fs.Chtimes(path, time.Now(), time.Now()) }},
		{"chmod", func(path string) error { return fs.Chmod(path, 0644) }},
	}
	paths := []string{``, `..\escape`, `\absolute`, "a\x00b"}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range paths {
				err := tc.call(path)
				if err == nil {
					t.Errorf("%s(%q) succeeded, want validation error", tc.name, path)
					continue
				}
				var pathErr *os.PathError
				if !errors.As(err, &pathErr) {
					t.Errorf("%s(%q) error type = %T, want *os.PathError", tc.name, path, err)
				}
			}
		})
	}
}
