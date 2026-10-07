package smb1

import (
	"errors"
	"os"
	"testing"

	"github.com/macourteau/smb1client/internal/erref"
)

// A directory Remove that the server refuses because the directory still has
// entries must come back in go-smb2's shape — *os.PathError{Op: "remove"}
// wrapping *ResponseError carrying STATUS_DIRECTORY_NOT_EMPTY — so a caller
// ported from go-smb2 can detect it with errors.As unchanged. Other failures
// keep the usual public-API mapping.
func TestMapRemoveDirError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		check func(t *testing.T, err error)
	}{
		{
			name: "directory not empty",
			err:  erref.STATUS_DIRECTORY_NOT_EMPTY,
			check: func(t *testing.T, err error) {
				var respErr *ResponseError
				if !errors.As(err, &respErr) {
					t.Fatalf("error %v (%T) does not unwrap to *ResponseError", err, err)
				}
				if respErr.Code != uint32(erref.STATUS_DIRECTORY_NOT_EMPTY) {
					t.Errorf("Code = 0x%08X, want 0x%08X", respErr.Code, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))
				}
				if IsNotFoundError(err) || IsPermissionError(err) || IsExistError(err) {
					t.Errorf("not-empty error misclassified: %v", err)
				}
			},
		},
		{
			name: "not found",
			err:  erref.STATUS_OBJECT_NAME_NOT_FOUND,
			check: func(t *testing.T, err error) {
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("error %v does not match os.ErrNotExist", err)
				}
			},
		},
		{
			name: "access denied",
			err:  erref.STATUS_ACCESS_DENIED,
			check: func(t *testing.T, err error) {
				if !errors.Is(err, os.ErrPermission) {
					t.Errorf("error %v does not match os.ErrPermission", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapRemoveDirError(tt.err, "dir\\sub")
			var pathErr *os.PathError
			if !errors.As(err, &pathErr) {
				t.Fatalf("error %v (%T) is not *os.PathError", err, err)
			}
			if pathErr.Op != "remove" || pathErr.Path != "dir\\sub" {
				t.Errorf("PathError Op/Path = %q/%q, want %q/%q", pathErr.Op, pathErr.Path, "remove", "dir\\sub")
			}
			tt.check(t, err)
		})
	}
}
