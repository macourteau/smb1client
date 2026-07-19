package smb1

import (
	"errors"
	"os"
	"testing"
)

// The deprecated names are aliases, not distinct types: a value of the
// current type must be assignable through the old name with no conversion.
var (
	_ *Session  = (*Client)(nil)
	_ *Share    = (*RemoteFileSystem)(nil)
	_ *File     = (*RemoteFile)(nil)
	_ *FileStat = (*RemoteFileStat)(nil)
)

func TestMaxReadSizeLimit(t *testing.T) {
	if MaxReadSizeLimit != 0x100000 {
		t.Errorf("MaxReadSizeLimit = %#x, want 0x100000", MaxReadSizeLimit)
	}
}

// Dialer.Negotiator is a struct with go-smb2's field set; SMB1 ignores every
// field, but source compatibility requires them to be settable.
func TestNegotiatorFieldsAccepted(t *testing.T) {
	d := &Dialer{
		Negotiator: Negotiator{
			RequireMessageSigning: true,
			ClientGuid:            [16]byte{1, 2, 3},
			SpecifiedDialect:      0x0202,
		},
		Initiator: &NTLMInitiator{User: "u", Password: "p"},
	}
	if !d.Negotiator.RequireMessageSigning {
		t.Error("Negotiator.RequireMessageSigning not retained")
	}
}

func TestNormalizePathDefaultEnabled(t *testing.T) {
	if !NORMALIZE_PATH {
		t.Error("NORMALIZE_PATH default = false, want true")
	}
}

// Truncate rejects a negative size before any wire traffic, mirroring
// go-smb2's bare os.ErrInvalid.
func TestShareTruncateNegativeSize(t *testing.T) {
	fs := &Share{}
	if err := fs.Truncate("file.txt", -1); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("Truncate(-1) error = %v, want os.ErrInvalid", err)
	}
}

// Path validation also runs before any wire traffic, so a traversal attempt
// fails on a zero Share.
func TestShareTruncateInvalidPath(t *testing.T) {
	fs := &Share{}
	err := fs.Truncate(`..\escape.txt`, 0)
	if err == nil {
		t.Fatal("Truncate with traversal path succeeded, want error")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Errorf("Truncate error = %T, want *os.PathError", err)
	}
}
