package smb1

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/macourteau/smb1client/internal/smb1"
)

// The fallback from the 64-bit level to the legacy one must fire only when the
// server declines the level. Falling back on a transport failure would spend a
// second round trip to fail again; not falling back on a declined level would
// deny free space to exactly the old and embedded servers the legacy level
// exists for.
//
// Every server-originated case below is built with smb1.StatusToError — the
// function the receive path actually calls — rather than by hand-constructing
// an error type. An earlier version of this test used *ResponseError, which the
// wire path never produces, so it passed against a predicate that could not
// classify a single real error.
func TestIsUnsupportedLevelError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},

		// As produced by the receive path.
		{"wire not supported", smb1.StatusToError(0xC00000BB), true},
		{"wire invalid level", smb1.StatusToError(0xC0000148), true},
		{"wire invalid parameter", smb1.StatusToError(0xC000000D), true},
		{"wire invalid info class", smb1.StatusToError(0xC0000003), true},
		{"wire not implemented", smb1.StatusToError(0xC0000002), true},

		// The public error vocabulary, which callers may construct.
		{"response not supported", &ResponseError{Code: 0xC00000BB}, true},
		{"response invalid level", &ResponseError{Code: 0xC0000148}, true},
		{"smb not supported", &SMBError{Status: 0xC00000BB}, true},

		// Real failures that must propagate rather than trigger a retry at a
		// different level.
		{"wire access denied", smb1.StatusToError(0xC0000022), false},
		{"wire not found", smb1.StatusToError(0xC0000034), false},
		{"wire success is nil", smb1.StatusToError(0x00000000), false},
		{"response access denied", &ResponseError{Code: 0xC0000022}, false},
		{"network", net.ErrClosed, false},
		{"plain", errors.New("boom"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUnsupportedLevelError(tc.err); got != tc.want {
				t.Errorf("isUnsupportedLevelError(%v [%T]) = %v, want %v", tc.err, tc.err, got, tc.want)
			}
		})
	}
}

// The predicate reads the status code, not the message, so it must survive
// being wrapped on the way up.
func TestIsUnsupportedLevelErrorThroughWrapping(t *testing.T) {
	wire := smb1.StatusToError(0xC00000BB)

	if !isUnsupportedLevelError(fmt.Errorf("query failed: %w", wire)) {
		t.Error("wrapped wire error not recognised")
	}
	if !isUnsupportedLevelError(&os.PathError{Op: "statfs", Path: "x", Err: wire}) {
		t.Error("wire error inside *os.PathError not recognised")
	}
	if !isUnsupportedLevelError(fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", wire))) {
		t.Error("doubly wrapped wire error not recognised")
	}
}

func TestNtStatusOf(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus uint32
		wantOK     bool
	}{
		{"wire", smb1.StatusToError(0xC0000148), 0xC0000148, true},
		{"wrapped wire", fmt.Errorf("x: %w", smb1.StatusToError(0xC0000022)), 0xC0000022, true},
		{"response error", &ResponseError{Code: 0xC00000BB}, 0xC00000BB, true},
		{"smb error", &SMBError{Status: 0xC0000034}, 0xC0000034, true},
		{"nil", nil, 0, false},
		{"no status", errors.New("boom"), 0, false},
		{"network", net.ErrClosed, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, ok := ntStatusOf(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("ntStatusOf(%v) ok = %v, want %v", tc.err, ok, tc.wantOK)
			}
			if status != tc.wantStatus {
				t.Errorf("ntStatusOf(%v) status = %#x, want %#x", tc.err, status, tc.wantStatus)
			}
		})
	}
}

// The concrete type must satisfy the interface without conversion.
var _ FileFsInfo = (*fileFsSizeInfo)(nil)

// The accessor mapping follows go-smb2's fileFsFullSizeInformation exactly:
// BlockSize is bytes per sector, FragmentSize is sectors per allocation unit,
// and the counts are allocation units. A consumer ported from go-smb2
// computes capacity as count * FragmentSize * BlockSize, so a "corrected"
// mapping would silently change its answers.
func TestFileFsSizeInfoMapping(t *testing.T) {
	// nas-shaped geometry: 4 KiB allocation units on 512-byte sectors.
	info, err := newFileFsSizeInfo(8388608, 5242880, 8, 512)
	if err != nil {
		t.Fatalf("newFileFsSizeInfo: unexpected error: %v", err)
	}

	if got := info.BlockSize(); got != 512 {
		t.Errorf("BlockSize() = %d, want 512", got)
	}
	if got := info.FragmentSize(); got != 8 {
		t.Errorf("FragmentSize() = %d, want 8", got)
	}
	if got := info.TotalBlockCount(); got != 8388608 {
		t.Errorf("TotalBlockCount() = %d, want 8388608", got)
	}
	if got := info.FreeBlockCount(); got != 5242880 {
		t.Errorf("FreeBlockCount() = %d, want 5242880", got)
	}
	// SMB1 has no per-caller quota figure; available must equal free rather
	// than report zero or garbage.
	if got := info.AvailableBlockCount(); got != info.FreeBlockCount() {
		t.Errorf("AvailableBlockCount() = %d, want FreeBlockCount() = %d", got, info.FreeBlockCount())
	}

	// The go-smb2 capacity formula must land on the real byte figure.
	if total := info.TotalBlockCount() * info.FragmentSize() * info.BlockSize(); total != 32<<30 {
		t.Errorf("capacity via go-smb2 formula = %d, want %d", total, 32<<30)
	}
}

// The geometry is server-supplied, so a zero-byte allocation unit must be
// refused rather than passed through: every capacity computation a caller
// can make multiplies by it, silently turning any volume into "empty".
func TestNewFileFsSizeInfoRejectsZeroGeometry(t *testing.T) {
	tests := []struct {
		name             string
		sectors, bytesPS uint64
	}{
		{"zero sectors per unit", 0, 512},
		{"zero bytes per sector", 8, 0},
		{"both zero", 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newFileFsSizeInfo(100, 40, tc.sectors, tc.bytesPS)
			if err == nil {
				t.Fatalf("newFileFsSizeInfo(100, 40, %d, %d) = %+v, want error",
					tc.sectors, tc.bytesPS, got)
			}
		})
	}
}

// Path validation runs before any wire traffic, so invalid names fail on a
// zero Share. The empty string is deliberately absent here: it is a valid
// argument (the share root, as in go-smb2) and proceeds to the network.
func TestShareStatfsInvalidPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"traversal", `..\escape`},
		{"absolute", `\absolute`},
		{"null byte", "a\x00b"},
	}

	fs := &Share{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fs.Statfs(tc.path)
			if err == nil {
				t.Fatalf("Statfs(%q) succeeded, want validation error", tc.path)
			}
			var pathErr *os.PathError
			if !errors.As(err, &pathErr) {
				t.Errorf("Statfs(%q) error type = %T, want *os.PathError", tc.path, err)
			}
		})
	}
}
