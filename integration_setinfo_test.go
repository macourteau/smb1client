//go:build integration
// +build integration

package smb1_test

import (
	"errors"
	"os"
	"testing"
	"time"

	smb1 "github.com/macourteau/smb1client"
	"github.com/macourteau/smb1client/internal/erref"
)

// skipIfChmodUnsupported skips the test when the server refuses attribute
// changes outright: some legacy devices answer STATUS_NOT_SUPPORTED to both
// the TRANS2 basic-info set and the core-protocol SMB_COM_SET_INFORMATION
// fallback, leaving no SMB1 mechanism to change attributes at all.
func skipIfChmodUnsupported(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, erref.STATUS_NOT_SUPPORTED) {
		t.Skipf("server does not support changing file attributes (STATUS_NOT_SUPPORTED even via the SMB_COM_SET_INFORMATION fallback): %v", err)
	}
}

// Chtimes must set the modification time to what was asked, observable
// through Stat. The access time is set on the wire too, but Samba does not
// reliably persist atimes (the backing filesystem is often mounted
// noatime/relatime), so it is only logged, not asserted.
func TestIntegration_Chtimes(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, unmount := mountTestShare(t, session)
	defer unmount()

	filename := testFileName("chtimes")
	defer share.Remove(filename)

	if err := share.WriteFile(filename, []byte("chtimes probe"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	atime := time.Date(2021, 3, 9, 8, 15, 30, 0, time.UTC)
	mtime := time.Date(2020, 6, 15, 12, 30, 45, 0, time.UTC)

	if err := share.Chtimes(filename, atime, mtime); err != nil {
		t.Fatalf("Chtimes failed: %v", err)
	}

	fi, err := share.Stat(filename)
	if err != nil {
		t.Fatalf("Stat after Chtimes failed: %v", err)
	}

	// Servers may round to their filesystem's timestamp resolution; a two
	// second tolerance covers even FAT-style granularity.
	if diff := fi.ModTime().Sub(mtime); diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("ModTime after Chtimes = %v, want %v (±2s)", fi.ModTime(), mtime)
	}

	stat := fi.Sys().(*smb1.FileStat)
	t.Logf("Chtimes: asked atime=%v, server reports %v (best-effort)", atime, stat.LastAccessTime)
}

// A zero mtime must leave the modification time unchanged — SMB1 encodes it
// as FILETIME 0, "do not change" — rather than resetting it to a garbage
// epoch.
func TestIntegration_ChtimesZeroTimeLeavesUnchanged(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, unmount := mountTestShare(t, session)
	defer unmount()

	filename := testFileName("chtimes_zero")
	defer share.Remove(filename)

	if err := share.WriteFile(filename, []byte("zero-time probe"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	mtime := time.Date(2019, 11, 2, 3, 4, 5, 0, time.UTC)
	if err := share.Chtimes(filename, time.Time{}, mtime); err != nil {
		t.Fatalf("Chtimes(mtime only) failed: %v", err)
	}

	// Now touch only the atime; the mtime set above must survive.
	if err := share.Chtimes(filename, time.Now(), time.Time{}); err != nil {
		t.Fatalf("Chtimes(atime only) failed: %v", err)
	}

	fi, err := share.Stat(filename)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if diff := fi.ModTime().Sub(mtime); diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("ModTime after zero-mtime Chtimes = %v, want %v (±2s) unchanged", fi.ModTime(), mtime)
	}
}

// Chmod must toggle the read-only attribute both ways, observable through
// Stat's mode bits, and must not disturb unrelated attributes.
func TestIntegration_Chmod(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, unmount := mountTestShare(t, session)
	defer unmount()

	filename := testFileName("chmod")
	defer func() {
		// Restore writability so the remove cannot be refused.
		share.Chmod(filename, 0644)
		share.Remove(filename)
	}()

	if err := share.WriteFile(filename, []byte("chmod probe"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	before, err := share.Stat(filename)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	attrsBefore := before.Sys().(*smb1.FileStat).FileAttributes

	if err := share.Chmod(filename, 0444); err != nil {
		skipIfChmodUnsupported(t, err)
		t.Fatalf("Chmod(0444) failed: %v", err)
	}
	fi, err := share.Stat(filename)
	if err != nil {
		t.Fatalf("Stat after Chmod(0444) failed: %v", err)
	}
	if fi.Mode()&0200 != 0 {
		t.Errorf("mode after Chmod(0444) = %v, want owner-write cleared", fi.Mode())
	}

	if err := share.Chmod(filename, 0644); err != nil {
		t.Fatalf("Chmod(0644) failed: %v", err)
	}
	fi, err = share.Stat(filename)
	if err != nil {
		t.Fatalf("Stat after Chmod(0644) failed: %v", err)
	}
	if fi.Mode()&0200 == 0 {
		t.Errorf("mode after Chmod(0644) = %v, want owner-write set", fi.Mode())
	}

	// The round trip must not have invented or dropped unrelated attributes.
	attrsAfter := fi.Sys().(*smb1.FileStat).FileAttributes
	const readonly = 0x00000001 // FILE_ATTRIBUTE_READONLY
	if attrsAfter&^readonly != attrsBefore&^readonly {
		t.Errorf("non-readonly attributes changed: %#x -> %#x", attrsBefore, attrsAfter)
	}
}

// File.Chmod performs the same toggle through an open handle.
func TestIntegration_FileChmod(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, unmount := mountTestShare(t, session)
	defer unmount()

	filename := testFileName("file_chmod")
	defer func() {
		share.Chmod(filename, 0644)
		share.Remove(filename)
	}()

	f, err := share.Create(filename)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if _, err := f.WriteString("file chmod probe"); err != nil {
		f.Close()
		t.Fatalf("WriteString failed: %v", err)
	}

	if err := f.Chmod(0444); err != nil {
		f.Close()
		skipIfChmodUnsupported(t, err)
		t.Fatalf("File.Chmod(0444) failed: %v", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		t.Fatalf("File.Stat failed: %v", err)
	}
	if fi.Mode()&0200 != 0 {
		t.Errorf("mode after File.Chmod(0444) = %v, want owner-write cleared", fi.Mode())
	}

	if err := f.Chmod(0644); err != nil {
		f.Close()
		t.Fatalf("File.Chmod(0644) failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	fi, err = share.Stat(filename)
	if err != nil {
		t.Fatalf("Stat after close failed: %v", err)
	}
	if fi.Mode()&0200 == 0 {
		t.Errorf("mode after File.Chmod(0644) = %v, want owner-write set", fi.Mode())
	}
}

// SMB1 cannot create or read symbolic links; both operations must refuse in
// the go-smb2 error shape, detectable with errors.Is even against a live
// server.
func TestIntegration_SymlinkReadlinkUnsupported(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, unmount := mountTestShare(t, session)
	defer unmount()

	err := share.Symlink("target.txt", "link.txt")
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Symlink error = %v, want errors.ErrUnsupported", err)
	}
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) {
		t.Errorf("Symlink error type = %T, want *os.LinkError", err)
	}

	_, err = share.Readlink("link.txt")
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Readlink error = %v, want errors.ErrUnsupported", err)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Errorf("Readlink error type = %T, want *os.PathError", err)
	}
}
