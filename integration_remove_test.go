//go:build integration
// +build integration

package smb1_test

import (
	"errors"
	"os"
	"testing"

	smb1 "github.com/macourteau/smb1client"
)

// statusDirectoryNotEmpty is STATUS_DIRECTORY_NOT_EMPTY ([MS-ERREF] 2.3.1).
const statusDirectoryNotEmpty = 0xC0000101

// Remove of a non-empty directory must fail and leave the directory and its
// contents in place. Some Samba versions (4.9.5 on ASIAIR devices) answer a
// delete-on-close open of a non-empty directory with success at every step
// and then keep the directory, so a Remove built on that reported success for
// a delete that never happened. The verification uses a fresh session so it
// reads the server's state, not anything cached on the removing connection.
func TestDir_RemoveNonEmptyFails(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()
	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	dir := testFileName("rm_nonempty")
	file := dir + "\\x.fit"
	if err := share.Mkdir(dir, 0755); err != nil {
		t.Fatalf("Mkdir(%q) failed: %v", dir, err)
	}
	defer share.RemoveAll(dir)
	if err := share.WriteFile(file, []byte("frame"), 0644); err != nil {
		t.Fatalf("WriteFile(%q) failed: %v", file, err)
	}

	err := share.Remove(dir)
	if err == nil {
		t.Fatalf("Remove(%q) on a non-empty directory succeeded, want an error", dir)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Op != "remove" {
		t.Errorf("Remove error = %v (%T), want *os.PathError with Op \"remove\"", err, err)
	}
	var respErr *smb1.ResponseError
	if !errors.As(err, &respErr) || respErr.Code != statusDirectoryNotEmpty {
		t.Errorf("Remove error = %v, want *ResponseError with STATUS_DIRECTORY_NOT_EMPTY", err)
	}

	verifySession, verifyCleanup := createTestSession(t)
	defer verifyCleanup()
	verifyShare, verifyShareCleanup := mountTestShare(t, verifySession)
	defer verifyShareCleanup()

	entries, err := verifyShare.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q) from a fresh session failed: %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != "x.fit" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("ReadDir(%q) = %v after the refused Remove, want [x.fit]", dir, names)
	}
}

// Remove of an empty directory succeeds and the directory is gone, including
// one that just had its last entry removed.
func TestDir_RemoveEmptySucceeds(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()
	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	dir := testFileName("rm_empty")
	file := dir + "\\x.fit"
	if err := share.Mkdir(dir, 0755); err != nil {
		t.Fatalf("Mkdir(%q) failed: %v", dir, err)
	}
	defer share.RemoveAll(dir)
	if err := share.WriteFile(file, []byte("frame"), 0644); err != nil {
		t.Fatalf("WriteFile(%q) failed: %v", file, err)
	}

	if err := share.Remove(file); err != nil {
		t.Fatalf("Remove(%q) failed: %v", file, err)
	}
	if err := share.Remove(dir); err != nil {
		t.Fatalf("Remove(%q) on the emptied directory failed: %v", dir, err)
	}
	if _, err := share.Stat(dir); !smb1.IsNotFoundError(err) {
		t.Errorf("Stat(%q) after Remove = %v, want a not-found error", dir, err)
	}
}

// RemoveAll removes a nested tree: it empties each directory before removing
// it, so directories are only ever removed empty.
func TestDir_RemoveAllNested(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()
	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	root := testFileName("rm_all")
	sub := root + "\\a\\b"
	if err := share.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("MkdirAll(%q) failed: %v", sub, err)
	}
	for _, f := range []string{root + "\\top.fit", root + "\\a\\mid.fit", sub + "\\leaf.fit"} {
		if err := share.WriteFile(f, []byte("frame"), 0644); err != nil {
			t.Fatalf("WriteFile(%q) failed: %v", f, err)
		}
	}

	if err := share.RemoveAll(root); err != nil {
		t.Fatalf("RemoveAll(%q) failed: %v", root, err)
	}
	if _, err := share.Stat(root); !smb1.IsNotFoundError(err) {
		t.Errorf("Stat(%q) after RemoveAll = %v, want a not-found error", root, err)
	}
}

// A file held open by another session without FILE_SHARE_DELETE (OpenFile
// grants only read and write sharing) cannot be removed or renamed. The
// failure must stay a permission error, as before, and also be recognisable
// as a sharing violation, which a caller can wait out.
func TestFile_SharingViolationClassified(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()
	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	name := testFileName("sharing")
	if err := share.WriteFile(name, []byte("frame"), 0644); err != nil {
		t.Fatalf("WriteFile(%q) failed: %v", name, err)
	}
	defer share.Remove(name)
	renamed := name + ".renamed"
	defer share.Remove(renamed) // only exists if the Rename wrongly succeeded

	holderSession, holderCleanup := createTestSession(t)
	defer holderCleanup()
	holderShare, holderShareCleanup := mountTestShare(t, holderSession)
	defer holderShareCleanup()

	held, err := holderShare.Open(name)
	if err != nil {
		t.Fatalf("Open(%q) in the holding session failed: %v", name, err)
	}

	checks := []struct {
		op  string
		err error
	}{
		{"Remove", share.Remove(name)},
		{"Rename", share.Rename(name, renamed)},
	}
	for _, c := range checks {
		if c.err == nil {
			t.Errorf("%s of a file held open without share-delete succeeded, want a sharing violation", c.op)
			continue
		}
		if !smb1.IsSharingViolation(c.err) {
			t.Errorf("%s error = %v, IsSharingViolation = false, want true", c.op, c.err)
		}
		if !errors.Is(c.err, os.ErrPermission) {
			t.Errorf("%s error = %v, errors.Is(os.ErrPermission) = false, want true", c.op, c.err)
		}
	}

	if err := held.Close(); err != nil {
		t.Fatalf("Close of the held file failed: %v", err)
	}
	if err := share.Remove(name); err != nil {
		t.Fatalf("Remove(%q) after the holder closed failed: %v", name, err)
	}
}
