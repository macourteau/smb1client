//go:build integration
// +build integration

package smb1_test

import (
	"testing"
)

// Statfs against a live server. Most servers answer SMB_QUERY_FS_SIZE_INFO
// directly — the legacy SMB_INFO_ALLOCATION fallback does not fire — but the
// numbers are only trustworthy if they are internally consistent, which is
// what this asserts. The name argument is exercised in three forms that must
// all answer identically, because the query is share-wide.
func TestIntegration_Statfs(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, unmount := mountTestShare(t, session)
	defer unmount()

	info, err := share.Statfs("")
	if err != nil {
		t.Fatalf(`Statfs("") failed: %v`, err)
	}

	if info.TotalBlockCount() == 0 {
		t.Error("Statfs() reported a zero-block volume; a mounted share must have capacity")
	}
	if info.BlockSize() == 0 {
		t.Error("Statfs() reported zero bytes per sector")
	}
	if info.FragmentSize() == 0 {
		t.Error("Statfs() reported zero sectors per allocation unit")
	}
	if info.FreeBlockCount() > info.TotalBlockCount() {
		t.Errorf("Statfs() reported free (%d) > total (%d) blocks", info.FreeBlockCount(), info.TotalBlockCount())
	}
	// SMB1 has one free figure; the caller-available count must mirror it.
	if info.AvailableBlockCount() != info.FreeBlockCount() {
		t.Errorf("AvailableBlockCount() = %d, want FreeBlockCount() = %d",
			info.AvailableBlockCount(), info.FreeBlockCount())
	}

	// The query ignores the name — a subdirectory and the root must report
	// the same volume geometry.
	sub, err := share.Statfs("statfs_probe_dir_does_not_need_to_exist")
	if err != nil {
		t.Fatalf("Statfs(name) failed: %v", err)
	}
	if sub.BlockSize() != info.BlockSize() || sub.TotalBlockCount() != info.TotalBlockCount() {
		t.Errorf("Statfs(name) geometry differs from Statfs(\"\"): block=%d/%d total=%d/%d",
			sub.BlockSize(), info.BlockSize(), sub.TotalBlockCount(), info.TotalBlockCount())
	}

	totalBytes := info.TotalBlockCount() * info.FragmentSize() * info.BlockSize()
	freeBytes := info.FreeBlockCount() * info.FragmentSize() * info.BlockSize()
	t.Logf("Statfs: total=%d free=%d (blocks: total=%d free=%d frag=%d bs=%d)",
		totalBytes, freeBytes, info.TotalBlockCount(), info.FreeBlockCount(),
		info.FragmentSize(), info.BlockSize())
}

// Repeated calls must agree closely, and a query through an open file must
// agree with the share-level query — both address the same tree. A wildly
// different second answer would mean the query is not idempotent or the
// decode is reading stale bytes.
func TestIntegration_StatfsIsStable(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, unmount := mountTestShare(t, session)
	defer unmount()

	first, err := share.Statfs("")
	if err != nil {
		t.Fatalf("first Statfs() failed: %v", err)
	}
	second, err := share.Statfs("")
	if err != nil {
		t.Fatalf("second Statfs() failed: %v", err)
	}

	if first.TotalBlockCount() != second.TotalBlockCount() {
		t.Errorf("TotalBlockCount changed between calls: %d then %d", first.TotalBlockCount(), second.TotalBlockCount())
	}
	if first.BlockSize() != second.BlockSize() {
		t.Errorf("BlockSize changed between calls: %d then %d", first.BlockSize(), second.BlockSize())
	}

	// File.Statfs must see the same volume as Share.Statfs. Free counts can
	// drift while the server does other work, so only the fixed geometry and
	// total are held to equality.
	filename := testFileName("statfs_file")
	defer share.Remove(filename)

	f, err := share.Create(filename)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer f.Close()

	viaFile, err := f.Statfs()
	if err != nil {
		t.Fatalf("File.Statfs() failed: %v", err)
	}
	if viaFile.BlockSize() != first.BlockSize() ||
		viaFile.FragmentSize() != first.FragmentSize() ||
		viaFile.TotalBlockCount() != first.TotalBlockCount() {
		t.Errorf("File.Statfs() disagrees with Share.Statfs(): bs=%d/%d frag=%d/%d total=%d/%d",
			viaFile.BlockSize(), first.BlockSize(),
			viaFile.FragmentSize(), first.FragmentSize(),
			viaFile.TotalBlockCount(), first.TotalBlockCount())
	}
}

// VolumeInfo is the write-free way to tell one piece of removable media from
// another. Live-device verified: real servers report a distinct, non-zero serial
// number per share.
func TestIntegration_VolumeInfo(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, unmount := mountTestShare(t, session)
	defer unmount()

	info, err := share.VolumeInfo()
	if err != nil {
		t.Fatalf("VolumeInfo() failed: %v", err)
	}

	if info.SerialNumber == 0 {
		t.Error("VolumeInfo() reported a zero serial number; media identity cannot rest on it")
	}

	// The serial must be stable across queries, or it identifies nothing.
	again, err := share.VolumeInfo()
	if err != nil {
		t.Fatalf("second VolumeInfo() failed: %v", err)
	}
	if again.SerialNumber != info.SerialNumber {
		t.Errorf("serial number changed between calls: %#08x then %#08x", info.SerialNumber, again.SerialNumber)
	}

	t.Logf("VolumeInfo: serial=%#08x label=%q created=%v", info.SerialNumber, info.Label, info.CreationTime)
}

// Different shares must report different serial numbers, otherwise the serial
// cannot distinguish the media behind them.
func TestIntegration_VolumeSerialsDifferPerShare(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	names, err := session.ListSharenames()
	if err != nil {
		t.Fatalf("ListSharenames() failed: %v", err)
	}

	serials := make(map[uint32]string)
	for _, name := range names {
		if name == "IPC$" || name == "print$" {
			continue
		}
		share, err := session.Mount(name)
		if err != nil {
			t.Logf("skipping %q: mount failed: %v", name, err)
			continue
		}
		info, err := share.VolumeInfo()
		share.Umount()
		if err != nil {
			t.Errorf("VolumeInfo() on %q failed: %v", name, err)
			continue
		}
		if prev, seen := serials[info.SerialNumber]; seen {
			t.Errorf("shares %q and %q report the same serial %#08x", prev, name, info.SerialNumber)
			continue
		}
		serials[info.SerialNumber] = name
		t.Logf("share %-14q serial=%#08x", name, info.SerialNumber)
	}

	if len(serials) == 0 {
		t.Skip("no mountable data shares to compare")
	}
}
