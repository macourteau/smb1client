//go:build integration
// +build integration

package smb1_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"time"
)

// =============================================================================
// go-smb2 API parity tests: WriteString, ReadFrom/WriteTo, Readdirnames,
// Share.Truncate, Share.Glob
// =============================================================================

func TestFile_WriteString(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("write_string")
	defer share.Remove(filename)

	f, err := share.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	const content = "written via WriteString\n"
	n, err := f.WriteString(content)
	if err != nil {
		f.Close()
		t.Fatalf("WriteString failed: %v", err)
	}
	if n != len(content) {
		t.Errorf("WriteString length: got %d, expected %d", n, len(content))
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close: %v", err)
	}

	readData, err := share.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read back: %v", err)
	}
	if string(readData) != content {
		t.Errorf("Content mismatch: got %q, expected %q", readData, content)
	}
}

func TestFile_ReadFromWriteTo(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("readfrom_writeto")
	defer share.Remove(filename)

	// Larger than one copy buffer so the loop runs more than once.
	testContent := bytes.Repeat([]byte("0123456789abcdef"), 20*1024) // 320 KiB

	// Upload through ReadFrom (the io.Copy(file, reader) path).
	f, err := share.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	n, err := f.ReadFrom(bytes.NewReader(testContent))
	if err != nil {
		f.Close()
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if n != int64(len(testContent)) {
		t.Errorf("ReadFrom length: got %d, expected %d", n, len(testContent))
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close: %v", err)
	}

	// Download through WriteTo (the io.Copy(writer, file) path).
	f, err = share.Open(filename)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	var buf bytes.Buffer
	n, err = f.WriteTo(&buf)
	if err != nil {
		f.Close()
		t.Fatalf("WriteTo failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close: %v", err)
	}
	if n != int64(len(testContent)) {
		t.Errorf("WriteTo length: got %d, expected %d", n, len(testContent))
	}
	if !bytes.Equal(buf.Bytes(), testContent) {
		t.Error("Downloaded content differs from uploaded content")
	}

	// io.Copy must now route through the same methods and stay equivalent.
	f, err = share.Open(filename)
	if err != nil {
		t.Fatalf("Failed to reopen file: %v", err)
	}
	var buf2 bytes.Buffer
	if _, err := io.Copy(&buf2, f); err != nil {
		f.Close()
		t.Fatalf("io.Copy from file failed: %v", err)
	}
	f.Close()
	if !bytes.Equal(buf2.Bytes(), testContent) {
		t.Error("io.Copy content differs from WriteTo content")
	}
}

func TestShare_Truncate(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("truncate")
	defer share.Remove(filename)

	if err := share.WriteFile(filename, []byte("0123456789"), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Shrink.
	if err := share.Truncate(filename, 4); err != nil {
		t.Fatalf("Truncate(4) failed: %v", err)
	}
	data, err := share.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read back: %v", err)
	}
	if !bytes.Equal(data, []byte("0123")) {
		t.Errorf("After shrink: got %q, expected %q", data, "0123")
	}

	// Grow: the extension must read back as zeros.
	if err := share.Truncate(filename, 8); err != nil {
		t.Fatalf("Truncate(8) failed: %v", err)
	}
	data, err = share.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read back: %v", err)
	}
	if !bytes.Equal(data, []byte("0123\x00\x00\x00\x00")) {
		t.Errorf("After grow: got %q, expected %q", data, "0123\x00\x00\x00\x00")
	}

	// A missing file is an error (FILE_OPEN disposition, no create).
	if err := share.Truncate(testFileName("truncate_missing"), 0); err == nil {
		t.Error("Truncate on missing file succeeded, expected error")
	}
}

func TestShare_Glob(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	dir := fmt.Sprintf("glob_test_%d", time.Now().UnixNano())
	if err := share.Mkdir(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	defer share.RemoveAll(dir)

	for _, name := range []string{"a.txt", "b.txt", "c.log"} {
		if err := share.WriteFile(dir+"\\"+name, []byte(name), 0644); err != nil {
			t.Fatalf("Failed to create %s: %v", name, err)
		}
	}

	matches, err := share.Glob(dir + "\\*.txt")
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	want := []string{dir + "\\a.txt", dir + "\\b.txt"}
	if len(matches) != len(want) {
		t.Fatalf("Glob matches: got %q, expected %q", matches, want)
	}
	for i := range want {
		if matches[i] != want[i] {
			t.Errorf("Glob match %d: got %q, expected %q", i, matches[i], want[i])
		}
	}

	// No matches is nil result, nil error.
	matches, err = share.Glob(dir + "\\*.exe")
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Glob(*.exe): got %q, expected no matches", matches)
	}
}

func TestFile_Readdirnames(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	dir := fmt.Sprintf("readdirnames_test_%d", time.Now().UnixNano())
	if err := share.Mkdir(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	defer share.RemoveAll(dir)

	wantNames := map[string]bool{"one.txt": true, "two.txt": true}
	for name := range wantNames {
		if err := share.WriteFile(dir+"\\"+name, []byte(name), 0644); err != nil {
			t.Fatalf("Failed to create %s: %v", name, err)
		}
	}

	// Share.OpenFile always opens with FILE_NON_DIRECTORY_FILE, so a
	// directory handle may not be obtainable; Readdirnames itself is what is
	// under test, not directory opening.
	f, err := share.Open(dir)
	if err != nil {
		t.Skipf("Cannot open a directory handle on this server: %v", err)
	}
	defer f.Close()

	names, err := f.Readdirnames(-1)
	if err != nil {
		t.Fatalf("Readdirnames failed: %v", err)
	}
	if len(names) != len(wantNames) {
		t.Fatalf("Readdirnames: got %q, expected %d names", names, len(wantNames))
	}
	for _, name := range names {
		if !wantNames[name] {
			t.Errorf("Readdirnames returned unexpected name %q", name)
		}
	}
}
