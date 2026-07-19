//go:build integration
// +build integration

package smb1_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	smb1 "github.com/macourteau/smb1client"
)

// Test configuration. The defaults address the dockerized Samba server started
// by integration/up.sh; each is overridable through the environment variables
// README.md documents, so the suite can also be pointed at real hardware:
//
//	SMB_SERVER=192.0.2.1:445 go test -tags=integration ./...
var (
	testHost     = envOr("SMB_SERVER", "localhost:10445")
	testUser     = envOr("SMB_USER", "smbtest")
	testPassword = envOr("SMB_PASSWORD", "smbtest")
	testDomain   = envOr("SMB_DOMAIN", "")
	testShare    = envOr("SMB_SHARE", "testshare")
)

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// Test helper: create a test session
func createTestSession(t *testing.T) (*smb1.Session, func()) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", testHost, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	d := &smb1.Dialer{
		Initiator: &smb1.NTLMInitiator{
			User:     testUser,
			Password: testPassword,
			Domain:   testDomain,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("Failed to dial: %v", err)
	}

	cleanup := func() {
		session.Logoff()
		conn.Close()
	}

	return session, cleanup
}

// Test helper: mount a test share
func mountTestShare(t *testing.T, session *smb1.Session) (*smb1.Share, func()) {
	t.Helper()

	share, err := session.Mount(testShare)
	if err != nil {
		t.Fatalf("Failed to mount share: %v", err)
	}

	cleanup := func() {
		share.Umount()
	}

	return share, cleanup
}

// Test helper: generate unique test filename
func testFileName(prefix string) string {
	return fmt.Sprintf("%s_%d.txt", prefix, time.Now().UnixNano())
}

// =============================================================================
// Connection Tests
// =============================================================================

func TestConnection_ValidCredentials(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	// If we get here, authentication was successful
	if session == nil {
		t.Fatal("Expected valid session, got nil")
	}
}

func TestConnection_InvalidCredentials(t *testing.T) {
	conn, err := net.DialTimeout("tcp", testHost, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	d := &smb1.Dialer{
		Initiator: &smb1.NTLMInitiator{
			User:     "invalid_user_" + fmt.Sprint(time.Now().UnixNano()),
			Password: "invalid_password_wrong",
			Domain:   testDomain,
		},
	}

	session, err := d.Dial(conn)
	if err == nil {
		// Some servers (typically legacy devices with "map to guest" enabled)
		// accept any unknown user as guest, so a successful dial is not a
		// client bug — there is just no way to provoke a credential failure.
		session.Logoff()
		t.Skip("server maps unknown users to guest; cannot test invalid credentials")
	}

	// Note: Authentication might succeed with empty credentials on some servers
	// Just verify we got an error of some kind
	t.Logf("Got expected error with invalid credentials: %v", err)
}

func TestConnection_Timeout(t *testing.T) {
	t.Skip("Timeout testing is unreliable in integration tests - tested in unit tests instead")

	// Note: This test is skipped because:
	// 1. Network operations might complete too fast for timeout to trigger
	// 2. Timeout behavior is better tested in controlled unit test environments
	// 3. Real integration with SMB server makes timing unpredictable
}

func TestConnection_ShareMount(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	if share == nil {
		t.Fatal("Expected valid share, got nil")
	}
}

// =============================================================================
// File Operations Tests
// =============================================================================

func TestFile_CreateWriteReadDelete(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("create_write_read")
	testContent := []byte("Hello from integration test!\nLine 2\nLine 3\n")

	// Create and write
	f, err := share.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	n, err := f.Write(testContent)
	if err != nil {
		f.Close()
		t.Fatalf("Failed to write: %v", err)
	}
	if n != len(testContent) {
		t.Errorf("Write length mismatch: wrote %d, expected %d", n, len(testContent))
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close: %v", err)
	}

	// Verify file exists with Stat
	stat, err := share.Stat(filename)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}
	if stat.Size() != int64(len(testContent)) {
		t.Errorf("Size mismatch: got %d, expected %d", stat.Size(), len(testContent))
	}

	// Read back
	readData, err := share.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if !bytes.Equal(readData, testContent) {
		t.Errorf("Content mismatch:\nExpected: %q\nGot: %q", testContent, readData)
	}

	// Delete
	if err := share.Remove(filename); err != nil {
		t.Fatalf("Failed to remove file: %v", err)
	}

	// Verify deleted
	_, err = share.Stat(filename)
	if err == nil {
		t.Fatal("Expected not found error after delete, got nil")
	}
	// Just verify we got an error (error message format varies by implementation)
	t.Logf("Got expected error after deletion: %v", err)
}

func TestFile_LargeFile(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("large_file")
	defer share.Remove(filename) // Cleanup

	// Create 100KB test data (smaller to avoid short write issues with SMB1)
	const size = 100 * 1024
	testData := make([]byte, size)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Write in chunks to avoid short write
	f, err := share.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}

	// Write in smaller chunks
	const chunkSize = 32 * 1024 // 32KB chunks
	for offset := 0; offset < size; {
		end := offset + chunkSize
		if end > size {
			end = size
		}
		n, err := f.Write(testData[offset:end])
		if err != nil {
			f.Close()
			t.Fatalf("Failed to write chunk at offset %d: %v", offset, err)
		}
		offset += n
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close large file: %v", err)
	}

	// Verify size
	stat, err := share.Stat(filename)
	if err != nil {
		t.Fatalf("Failed to stat large file: %v", err)
	}
	if stat.Size() != size {
		t.Errorf("Size mismatch: got %d, expected %d", stat.Size(), size)
	}

	// Read back and verify
	readData, err := share.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read large file: %v", err)
	}
	if len(readData) != size {
		t.Errorf("Read size mismatch: got %d, expected %d", len(readData), size)
	}
	if !bytes.Equal(readData, testData) {
		t.Error("Large file content mismatch")
	}
}

func TestFile_SpecialCharactersInName(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	testCases := []string{
		fmt.Sprintf("spaces in name %d.txt", time.Now().UnixNano()),
		fmt.Sprintf("dash-test-%d.txt", time.Now().UnixNano()),
		fmt.Sprintf("underscore_test_%d.txt", time.Now().UnixNano()),
		fmt.Sprintf("dots.in.name.%d.txt", time.Now().UnixNano()),
		fmt.Sprintf("numbers123_%d.txt", time.Now().UnixNano()),
	}

	for _, filename := range testCases {
		t.Run(filename, func(t *testing.T) {
			content := []byte("test content for special chars")

			if err := share.WriteFile(filename, content, 0644); err != nil {
				t.Fatalf("Failed to write file with special chars: %v", err)
			}

			readData, err := share.ReadFile(filename)
			if err != nil {
				t.Fatalf("Failed to read file with special chars: %v", err)
			}

			if !bytes.Equal(readData, content) {
				t.Error("Content mismatch for file with special chars")
			}

			if err := share.Remove(filename); err != nil {
				t.Fatalf("Failed to remove file with special chars: %v", err)
			}
		})
	}
}

func TestFile_EmptyFile(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("empty_file")
	defer share.Remove(filename)

	// Create empty file
	f, err := share.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close empty file: %v", err)
	}

	// Verify size is 0
	stat, err := share.Stat(filename)
	if err != nil {
		t.Fatalf("Failed to stat empty file: %v", err)
	}
	if stat.Size() != 0 {
		t.Errorf("Empty file size mismatch: got %d, expected 0", stat.Size())
	}

	// Read should return empty
	readData, err := share.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read empty file: %v", err)
	}
	if len(readData) != 0 {
		t.Errorf("Empty file read returned %d bytes, expected 0", len(readData))
	}
}

func TestFile_Rename(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	oldName := testFileName("renameagent-old")
	newName := testFileName("renameagent-new")
	content := []byte("content for rename test")

	// Create file
	if err := share.WriteFile(oldName, content, 0644); err != nil {
		t.Fatalf("Failed to create file for rename: %v", err)
	}
	defer share.Remove(oldName)
	defer share.Remove(newName)

	// Rename
	if err := share.Rename(oldName, newName); err != nil {
		t.Fatalf("Rename failed: %v", err)
	}

	// Verify old name doesn't exist
	if _, err := share.Stat(oldName); err == nil {
		t.Fatal("Old filename still exists after rename")
	}

	// Verify new name exists and content matches
	readData, err := share.ReadFile(newName)
	if err != nil {
		t.Fatalf("Failed to read renamed file: %v", err)
	}
	if !bytes.Equal(readData, content) {
		t.Error("Content mismatch after rename")
	}
}

func TestFile_RenameAcrossDirectories(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	srcDir := fmt.Sprintf("renameagent-src_%d", time.Now().UnixNano())
	dstDir := fmt.Sprintf("renameagent-dst_%d", time.Now().UnixNano())
	content := []byte("content moved between directories")

	for _, dir := range []string{srcDir, dstDir} {
		if err := share.Mkdir(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}
	defer share.RemoveAll(srcDir)
	defer share.RemoveAll(dstDir)

	// Forward slashes exercise path normalization on both arguments.
	oldPath := srcDir + "/moved.txt"
	newPath := dstDir + "/moved.txt"

	if err := share.WriteFile(oldPath, content, 0644); err != nil {
		t.Fatalf("Failed to create file for rename: %v", err)
	}

	if err := share.Rename(oldPath, newPath); err != nil {
		t.Fatalf("Rename across directories failed: %v", err)
	}

	if _, err := share.Stat(oldPath); err == nil {
		t.Fatal("Old path still exists after rename")
	}

	readData, err := share.ReadFile(newPath)
	if err != nil {
		t.Fatalf("Failed to read moved file: %v", err)
	}
	if !bytes.Equal(readData, content) {
		t.Error("Content mismatch after rename across directories")
	}
}

func TestDir_Rename(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	oldDir := fmt.Sprintf("renameagent-dir_%d", time.Now().UnixNano())
	newDir := fmt.Sprintf("renameagent-dirrenamed_%d", time.Now().UnixNano())
	content := []byte("file inside renamed directory")

	if err := share.Mkdir(oldDir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	defer share.RemoveAll(oldDir)
	defer share.RemoveAll(newDir)

	if err := share.WriteFile(oldDir+"/inner.txt", content, 0644); err != nil {
		t.Fatalf("Failed to create file in directory: %v", err)
	}

	if err := share.Rename(oldDir, newDir); err != nil {
		t.Fatalf("Directory rename failed: %v", err)
	}

	if _, err := share.Stat(oldDir); err == nil {
		t.Fatal("Old directory name still exists after rename")
	}

	stat, err := share.Stat(newDir)
	if err != nil {
		t.Fatalf("Failed to stat renamed directory: %v", err)
	}
	if !stat.IsDir() {
		t.Error("Renamed entry is not a directory")
	}

	readData, err := share.ReadFile(newDir + "/inner.txt")
	if err != nil {
		t.Fatalf("Failed to read file inside renamed directory: %v", err)
	}
	if !bytes.Equal(readData, content) {
		t.Error("Content mismatch inside renamed directory")
	}
}

func TestFile_RenameTargetExists(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	oldName := testFileName("renameagent-collide-old")
	newName := testFileName("renameagent-collide-new")
	oldContent := []byte("source content")
	newContent := []byte("existing target content")

	if err := share.WriteFile(oldName, oldContent, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}
	defer share.Remove(oldName)

	if err := share.WriteFile(newName, newContent, 0644); err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}
	defer share.Remove(newName)

	// SMB_COM_RENAME does not overwrite an existing target; the server
	// reports STATUS_OBJECT_NAME_COLLISION, surfaced as an exists error.
	err := share.Rename(oldName, newName)
	if err == nil {
		t.Fatal("Rename onto existing target succeeded, expected collision error")
	}
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) {
		t.Errorf("Rename error is %T, expected *os.LinkError", err)
	}
	if !smb1.IsExistError(err) {
		t.Errorf("IsExistError(%v) = false, expected true", err)
	}

	// Both files must be intact after the failed rename.
	readData, err := share.ReadFile(oldName)
	if err != nil {
		t.Fatalf("Failed to read source after failed rename: %v", err)
	}
	if !bytes.Equal(readData, oldContent) {
		t.Error("Source content changed after failed rename")
	}
	readData, err = share.ReadFile(newName)
	if err != nil {
		t.Fatalf("Failed to read target after failed rename: %v", err)
	}
	if !bytes.Equal(readData, newContent) {
		t.Error("Target content changed after failed rename")
	}
}

// =============================================================================
// Directory Operations Tests
// =============================================================================

func TestDir_CreateListRemove(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	dirname := testFileName("test_dir")

	// Create directory
	if err := share.Mkdir(dirname, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// Verify it exists and is a directory
	stat, err := share.Stat(dirname)
	if err != nil {
		share.Remove(dirname)
		t.Fatalf("Failed to stat directory: %v", err)
	}
	if !stat.IsDir() {
		share.Remove(dirname)
		t.Error("Created path is not a directory")
	}

	// List parent directory and verify our dir is there
	entries, err := share.ReadDir("")
	if err != nil {
		share.Remove(dirname)
		t.Fatalf("Failed to list directory: %v", err)
	}

	found := false
	for _, entry := range entries {
		if entry.Name() == dirname && entry.IsDir() {
			found = true
			break
		}
	}
	if !found {
		share.Remove(dirname)
		t.Error("Created directory not found in listing")
	}

	// Remove directory
	if err := share.Remove(dirname); err != nil {
		t.Fatalf("Failed to remove directory: %v", err)
	}

	// Verify removed
	_, err = share.Stat(dirname)
	if err == nil {
		t.Fatal("Directory still exists after removal")
	}
	if !smb1.IsNotFoundError(err) {
		t.Errorf("Expected not found error, got: %v", err)
	}
}

func TestDir_NestedDirectories(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	baseDir := testFileName("nested_base")
	subDir := baseDir + "\\subdir"
	subSubDir := subDir + "\\subsubdir"

	// Create nested structure with MkdirAll
	if err := share.MkdirAll(subSubDir, 0755); err != nil {
		t.Fatalf("Failed to create nested directories: %v", err)
	}

	// Verify all levels exist
	for _, dir := range []string{baseDir, subDir, subSubDir} {
		stat, err := share.Stat(dir)
		if err != nil {
			t.Errorf("Failed to stat %s: %v", dir, err)
			continue
		}
		if !stat.IsDir() {
			t.Errorf("%s is not a directory", dir)
		}
	}

	// Create a file in the deepest directory
	filename := subSubDir + "\\test.txt"
	content := []byte("nested file content")
	if err := share.WriteFile(filename, content, 0644); err != nil {
		t.Errorf("Failed to create file in nested directory: %v", err)
	} else {
		// Verify file content
		readData, err := share.ReadFile(filename)
		if err != nil {
			t.Errorf("Failed to read nested file: %v", err)
		} else if !bytes.Equal(readData, content) {
			t.Error("Nested file content mismatch")
		}
		share.Remove(filename)
	}

	// Cleanup (remove from deepest to shallowest)
	share.Remove(subSubDir)
	share.Remove(subDir)
	share.Remove(baseDir)
}

func TestDir_ReadDirWithFiles(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	dirname := testFileName("dir_with_files")

	// Create directory
	if err := share.Mkdir(dirname, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	defer share.Remove(dirname)

	// Create multiple files in the directory
	fileNames := []string{"file1.txt", "file2.txt", "file3.txt"}
	for _, fname := range fileNames {
		path := dirname + "\\" + fname
		if err := share.WriteFile(path, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", fname, err)
		}
		defer share.Remove(path)
	}

	// Read directory
	entries, err := share.ReadDir(dirname)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	// Verify we got all files
	if len(entries) != len(fileNames) {
		t.Errorf("Expected %d entries, got %d", len(fileNames), len(entries))
	}

	// Verify file names
	foundFiles := make(map[string]bool)
	for _, entry := range entries {
		foundFiles[entry.Name()] = true
		if entry.IsDir() {
			t.Errorf("File %s reported as directory", entry.Name())
		}
	}

	for _, fname := range fileNames {
		if !foundFiles[fname] {
			t.Errorf("File %s not found in directory listing", fname)
		}
	}
}

// =============================================================================
// Binary Data Tests
// =============================================================================

func TestBinary_AllByteValues(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("binary_all_bytes")
	defer share.Remove(filename)

	// Create data with all byte values 0x00 - 0xFF
	testData := make([]byte, 256)
	for i := 0; i < 256; i++ {
		testData[i] = byte(i)
	}

	// Write binary data
	if err := share.WriteFile(filename, testData, 0644); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	// Read back
	readData, err := share.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read binary data: %v", err)
	}

	// Verify integrity
	if len(readData) != len(testData) {
		t.Fatalf("Binary data length mismatch: got %d, expected %d", len(readData), len(testData))
	}

	for i := 0; i < 256; i++ {
		if readData[i] != testData[i] {
			t.Errorf("Binary data mismatch at byte %d: got 0x%02X, expected 0x%02X", i, readData[i], testData[i])
		}
	}
}

func TestBinary_RandomData(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("binary_random")
	defer share.Remove(filename)

	// Generate random binary data
	const size = 1024 * 1024 // 1MB
	testData := make([]byte, size)
	if _, err := rand.Read(testData); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	// Write
	if err := share.WriteFile(filename, testData, 0644); err != nil {
		t.Fatalf("Failed to write random binary data: %v", err)
	}

	// Read back
	readData, err := share.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read random binary data: %v", err)
	}

	// Verify
	if !bytes.Equal(readData, testData) {
		t.Error("Random binary data integrity check failed")
	}
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestEdge_FileNotFound(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	nonExistentFile := "nonexistent_file_" + fmt.Sprint(time.Now().UnixNano()) + ".txt"

	// Try to open non-existent file
	_, err := share.Open(nonExistentFile)
	if err == nil {
		t.Fatal("Expected error when opening non-existent file, got nil")
	}
	if !smb1.IsNotFoundError(err) {
		t.Errorf("Expected IsNotFoundError, got: %v", err)
	}

	// Try to stat non-existent file
	_, err = share.Stat(nonExistentFile)
	if err == nil {
		t.Fatal("Expected error when stating non-existent file, got nil")
	}
	if !smb1.IsNotFoundError(err) {
		t.Errorf("Expected IsNotFoundError, got: %v", err)
	}

	// Try to delete non-existent file
	err = share.Remove(nonExistentFile)
	if err == nil {
		t.Fatal("Expected error when removing non-existent file, got nil")
	}
	if !smb1.IsNotFoundError(err) {
		t.Errorf("Expected IsNotFoundError, got: %v", err)
	}
}

func TestEdge_InvalidPaths(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	// Path validation rejects only ".." components that would escape the
	// share root; a ".." that stays inside the share is legal and resolved
	// by the server (go-smb2 is even laxer and forwards all of them).
	invalidPaths := []string{
		"../parent_dir_access",
		"..\\parent_dir_access",
	}

	for _, path := range invalidPaths {
		t.Run(path, func(t *testing.T) {
			_, err := share.Create(path)
			if err == nil {
				share.Remove(path)
				t.Error("Expected error for invalid path, got nil")
			}
		})
	}

	t.Run("in-share dot-dot resolves", func(t *testing.T) {
		f, err := share.Create("indir/../inshare_traversal")
		if err != nil {
			t.Fatalf("Create with in-share ..: %v", err)
		}
		f.Close()
		defer share.Remove("inshare_traversal")

		// The server resolves the components, so the file lands at the root.
		if _, err := share.Stat("inshare_traversal"); err != nil {
			t.Errorf("resolved file not found at share root: %v", err)
		}
	})
}

func TestEdge_OverwriteExistingFile(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("overwrite_test")
	defer share.Remove(filename)

	// Create initial file
	initialContent := []byte("initial content")
	if err := share.WriteFile(filename, initialContent, 0644); err != nil {
		t.Fatalf("Failed to create initial file: %v", err)
	}

	// Overwrite with new content
	newContent := []byte("new content that is different")
	if err := share.WriteFile(filename, newContent, 0644); err != nil {
		t.Fatalf("Failed to overwrite file: %v", err)
	}

	// Verify new content
	readData, err := share.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read overwritten file: %v", err)
	}
	if !bytes.Equal(readData, newContent) {
		t.Errorf("Overwrite failed: got %q, expected %q", readData, newContent)
	}
}

func TestEdge_FileOpenRead(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("open_read_test")
	testContent := []byte("content for open/read test")

	// Create file
	if err := share.WriteFile(filename, testContent, 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	defer share.Remove(filename)

	// Open file for reading
	f, err := share.Open(filename)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	// Read using io.ReadAll
	readData, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if !bytes.Equal(readData, testContent) {
		t.Errorf("Content mismatch: got %q, expected %q", readData, testContent)
	}
}

func TestEdge_LongFilename(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	// Create a reasonably long filename (but not too long to avoid hitting limits)
	longName := fmt.Sprintf("long_filename_%s_%d.txt",
		strings.Repeat("x", 100),
		time.Now().UnixNano())

	content := []byte("content for long filename test")

	// Try to create file with long name
	err := share.WriteFile(longName, content, 0644)
	if err != nil {
		// Long filenames might not be supported, just log warning
		t.Logf("Long filename not supported (this may be expected): %v", err)
		return
	}

	defer share.Remove(longName)

	// Verify we can read it back
	readData, err := share.ReadFile(longName)
	if err != nil {
		t.Errorf("Failed to read file with long name: %v", err)
	} else if !bytes.Equal(readData, content) {
		t.Error("Content mismatch for long filename")
	}
}

// =============================================================================
// Concurrent Operations Tests
// =============================================================================

func TestConcurrent_MultipleReads(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	filename := testFileName("concurrent_reads")
	content := []byte("content for concurrent read test")

	// Create test file
	if err := share.WriteFile(filename, content, 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	defer share.Remove(filename)

	// Launch multiple concurrent reads
	const numReaders = 5
	done := make(chan error, numReaders)

	for i := 0; i < numReaders; i++ {
		go func(n int) {
			readData, err := share.ReadFile(filename)
			if err != nil {
				done <- fmt.Errorf("reader %d failed: %v", n, err)
				return
			}
			if !bytes.Equal(readData, content) {
				done <- fmt.Errorf("reader %d: content mismatch", n)
				return
			}
			done <- nil
		}(i)
	}

	// Wait for all readers
	for i := 0; i < numReaders; i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}

func TestConcurrent_MultipleFiles(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, shareCleanup := mountTestShare(t, session)
	defer shareCleanup()

	// Create multiple files concurrently
	const numFiles = 10
	done := make(chan error, numFiles)
	baseTime := time.Now().UnixNano()

	for i := 0; i < numFiles; i++ {
		go func(n int) {
			filename := fmt.Sprintf("concurrent_file_%d_%d.txt", baseTime, n)
			content := []byte(fmt.Sprintf("content for file %d", n))

			// Create and write
			if err := share.WriteFile(filename, content, 0644); err != nil {
				done <- fmt.Errorf("failed to create file %d: %v", n, err)
				return
			}

			// Read back and verify
			readData, err := share.ReadFile(filename)
			if err != nil {
				share.Remove(filename)
				done <- fmt.Errorf("failed to read file %d: %v", n, err)
				return
			}

			if !bytes.Equal(readData, content) {
				share.Remove(filename)
				done <- fmt.Errorf("file %d: content mismatch", n)
				return
			}

			// Cleanup
			if err := share.Remove(filename); err != nil {
				done <- fmt.Errorf("failed to remove file %d: %v", n, err)
				return
			}

			done <- nil
		}(i)
	}

	// Wait for all operations
	for i := 0; i < numFiles; i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}

func TestSession_ListSharenames(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	shares, err := session.ListSharenames()
	if err != nil {
		t.Fatalf("Failed to list shares: %v", err)
	}

	if len(shares) == 0 {
		t.Fatal("Expected at least one share, got zero")
	}

	t.Logf("Found %d shares:", len(shares))
	for i, share := range shares {
		t.Logf("  %d. %s", i+1, share)
	}

	// Verify that the test share is in the list
	found := false
	for _, share := range shares {
		if strings.EqualFold(share, testShare) {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected share %q not found in list", testShare)
	}

	// Verify IPC$ is in the list (should always be present)
	foundIPC := false
	for _, share := range shares {
		if strings.EqualFold(share, "IPC$") {
			foundIPC = true
			break
		}
	}

	if !foundIPC {
		t.Error("Expected IPC$ share not found in list")
	}
}
