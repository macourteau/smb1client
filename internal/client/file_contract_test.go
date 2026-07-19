package client

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// TestFileStat tests File.Stat() method.
func TestFileStat(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()
	done := make(chan struct{})
	var stat *FileStat
	var err error

	go func() {
		stat, err = f.Stat(ctx)
		close(done)
	}()

	// Wait for first request (SMB_QUERY_FILE_BASIC_INFO)
	time.Sleep(10 * time.Millisecond)

	// Send basic info response
	respHeader1 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader1.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader1.Status = smb1.STATUS_SUCCESS
	respHeader1.MID = 0

	// Build TRANS2 response for basic info
	basicInfoData := make([]byte, 40)
	binary.LittleEndian.PutUint64(basicInfoData[0:8], 132450912000000000)   // CreationTime
	binary.LittleEndian.PutUint64(basicInfoData[8:16], 132450912000000000)  // LastAccessTime
	binary.LittleEndian.PutUint64(basicInfoData[16:24], 132450912000000000) // LastWriteTime
	binary.LittleEndian.PutUint64(basicInfoData[24:32], 132450912000000000) // ChangeTime
	binary.LittleEndian.PutUint32(basicInfoData[32:36], smb1.FILE_ATTRIBUTE_NORMAL)

	// TRANS2 response structure:
	// WordCount params (20 bytes) describe where data is located
	// ByteCount data section contains the actual file info
	// Offsets are absolute from start of SMB header
	dataStart := uint16(smb1.HeaderSize + 1 + 20 + 2) // Header + WordCount + Params + ByteCount = 55

	trans2Params1 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params1[0:2], 0)                            // TotalParameterCount
	binary.LittleEndian.PutUint16(trans2Params1[2:4], uint16(len(basicInfoData)))   // TotalDataCount
	binary.LittleEndian.PutUint16(trans2Params1[4:6], 0)                            // Reserved
	binary.LittleEndian.PutUint16(trans2Params1[6:8], 0)                            // ParameterCount
	binary.LittleEndian.PutUint16(trans2Params1[8:10], 0)                           // ParameterOffset
	binary.LittleEndian.PutUint16(trans2Params1[10:12], 0)                          // ParameterDisplacement
	binary.LittleEndian.PutUint16(trans2Params1[12:14], uint16(len(basicInfoData))) // DataCount
	binary.LittleEndian.PutUint16(trans2Params1[14:16], dataStart)                  // DataOffset
	binary.LittleEndian.PutUint16(trans2Params1[16:18], 0)                          // DataDisplacement
	trans2Params1[18] = 0                                                           // SetupCount
	trans2Params1[19] = 0                                                           // Reserved2

	getMockConn(tree.Session.conn).addResponse(respHeader1, trans2Params1, basicInfoData)

	// Wait for second request (SMB_QUERY_FILE_STANDARD_INFO)
	time.Sleep(10 * time.Millisecond)

	// Send standard info response
	respHeader2 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader2.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader2.Status = smb1.STATUS_SUCCESS
	respHeader2.MID = 1

	standardInfoData := make([]byte, 24)
	binary.LittleEndian.PutUint64(standardInfoData[0:8], 1024) // AllocationSize
	binary.LittleEndian.PutUint64(standardInfoData[8:16], 512) // EndOfFile
	binary.LittleEndian.PutUint32(standardInfoData[16:20], 1)  // NumberOfLinks
	standardInfoData[20] = 0                                   // DeletePending
	standardInfoData[21] = 0                                   // Directory

	trans2Params2 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params2[0:2], 0)                               // TotalParameterCount
	binary.LittleEndian.PutUint16(trans2Params2[2:4], uint16(len(standardInfoData)))   // TotalDataCount
	binary.LittleEndian.PutUint16(trans2Params2[4:6], 0)                               // Reserved
	binary.LittleEndian.PutUint16(trans2Params2[6:8], 0)                               // ParameterCount
	binary.LittleEndian.PutUint16(trans2Params2[8:10], 0)                              // ParameterOffset
	binary.LittleEndian.PutUint16(trans2Params2[10:12], 0)                             // ParameterDisplacement
	binary.LittleEndian.PutUint16(trans2Params2[12:14], uint16(len(standardInfoData))) // DataCount
	binary.LittleEndian.PutUint16(trans2Params2[14:16], dataStart)                     // DataOffset
	binary.LittleEndian.PutUint16(trans2Params2[16:18], 0)                             // DataDisplacement
	trans2Params2[18] = 0                                                              // SetupCount
	trans2Params2[19] = 0                                                              // Reserved2

	getMockConn(tree.Session.conn).addResponse(respHeader2, trans2Params2, standardInfoData)

	// Wait for Stat to complete
	select {
	case <-done:
		if err != nil {
			t.Fatalf("Stat failed: %v", err)
		}
		if stat == nil {
			t.Fatal("stat is nil")
		}
		if stat.EndOfFile != 512 {
			t.Errorf("file size: got %d, want 512", stat.EndOfFile)
		}
		if stat.AllocationSize != 1024 {
			t.Errorf("allocation size: got %d, want 1024", stat.AllocationSize)
		}
		if stat.FileAttributes != smb1.FILE_ATTRIBUTE_NORMAL {
			t.Errorf("attributes: got 0x%08X, want 0x%08X", stat.FileAttributes, smb1.FILE_ATTRIBUTE_NORMAL)
		}
		if stat.FileName != "test.txt" {
			t.Errorf("filename: got %q, want %q", stat.FileName, "test.txt")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Stat timed out")
	}
}

// TestFileTruncate tests File.Truncate() method.
func TestFileTruncate(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()
	done := make(chan struct{})
	var err error

	go func() {
		err = f.Truncate(1024, ctx)
		close(done)
	}()

	// Wait for request
	time.Sleep(10 * time.Millisecond)

	// Send response
	respHeader := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = 0

	trans2Params := make([]byte, 20)
	// Empty response for SET_FILE_INFORMATION

	getMockConn(tree.Session.conn).addResponse(respHeader, trans2Params, nil)

	// Wait for Truncate to complete
	select {
	case <-done:
		if err != nil {
			t.Fatalf("Truncate failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Truncate timed out")
	}
}

// TestFileTruncateNegativeSize tests truncate with negative size.
func TestFileTruncateNegativeSize(t *testing.T) {
	tree := setupTestTree()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()
	err := f.Truncate(-1, ctx)
	if err == nil {
		t.Error("Truncate with negative size should return error")
	}
}

// TestFileTruncateZeroSize tests truncate to zero (empty file).
func TestFileTruncateZeroSize(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()
	done := make(chan struct{})
	var err error

	go func() {
		err = f.Truncate(0, ctx)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)

	respHeader := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = 0

	trans2Params := make([]byte, 20)
	getMockConn(tree.Session.conn).addResponse(respHeader, trans2Params, nil)

	select {
	case <-done:
		if err != nil {
			t.Fatalf("Truncate to zero failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Truncate timed out")
	}
}

// TestFileSeekEnd tests Seek with io.SeekEnd.
func TestFileSeekEnd(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()
	done := make(chan struct{})
	var offset int64
	var err error

	go func() {
		// Seek to end of file (offset 0 from end)
		offset, err = f.SeekContext(0, io.SeekEnd, ctx)
		close(done)
	}()

	// Wait for first request (SMB_QUERY_FILE_BASIC_INFO)
	time.Sleep(10 * time.Millisecond)

	// Send basic info response
	respHeader1 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader1.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader1.Status = smb1.STATUS_SUCCESS
	respHeader1.MID = 0

	basicInfoData := make([]byte, 40)
	binary.LittleEndian.PutUint64(basicInfoData[0:8], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[8:16], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[16:24], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[24:32], 132450912000000000)
	binary.LittleEndian.PutUint32(basicInfoData[32:36], smb1.FILE_ATTRIBUTE_NORMAL)

	dataStart := uint16(smb1.HeaderSize + 1 + 20 + 2)

	trans2Params1 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params1[0:2], 0)
	binary.LittleEndian.PutUint16(trans2Params1[2:4], uint16(len(basicInfoData)))
	binary.LittleEndian.PutUint16(trans2Params1[4:6], 0)
	binary.LittleEndian.PutUint16(trans2Params1[6:8], 0)
	binary.LittleEndian.PutUint16(trans2Params1[8:10], 0)
	binary.LittleEndian.PutUint16(trans2Params1[10:12], 0)
	binary.LittleEndian.PutUint16(trans2Params1[12:14], uint16(len(basicInfoData)))
	binary.LittleEndian.PutUint16(trans2Params1[14:16], dataStart)
	binary.LittleEndian.PutUint16(trans2Params1[16:18], 0)
	trans2Params1[18] = 0
	trans2Params1[19] = 0

	getMockConn(tree.Session.conn).addResponse(respHeader1, trans2Params1, basicInfoData)

	// Wait for second request (SMB_QUERY_FILE_STANDARD_INFO)
	time.Sleep(10 * time.Millisecond)

	// Send standard info response with file size = 1000
	respHeader2 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader2.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader2.Status = smb1.STATUS_SUCCESS
	respHeader2.MID = 1

	standardInfoData := make([]byte, 24)
	binary.LittleEndian.PutUint64(standardInfoData[0:8], 2048)  // AllocationSize
	binary.LittleEndian.PutUint64(standardInfoData[8:16], 1000) // EndOfFile
	binary.LittleEndian.PutUint32(standardInfoData[16:20], 1)
	standardInfoData[20] = 0
	standardInfoData[21] = 0

	trans2Params2 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params2[0:2], 0)
	binary.LittleEndian.PutUint16(trans2Params2[2:4], uint16(len(standardInfoData)))
	binary.LittleEndian.PutUint16(trans2Params2[4:6], 0)
	binary.LittleEndian.PutUint16(trans2Params2[6:8], 0)
	binary.LittleEndian.PutUint16(trans2Params2[8:10], 0)
	binary.LittleEndian.PutUint16(trans2Params2[10:12], 0)
	binary.LittleEndian.PutUint16(trans2Params2[12:14], uint16(len(standardInfoData)))
	binary.LittleEndian.PutUint16(trans2Params2[14:16], dataStart)
	binary.LittleEndian.PutUint16(trans2Params2[16:18], 0)
	trans2Params2[18] = 0
	trans2Params2[19] = 0

	getMockConn(tree.Session.conn).addResponse(respHeader2, trans2Params2, standardInfoData)

	// Wait for Seek to complete
	select {
	case <-done:
		if err != nil {
			t.Fatalf("Seek(0, SeekEnd) failed: %v", err)
		}
		if offset != 1000 {
			t.Errorf("offset: got %d, want 1000", offset)
		}
		// Verify internal offset was updated
		f.mu.Lock()
		if f.offset != 1000 {
			t.Errorf("internal offset: got %d, want 1000", f.offset)
		}
		f.mu.Unlock()
	case <-time.After(1 * time.Second):
		t.Fatal("Seek timed out")
	}
}

// TestFileSeekEndWithNegativeOffset tests Seek to before end of file.
func TestFileSeekEndWithNegativeOffset(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()
	done := make(chan struct{})
	var offset int64
	var err error

	go func() {
		// Seek to 100 bytes before end of file
		offset, err = f.SeekContext(-100, io.SeekEnd, ctx)
		close(done)
	}()

	// Wait for first request (SMB_QUERY_FILE_BASIC_INFO)
	time.Sleep(10 * time.Millisecond)

	respHeader1 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader1.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader1.Status = smb1.STATUS_SUCCESS
	respHeader1.MID = 0

	basicInfoData := make([]byte, 40)
	binary.LittleEndian.PutUint64(basicInfoData[0:8], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[8:16], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[16:24], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[24:32], 132450912000000000)
	binary.LittleEndian.PutUint32(basicInfoData[32:36], smb1.FILE_ATTRIBUTE_NORMAL)

	dataStart := uint16(smb1.HeaderSize + 1 + 20 + 2)

	trans2Params1 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params1[0:2], 0)
	binary.LittleEndian.PutUint16(trans2Params1[2:4], uint16(len(basicInfoData)))
	binary.LittleEndian.PutUint16(trans2Params1[4:6], 0)
	binary.LittleEndian.PutUint16(trans2Params1[6:8], 0)
	binary.LittleEndian.PutUint16(trans2Params1[8:10], 0)
	binary.LittleEndian.PutUint16(trans2Params1[10:12], 0)
	binary.LittleEndian.PutUint16(trans2Params1[12:14], uint16(len(basicInfoData)))
	binary.LittleEndian.PutUint16(trans2Params1[14:16], dataStart)
	binary.LittleEndian.PutUint16(trans2Params1[16:18], 0)
	trans2Params1[18] = 0
	trans2Params1[19] = 0

	getMockConn(tree.Session.conn).addResponse(respHeader1, trans2Params1, basicInfoData)

	time.Sleep(10 * time.Millisecond)

	// Send standard info response with file size = 1000
	respHeader2 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader2.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader2.Status = smb1.STATUS_SUCCESS
	respHeader2.MID = 1

	standardInfoData := make([]byte, 24)
	binary.LittleEndian.PutUint64(standardInfoData[0:8], 2048)
	binary.LittleEndian.PutUint64(standardInfoData[8:16], 1000) // File size
	binary.LittleEndian.PutUint32(standardInfoData[16:20], 1)
	standardInfoData[20] = 0
	standardInfoData[21] = 0

	trans2Params2 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params2[0:2], 0)
	binary.LittleEndian.PutUint16(trans2Params2[2:4], uint16(len(standardInfoData)))
	binary.LittleEndian.PutUint16(trans2Params2[4:6], 0)
	binary.LittleEndian.PutUint16(trans2Params2[6:8], 0)
	binary.LittleEndian.PutUint16(trans2Params2[8:10], 0)
	binary.LittleEndian.PutUint16(trans2Params2[10:12], 0)
	binary.LittleEndian.PutUint16(trans2Params2[12:14], uint16(len(standardInfoData)))
	binary.LittleEndian.PutUint16(trans2Params2[14:16], dataStart)
	binary.LittleEndian.PutUint16(trans2Params2[16:18], 0)
	trans2Params2[18] = 0
	trans2Params2[19] = 0

	getMockConn(tree.Session.conn).addResponse(respHeader2, trans2Params2, standardInfoData)

	select {
	case <-done:
		if err != nil {
			t.Fatalf("Seek(-100, SeekEnd) failed: %v", err)
		}
		expectedOffset := int64(1000 - 100) // 900
		if offset != expectedOffset {
			t.Errorf("offset: got %d, want %d", offset, expectedOffset)
		}
		f.mu.Lock()
		if f.offset != expectedOffset {
			t.Errorf("internal offset: got %d, want %d", f.offset, expectedOffset)
		}
		f.mu.Unlock()
	case <-time.After(1 * time.Second):
		t.Fatal("Seek timed out")
	}
}

// TestFileSeekEndNegativeResult tests SeekEnd resulting in negative offset.
func TestFileSeekEndNegativeResult(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()
	done := make(chan struct{})
	var err error

	go func() {
		// Try to seek to before start of file (should fail)
		_, err = f.SeekContext(-2000, io.SeekEnd, ctx)
		close(done)
	}()

	// Respond to stat queries
	time.Sleep(10 * time.Millisecond)

	respHeader1 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader1.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader1.Status = smb1.STATUS_SUCCESS
	respHeader1.MID = 0

	basicInfoData := make([]byte, 40)
	binary.LittleEndian.PutUint64(basicInfoData[0:8], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[8:16], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[16:24], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[24:32], 132450912000000000)
	binary.LittleEndian.PutUint32(basicInfoData[32:36], smb1.FILE_ATTRIBUTE_NORMAL)

	dataStart := uint16(smb1.HeaderSize + 1 + 20 + 2)

	trans2Params1 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params1[0:2], 0)
	binary.LittleEndian.PutUint16(trans2Params1[2:4], uint16(len(basicInfoData)))
	binary.LittleEndian.PutUint16(trans2Params1[4:6], 0)
	binary.LittleEndian.PutUint16(trans2Params1[6:8], 0)
	binary.LittleEndian.PutUint16(trans2Params1[8:10], 0)
	binary.LittleEndian.PutUint16(trans2Params1[10:12], 0)
	binary.LittleEndian.PutUint16(trans2Params1[12:14], uint16(len(basicInfoData)))
	binary.LittleEndian.PutUint16(trans2Params1[14:16], dataStart)
	binary.LittleEndian.PutUint16(trans2Params1[16:18], 0)
	trans2Params1[18] = 0
	trans2Params1[19] = 0

	getMockConn(tree.Session.conn).addResponse(respHeader1, trans2Params1, basicInfoData)

	time.Sleep(10 * time.Millisecond)

	respHeader2 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader2.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader2.Status = smb1.STATUS_SUCCESS
	respHeader2.MID = 1

	standardInfoData := make([]byte, 24)
	binary.LittleEndian.PutUint64(standardInfoData[0:8], 2048)
	binary.LittleEndian.PutUint64(standardInfoData[8:16], 1000) // File size
	binary.LittleEndian.PutUint32(standardInfoData[16:20], 1)
	standardInfoData[20] = 0
	standardInfoData[21] = 0

	trans2Params2 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params2[0:2], 0)
	binary.LittleEndian.PutUint16(trans2Params2[2:4], uint16(len(standardInfoData)))
	binary.LittleEndian.PutUint16(trans2Params2[4:6], 0)
	binary.LittleEndian.PutUint16(trans2Params2[6:8], 0)
	binary.LittleEndian.PutUint16(trans2Params2[8:10], 0)
	binary.LittleEndian.PutUint16(trans2Params2[10:12], 0)
	binary.LittleEndian.PutUint16(trans2Params2[12:14], uint16(len(standardInfoData)))
	binary.LittleEndian.PutUint16(trans2Params2[14:16], dataStart)
	binary.LittleEndian.PutUint16(trans2Params2[16:18], 0)
	trans2Params2[18] = 0
	trans2Params2[19] = 0

	getMockConn(tree.Session.conn).addResponse(respHeader2, trans2Params2, standardInfoData)

	select {
	case <-done:
		if err == nil {
			t.Error("Seek with negative result should return error")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Seek timed out")
	}
}

// TestFileSeekCombined tests all three seek modes.
func TestFileSeekCombined(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()

	// Test SeekStart
	offset, err := f.SeekContext(100, io.SeekStart, ctx)
	if err != nil {
		t.Fatalf("Seek(100, SeekStart) failed: %v", err)
	}
	if offset != 100 {
		t.Errorf("SeekStart: got %d, want 100", offset)
	}

	// Test SeekCurrent
	offset, err = f.SeekContext(50, io.SeekCurrent, ctx)
	if err != nil {
		t.Fatalf("Seek(50, SeekCurrent) failed: %v", err)
	}
	if offset != 150 {
		t.Errorf("SeekCurrent: got %d, want 150", offset)
	}

	// Test SeekEnd - need to provide mock responses
	done := make(chan struct{})
	go func() {
		offset, err = f.SeekContext(-50, io.SeekEnd, ctx)
		close(done)
	}()

	// Respond to stat queries
	time.Sleep(10 * time.Millisecond)

	respHeader1 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader1.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader1.Status = smb1.STATUS_SUCCESS
	respHeader1.MID = 0

	basicInfoData := make([]byte, 40)
	binary.LittleEndian.PutUint64(basicInfoData[0:8], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[8:16], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[16:24], 132450912000000000)
	binary.LittleEndian.PutUint64(basicInfoData[24:32], 132450912000000000)
	binary.LittleEndian.PutUint32(basicInfoData[32:36], smb1.FILE_ATTRIBUTE_NORMAL)

	dataStart := uint16(smb1.HeaderSize + 1 + 20 + 2)

	trans2Params1 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params1[0:2], 0)
	binary.LittleEndian.PutUint16(trans2Params1[2:4], uint16(len(basicInfoData)))
	binary.LittleEndian.PutUint16(trans2Params1[4:6], 0)
	binary.LittleEndian.PutUint16(trans2Params1[6:8], 0)
	binary.LittleEndian.PutUint16(trans2Params1[8:10], 0)
	binary.LittleEndian.PutUint16(trans2Params1[10:12], 0)
	binary.LittleEndian.PutUint16(trans2Params1[12:14], uint16(len(basicInfoData)))
	binary.LittleEndian.PutUint16(trans2Params1[14:16], dataStart)
	binary.LittleEndian.PutUint16(trans2Params1[16:18], 0)
	trans2Params1[18] = 0
	trans2Params1[19] = 0

	getMockConn(tree.Session.conn).addResponse(respHeader1, trans2Params1, basicInfoData)

	time.Sleep(10 * time.Millisecond)

	respHeader2 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader2.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader2.Status = smb1.STATUS_SUCCESS
	respHeader2.MID = 1

	standardInfoData := make([]byte, 24)
	binary.LittleEndian.PutUint64(standardInfoData[0:8], 2048)
	binary.LittleEndian.PutUint64(standardInfoData[8:16], 500) // File size
	binary.LittleEndian.PutUint32(standardInfoData[16:20], 1)
	standardInfoData[20] = 0
	standardInfoData[21] = 0

	trans2Params2 := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params2[0:2], 0)
	binary.LittleEndian.PutUint16(trans2Params2[2:4], uint16(len(standardInfoData)))
	binary.LittleEndian.PutUint16(trans2Params2[4:6], 0)
	binary.LittleEndian.PutUint16(trans2Params2[6:8], 0)
	binary.LittleEndian.PutUint16(trans2Params2[8:10], 0)
	binary.LittleEndian.PutUint16(trans2Params2[10:12], 0)
	binary.LittleEndian.PutUint16(trans2Params2[12:14], uint16(len(standardInfoData)))
	binary.LittleEndian.PutUint16(trans2Params2[14:16], dataStart)
	binary.LittleEndian.PutUint16(trans2Params2[16:18], 0)
	trans2Params2[18] = 0
	trans2Params2[19] = 0

	getMockConn(tree.Session.conn).addResponse(respHeader2, trans2Params2, standardInfoData)

	select {
	case <-done:
		if err != nil {
			t.Fatalf("Seek(-50, SeekEnd) failed: %v", err)
		}
		expectedOffset := int64(500 - 50) // 450
		if offset != expectedOffset {
			t.Errorf("SeekEnd: got %d, want %d", offset, expectedOffset)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("SeekEnd timed out")
	}
}

// statFileName runs File.Stat against the mock connection for a file opened
// under the given path and returns the FileName the stat reports. The two
// canned responses answer the SMB_QUERY_FILE_BASIC_INFO and
// SMB_QUERY_FILE_STANDARD_INFO TRANS2 requests Stat issues.
func statFileName(t *testing.T, name string) string {
	t.Helper()

	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    name,
		offset:  0,
	}

	ctx := context.Background()
	done := make(chan struct{})
	var stat *FileStat
	var err error

	go func() {
		stat, err = f.Stat(ctx)
		close(done)
	}()

	dataStart := uint16(smb1.HeaderSize + 1 + 20 + 2)

	buildTrans2Params := func(dataLen int) []byte {
		p := make([]byte, 20)
		binary.LittleEndian.PutUint16(p[2:4], uint16(dataLen))   // TotalDataCount
		binary.LittleEndian.PutUint16(p[12:14], uint16(dataLen)) // DataCount
		binary.LittleEndian.PutUint16(p[14:16], dataStart)       // DataOffset
		return p
	}

	// Basic info response.
	time.Sleep(10 * time.Millisecond)
	respHeader1 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader1.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader1.Status = smb1.STATUS_SUCCESS
	respHeader1.MID = 0
	basicInfoData := make([]byte, 40)
	binary.LittleEndian.PutUint32(basicInfoData[32:36], smb1.FILE_ATTRIBUTE_NORMAL)
	getMockConn(tree.Session.conn).addResponse(respHeader1, buildTrans2Params(len(basicInfoData)), basicInfoData)

	// Standard info response.
	time.Sleep(10 * time.Millisecond)
	respHeader2 := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader2.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader2.Status = smb1.STATUS_SUCCESS
	respHeader2.MID = 1
	standardInfoData := make([]byte, 24)
	binary.LittleEndian.PutUint64(standardInfoData[8:16], 512) // EndOfFile
	getMockConn(tree.Session.conn).addResponse(respHeader2, buildTrans2Params(len(standardInfoData)), standardInfoData)

	select {
	case <-done:
		if err != nil {
			t.Fatalf("Stat failed: %v", err)
		}
		return stat.FileName
	case <-time.After(1 * time.Second):
		t.Fatal("Stat timed out")
		return ""
	}
}

// TestFileStatBaseName is a regression test: Stat on an open file must report
// the base element of the open path, not the full share-relative path,
// matching os.File.Stat().Name() and go-smb2.
func TestFileStatBaseName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{`dir\sub\file.txt`, "file.txt"},
		{`file.txt`, "file.txt"},
	}
	for _, tt := range tests {
		if got := statFileName(t, tt.name); got != tt.want {
			t.Errorf("Stat FileName for open path %q = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestFileReadAtEOF tests that ReadAt returns io.EOF when reading 0 bytes at EOF.
// This is a regression test for a bug where ReadAt returned (0, nil) instead of
// (0, io.EOF), causing io.ReadAll() to loop infinitely.
func TestFileReadAtEOF(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()
	done := make(chan struct{})
	buf := make([]byte, 100)
	var n int
	var err error

	go func() {
		// Read at EOF position - server will return 0 bytes
		n, err = f.ReadAt(buf, 1000, ctx)
		close(done)
	}()

	// Wait for request
	time.Sleep(10 * time.Millisecond)

	// Send response with 0 bytes (EOF)
	respHeader := smb1.NewHeader(smb1.SMB_COM_READ_ANDX)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = 0

	respParams := make([]byte, 24)
	respParams[0] = smb1.SMB_COM_NO_ANDX_COMMAND

	// DataLength = 0 (EOF)
	respParams[10] = 0
	respParams[11] = 0

	getMockConn(tree.Session.conn).addResponse(respHeader, respParams, nil)

	select {
	case <-done:
		// Should return 0 bytes with EOF error
		if n != 0 {
			t.Errorf("ReadAt at EOF: expected 0 bytes, got %d", n)
		}
		if err != io.EOF {
			t.Errorf("ReadAt at EOF: expected io.EOF, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("ReadAt timed out")
	}
}

// readAtResponse queues one READ_ANDX reply carrying the given payload.
func readAtResponse(tree *Tree, mid uint16, payload []byte) {
	respHeader := smb1.NewHeader(smb1.SMB_COM_READ_ANDX)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = mid

	respParams := make([]byte, 24)
	respParams[0] = smb1.SMB_COM_NO_ANDX_COMMAND
	respParams[10] = byte(len(payload) & 0xFF)
	respParams[11] = byte((len(payload) >> 8) & 0xFF)

	getMockConn(tree.Session.conn).addResponse(respHeader, respParams, payload)
}

// TestFileReadAtShortRead is a regression test for the io.ReaderAt contract:
// a read that returns fewer bytes than requested (only possible at end of
// file) must return the data together with io.EOF, not a nil error.
func TestFileReadAtShortRead(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	ctx := context.Background()
	done := make(chan struct{})
	buf := make([]byte, 100)
	var n int
	var err error

	go func() {
		n, err = f.ReadAt(buf, 0, ctx)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	readAtResponse(tree, 0, []byte("hello"))

	select {
	case <-done:
		if n != 5 {
			t.Errorf("bytes read: got %d, want 5", n)
		}
		if string(buf[:n]) != "hello" {
			t.Errorf("data: got %q, want %q", string(buf[:n]), "hello")
		}
		if err != io.EOF {
			t.Errorf("short ReadAt error: got %v, want io.EOF", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("ReadAt timed out")
	}
}

// TestFileReadAtChunked verifies that ReadAt fills buffers larger than one
// READ_ANDX (65520 bytes without CAP_LARGE_READX) by issuing successive
// chunk reads, and that a completely filled buffer returns a nil error.
func TestFileReadAtChunked(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	const chunk = 65520 // maxDataPerRead without CAP_LARGE_READX
	buf := make([]byte, chunk+100)

	ctx := context.Background()
	done := make(chan struct{})
	var n int
	var err error

	go func() {
		n, err = f.ReadAt(buf, 0, ctx)
		close(done)
	}()

	payload := make([]byte, chunk)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	time.Sleep(10 * time.Millisecond)
	readAtResponse(tree, 0, payload)

	tail := make([]byte, 100)
	for i := range tail {
		tail[i] = byte((chunk + i) % 256)
	}
	time.Sleep(10 * time.Millisecond)
	readAtResponse(tree, 1, tail)

	select {
	case <-done:
		if err != nil {
			t.Fatalf("ReadAt failed: %v", err)
		}
		if n != len(buf) {
			t.Errorf("bytes read: got %d, want %d", n, len(buf))
		}
		for i := 0; i < n; i++ {
			if buf[i] != byte(i%256) {
				t.Errorf("data mismatch at position %d: got %d, want %d", i, buf[i], byte(i%256))
				break
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadAt timed out")
	}
}

// TestFileReadAtChunkedEOF verifies that hitting end of file after a full
// first chunk returns the bytes read so far together with io.EOF.
func TestFileReadAtChunkedEOF(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
		offset:  0,
	}

	const chunk = 65520 // maxDataPerRead without CAP_LARGE_READX
	buf := make([]byte, chunk+100)

	ctx := context.Background()
	done := make(chan struct{})
	var n int
	var err error

	go func() {
		n, err = f.ReadAt(buf, 0, ctx)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	readAtResponse(tree, 0, make([]byte, chunk))

	// Second chunk: the file ends exactly at the first chunk boundary.
	time.Sleep(10 * time.Millisecond)
	respHeader := smb1.NewHeader(smb1.SMB_COM_READ_ANDX)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_END_OF_FILE
	respHeader.MID = 1
	getMockConn(tree.Session.conn).addResponse(respHeader, nil, nil)

	select {
	case <-done:
		if n != chunk {
			t.Errorf("bytes read: got %d, want %d", n, chunk)
		}
		if err != io.EOF {
			t.Errorf("ReadAt at chunk-boundary EOF: got error %v, want io.EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadAt timed out")
	}
}

// TestBaseName covers the path shapes baseName must handle, mirroring
// go-smb2's base: last element, trailing separators trimmed, "" for the
// share root.
func TestBaseName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{``, ``},
		{`\`, ``},
		{`\\`, ``},
		{`file.txt`, `file.txt`},
		{`dir\file.txt`, `file.txt`},
		{`dir\sub\file.txt`, `file.txt`},
		{`dir\sub\`, `sub`},
		{`\file.txt`, `file.txt`},
	}
	for _, tt := range tests {
		if got := baseName(tt.path); got != tt.want {
			t.Errorf("baseName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
