package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// TestFileQueryBasicInfo tests File.QueryBasicInfo() against a mocked
// TRANS2_QUERY_FILE_INFORMATION exchange. The attributes must come back
// exactly as sent — no directory-flag merging — because the caller's
// read-modify-write echoes them to the server.
func TestFileQueryBasicInfo(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
	}

	ctx := context.Background()
	done := make(chan struct{})
	var info *smb1.FileBasicInfo
	var err error

	go func() {
		info, err = f.QueryBasicInfo(ctx)
		close(done)
	}()

	// Wait for the request to be sent
	time.Sleep(10 * time.Millisecond)

	respHeader := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = 0

	const wantAttrs = smb1.FILE_ATTRIBUTE_READONLY | smb1.FILE_ATTRIBUTE_ARCHIVE
	basicInfoData := make([]byte, 40)
	binary.LittleEndian.PutUint64(basicInfoData[0:8], 132450912000000000)   // CreationTime
	binary.LittleEndian.PutUint64(basicInfoData[8:16], 132450912000000000)  // LastAccessTime
	binary.LittleEndian.PutUint64(basicInfoData[16:24], 132450912000000000) // LastWriteTime
	binary.LittleEndian.PutUint64(basicInfoData[24:32], 132450912000000000) // ChangeTime
	binary.LittleEndian.PutUint32(basicInfoData[32:36], wantAttrs)

	// TRANS2 response params describe where the data section sits, with
	// offsets absolute from the start of the SMB header.
	dataStart := uint16(smb1.HeaderSize + 1 + 20 + 2) // Header + WordCount + Params + ByteCount

	trans2Params := make([]byte, 20)
	binary.LittleEndian.PutUint16(trans2Params[2:4], uint16(len(basicInfoData)))   // TotalDataCount
	binary.LittleEndian.PutUint16(trans2Params[12:14], uint16(len(basicInfoData))) // DataCount
	binary.LittleEndian.PutUint16(trans2Params[14:16], dataStart)                  // DataOffset

	getMockConn(tree.Session.conn).addResponse(respHeader, trans2Params, basicInfoData)

	select {
	case <-done:
		if err != nil {
			t.Fatalf("QueryBasicInfo failed: %v", err)
		}
		if info.Attributes != wantAttrs {
			t.Errorf("attributes: got %#x, want %#x", info.Attributes, wantAttrs)
		}
		if info.LastWriteTime != 132450912000000000 {
			t.Errorf("LastWriteTime: got %d, want 132450912000000000", info.LastWriteTime)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("QueryBasicInfo timed out")
	}
}

// TestFileSetBasicInfo tests File.SetBasicInfo() against a mocked
// TRANS2_SET_FILE_INFORMATION exchange, asserting the request actually
// carries the SMB_SET_FILE_BASIC_INFO level, the FID, and the encoded
// 40-byte information block.
func TestFileSetBasicInfo(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()

	go tree.Session.conn.Receive()

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "test.txt",
	}

	setInfo := &smb1.FileBasicInfo{
		LastAccessTime: 132450912000000000,
		LastWriteTime:  132450912990000000,
		Attributes:     smb1.FILE_ATTRIBUTE_READONLY | smb1.FILE_ATTRIBUTE_ARCHIVE,
	}

	ctx := context.Background()
	done := make(chan struct{})
	var err error

	go func() {
		err = f.SetBasicInfo(setInfo, ctx)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)

	respHeader := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	respHeader.Flags |= smb1.SMB_FLAGS_REPLY
	respHeader.Status = smb1.STATUS_SUCCESS
	respHeader.MID = 0

	getMockConn(tree.Session.conn).addResponse(respHeader, make([]byte, 20), nil)

	select {
	case <-done:
		if err != nil {
			t.Fatalf("SetBasicInfo failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("SetBasicInfo timed out")
	}

	// The captured frame must contain the set-info parameter block —
	// FID(2) + InformationLevel(2) + Reserved(2) — and the encoded data.
	mock := getMockConn(tree.Session.conn)
	mock.mu.Lock()
	sent := append([]byte(nil), mock.writeBuf...)
	mock.mu.Unlock()

	wantParams := make([]byte, 6)
	binary.LittleEndian.PutUint16(wantParams[0:2], f.fid)
	binary.LittleEndian.PutUint16(wantParams[2:4], smb1.SMB_SET_FILE_BASIC_INFO)
	if !bytes.Contains(sent, wantParams) {
		t.Errorf("sent request does not contain set-info params %x", wantParams)
	}
	if !bytes.Contains(sent, smb1.EncodeFileBasicInfo(setInfo)) {
		t.Error("sent request does not contain the encoded FileBasicInfo block")
	}
}
