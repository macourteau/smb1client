package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/erref"
	"github.com/macourteau/smb1client/internal/smb1"
	"github.com/macourteau/smb1client/internal/utf16le"
)

// capturedFrames splits the mock connection's write buffer into individual
// SMB packets (stripping the 4-byte NetBIOS session headers).
func capturedFrames(m *mockConn) [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	var frames [][]byte
	buf := m.writeBuf
	for len(buf) >= 4 {
		n := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if len(buf) < 4+n {
			break
		}
		frames = append(frames, append([]byte(nil), buf[4:4+n]...))
		buf = buf[4+n:]
	}
	return frames
}

// waitForFrames polls until the mock connection has captured at least count
// request frames, failing the test after a second.
func waitForFrames(t *testing.T, m *mockConn, count int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		frames := capturedFrames(m)
		if len(frames) >= count {
			return frames
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d request frames, have %d", count, len(capturedFrames(m)))
	return nil
}

// respond queues a response for the given MID and command with the given
// status. Params and data may be nil.
func respond(m *mockConn, mid uint16, command uint8, status uint32, params, data []byte) {
	h := smb1.NewHeader(command)
	h.Flags |= smb1.SMB_FLAGS_REPLY
	h.Status = status
	h.MID = mid
	m.addResponse(h, params, data)
}

// successTrans2Params is a minimal decodable TRANS2 response parameter block.
func successTrans2Params() []byte {
	return make([]byte, 20)
}

// The fallback must fire exactly when the TRANS2 set fails with
// STATUS_NOT_SUPPORTED: the second request on the wire must be the
// core-protocol SMB_COM_SET_INFORMATION carrying the DOS attribute subset
// (directory and NORMAL bits stripped) and the path.
func TestTreeSetPathAttributesFallbackOnNotSupported(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()
	go tree.Session.conn.Receive()
	mock := getMockConn(tree.Session.conn)

	const attrs = smb1.FILE_ATTRIBUTE_READONLY | smb1.FILE_ATTRIBUTE_ARCHIVE | smb1.FILE_ATTRIBUTE_DIRECTORY

	done := make(chan error, 1)
	go func() {
		done <- tree.SetPathAttributes("dir\\file.txt", attrs, context.Background())
	}()

	waitForFrames(t, mock, 1)
	respond(mock, 0, smb1.SMB_COM_TRANSACTION2, smb1.STATUS_NOT_SUPPORTED, nil, nil)

	frames := waitForFrames(t, mock, 2)
	respond(mock, 1, smb1.SMB_COM_SET_INFORMATION, smb1.STATUS_SUCCESS, nil, nil)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SetPathAttributes failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetPathAttributes timed out")
	}

	h1, _, _, err := smb1.DecodePacket(frames[0])
	if err != nil {
		t.Fatalf("failed to decode first request: %v", err)
	}
	if h1.Command != smb1.SMB_COM_TRANSACTION2 {
		t.Errorf("first request command = 0x%02X, want TRANS2 (0x%02X)", h1.Command, smb1.SMB_COM_TRANSACTION2)
	}

	h2, params, data, err := smb1.DecodePacket(frames[1])
	if err != nil {
		t.Fatalf("failed to decode fallback request: %v", err)
	}
	if h2.Command != smb1.SMB_COM_SET_INFORMATION {
		t.Fatalf("fallback command = 0x%02X, want SMB_COM_SET_INFORMATION (0x09)", h2.Command)
	}
	if len(params) != 16 {
		t.Fatalf("fallback params length = %d, want 16", len(params))
	}
	// Directory bit must not be sent; READONLY|ARCHIVE coincide in the low word.
	wantDOS := uint16(smb1.FILE_ATTRIBUTE_READONLY | smb1.FILE_ATTRIBUTE_ARCHIVE)
	if got := binary.LittleEndian.Uint16(params[0:2]); got != wantDOS {
		t.Errorf("fallback FileAttributes = 0x%04X, want 0x%04X", got, wantDOS)
	}
	if got := binary.LittleEndian.Uint32(params[2:6]); got != 0 {
		t.Errorf("fallback LastWriteTime = %d, want 0 (don't change)", got)
	}
	// The mock connection negotiates CAP_UNICODE, so the path travels UTF-16LE
	// with the protocol-required leading backslash.
	wantPath := utf16le.EncodeStringToBytes("\\dir\\file.txt")
	if !bytes.Contains(data, wantPath) {
		t.Errorf("fallback data %x does not contain UTF-16LE path %x", data, wantPath)
	}
}

// FILE_ATTRIBUTE_NORMAL has no DOS encoding: the core command sets
// attributes absolutely, so "normal" must go out as 0x0000.
func TestTreeSetPathAttributesFallbackMapsNormalToZero(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()
	go tree.Session.conn.Receive()
	mock := getMockConn(tree.Session.conn)

	done := make(chan error, 1)
	go func() {
		done <- tree.SetPathAttributes("plain.txt", smb1.FILE_ATTRIBUTE_NORMAL, context.Background())
	}()

	waitForFrames(t, mock, 1)
	respond(mock, 0, smb1.SMB_COM_TRANSACTION2, smb1.STATUS_NOT_SUPPORTED, nil, nil)

	frames := waitForFrames(t, mock, 2)
	respond(mock, 1, smb1.SMB_COM_SET_INFORMATION, smb1.STATUS_SUCCESS, nil, nil)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SetPathAttributes failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetPathAttributes timed out")
	}

	_, params, _, err := smb1.DecodePacket(frames[1])
	if err != nil {
		t.Fatalf("failed to decode fallback request: %v", err)
	}
	if got := binary.LittleEndian.Uint16(params[0:2]); got != 0 {
		t.Errorf("fallback FileAttributes = 0x%04X, want 0x0000 (normal)", got)
	}
}

// When the TRANS2 set succeeds, no fallback request may be sent.
func TestTreeSetPathAttributesNoFallbackOnSuccess(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()
	go tree.Session.conn.Receive()
	mock := getMockConn(tree.Session.conn)

	done := make(chan error, 1)
	go func() {
		done <- tree.SetPathAttributes("file.txt", smb1.FILE_ATTRIBUTE_READONLY, context.Background())
	}()

	waitForFrames(t, mock, 1)
	respond(mock, 0, smb1.SMB_COM_TRANSACTION2, smb1.STATUS_SUCCESS, successTrans2Params(), nil)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SetPathAttributes failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetPathAttributes timed out")
	}

	if frames := capturedFrames(mock); len(frames) != 1 {
		t.Errorf("sent %d requests, want 1 (no fallback on success)", len(frames))
	}
}

// Errors other than STATUS_NOT_SUPPORTED must be returned as-is with no
// fallback attempt.
func TestTreeSetPathAttributesNoFallbackOnOtherError(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()
	go tree.Session.conn.Receive()
	mock := getMockConn(tree.Session.conn)

	done := make(chan error, 1)
	go func() {
		done <- tree.SetPathAttributes("file.txt", smb1.FILE_ATTRIBUTE_READONLY, context.Background())
	}()

	waitForFrames(t, mock, 1)
	respond(mock, 0, smb1.SMB_COM_TRANSACTION2, uint32(erref.STATUS_ACCESS_DENIED), nil, nil)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("SetPathAttributes succeeded, want STATUS_ACCESS_DENIED")
		}
		if !errors.Is(err, erref.STATUS_ACCESS_DENIED) {
			t.Errorf("error = %v, want STATUS_ACCESS_DENIED", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetPathAttributes timed out")
	}

	if frames := capturedFrames(mock); len(frames) != 1 {
		t.Errorf("sent %d requests, want 1 (no fallback on other errors)", len(frames))
	}
}

// File.SetAttributes falls back path-based: the SMB_COM_SET_INFORMATION
// request must carry the path the file was opened with, not the FID.
func TestFileSetAttributesFallbackOnNotSupported(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()
	go tree.Session.conn.Receive()
	mock := getMockConn(tree.Session.conn)

	f := &File{
		session: tree.Session,
		tid:     200,
		fid:     0x002A,
		name:    "sub\\open.txt",
	}

	done := make(chan error, 1)
	go func() {
		done <- f.SetAttributes(smb1.FILE_ATTRIBUTE_READONLY, context.Background())
	}()

	waitForFrames(t, mock, 1)
	respond(mock, 0, smb1.SMB_COM_TRANSACTION2, smb1.STATUS_NOT_SUPPORTED, nil, nil)

	frames := waitForFrames(t, mock, 2)
	respond(mock, 1, smb1.SMB_COM_SET_INFORMATION, smb1.STATUS_SUCCESS, nil, nil)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SetAttributes failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetAttributes timed out")
	}

	h2, params, data, err := smb1.DecodePacket(frames[1])
	if err != nil {
		t.Fatalf("failed to decode fallback request: %v", err)
	}
	if h2.Command != smb1.SMB_COM_SET_INFORMATION {
		t.Fatalf("fallback command = 0x%02X, want SMB_COM_SET_INFORMATION (0x09)", h2.Command)
	}
	if got := binary.LittleEndian.Uint16(params[0:2]); got != uint16(smb1.FILE_ATTRIBUTE_READONLY) {
		t.Errorf("fallback FileAttributes = 0x%04X, want 0x%04X", got, smb1.FILE_ATTRIBUTE_READONLY)
	}
	wantPath := utf16le.EncodeStringToBytes("\\sub\\open.txt")
	if !bytes.Contains(data, wantPath) {
		t.Errorf("fallback data %x does not contain UTF-16LE path %x", data, wantPath)
	}
}

// File.SetAttributes must not fall back when the handle-based TRANS2 set
// works or fails with an unrelated error.
func TestFileSetAttributesNoFallback(t *testing.T) {
	cases := []struct {
		name    string
		status  uint32
		params  []byte
		wantErr bool
	}{
		{"success", smb1.STATUS_SUCCESS, successTrans2Params(), false},
		{"other error", uint32(erref.STATUS_ACCESS_DENIED), nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := setupTestTree()
			defer tree.Session.conn.Close()
			go tree.Session.conn.Receive()
			mock := getMockConn(tree.Session.conn)

			f := &File{
				session: tree.Session,
				tid:     200,
				fid:     0x002A,
				name:    "open.txt",
			}

			done := make(chan error, 1)
			go func() {
				done <- f.SetAttributes(smb1.FILE_ATTRIBUTE_READONLY, context.Background())
			}()

			waitForFrames(t, mock, 1)
			respond(mock, 0, smb1.SMB_COM_TRANSACTION2, tc.status, tc.params, nil)

			select {
			case err := <-done:
				if tc.wantErr && err == nil {
					t.Fatal("SetAttributes succeeded, want error")
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("SetAttributes failed: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("SetAttributes timed out")
			}

			if frames := capturedFrames(mock); len(frames) != 1 {
				t.Errorf("sent %d requests, want 1 (no fallback)", len(frames))
			}
		})
	}
}
