package client

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/erref"
	"github.com/macourteau/smb1client/internal/smb1"
	"github.com/macourteau/smb1client/internal/utf16le"
)

// SendDeleteDirectory must put SMB_COM_DELETE_DIRECTORY on the wire with the
// path, and surface the server's status unchanged — in particular
// STATUS_DIRECTORY_NOT_EMPTY, which is the whole point of using this command
// instead of delete-on-close (some Samba versions acknowledge a delete-on-close
// open of a non-empty directory and then silently leave it in place).
func TestTreeSendDeleteDirectory(t *testing.T) {
	tests := []struct {
		name    string
		status  uint32
		wantErr error
	}{
		{name: "success", status: smb1.STATUS_SUCCESS},
		{name: "not empty", status: uint32(erref.STATUS_DIRECTORY_NOT_EMPTY), wantErr: erref.STATUS_DIRECTORY_NOT_EMPTY},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := setupTestTree()
			defer tree.Session.conn.Close()
			go tree.Session.conn.Receive()
			mock := getMockConn(tree.Session.conn)

			done := make(chan error, 1)
			go func() {
				done <- tree.SendDeleteDirectory("dir\\sub", context.Background())
			}()

			frames := waitForFrames(t, mock, 1)
			respond(mock, 0, smb1.SMB_COM_DELETE_DIRECTORY, tt.status, nil, nil)

			select {
			case err := <-done:
				if tt.wantErr == nil && err != nil {
					t.Fatalf("SendDeleteDirectory failed: %v", err)
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Fatalf("SendDeleteDirectory error = %v, want %v", err, tt.wantErr)
				}
			case <-time.After(time.Second):
				t.Fatal("SendDeleteDirectory timed out")
			}

			if len(frames) != 1 {
				t.Fatalf("sent %d requests, want 1", len(frames))
			}
			h, params, data, err := smb1.DecodePacket(frames[0])
			if err != nil {
				t.Fatalf("failed to decode request: %v", err)
			}
			if h.Command != smb1.SMB_COM_DELETE_DIRECTORY {
				t.Fatalf("command = 0x%02X, want SMB_COM_DELETE_DIRECTORY (0x01)", h.Command)
			}
			if h.TID != tree.TID || h.UID != tree.Session.uid {
				t.Errorf("TID/UID = %d/%d, want %d/%d", h.TID, h.UID, tree.TID, tree.Session.uid)
			}
			if len(params) != 0 {
				t.Errorf("params = %x, want empty (WordCount 0)", params)
			}
			wantPath := utf16le.EncodeStringToBytes("\\dir\\sub")
			if !bytes.Contains(data, wantPath) {
				t.Errorf("data %x does not contain UTF-16LE path %x", data, wantPath)
			}
		})
	}
}
