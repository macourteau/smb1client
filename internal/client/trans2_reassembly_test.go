package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// trans2Fragment builds one message of a TRANS2 reply: the SMB parameter block
// describing the whole reply's totals plus this message's own slice of it, and
// the byte section carrying that slice. Parameters sit at the start of the byte
// section with the data immediately after, so no padding offsets are involved.
func trans2Fragment(totalParams, totalData int, params, data []byte, paramDisp, dataDisp int) ([]byte, []byte) {
	smbParams := make([]byte, 20)
	dataStart := smb1.HeaderSize + 1 + len(smbParams) + 2

	binary.LittleEndian.PutUint16(smbParams[0:2], uint16(totalParams))
	binary.LittleEndian.PutUint16(smbParams[2:4], uint16(totalData))
	binary.LittleEndian.PutUint16(smbParams[6:8], uint16(len(params)))
	binary.LittleEndian.PutUint16(smbParams[8:10], uint16(dataStart))
	binary.LittleEndian.PutUint16(smbParams[10:12], uint16(paramDisp))
	binary.LittleEndian.PutUint16(smbParams[12:14], uint16(len(data)))
	binary.LittleEndian.PutUint16(smbParams[14:16], uint16(dataStart+len(params)))
	binary.LittleEndian.PutUint16(smbParams[16:18], uint16(dataDisp))

	return smbParams, append(append([]byte(nil), params...), data...)
}

// A server answers a TRANS2 request with as many bytes as its own send buffer
// holds, not as many as MaxDataCount allows, and splits the rest across further
// messages carrying the same MID. Reading only the first message silently drops
// the remainder — for a directory listing that means entries vanishing with no
// error, so every byte the totals promise must come back.
func TestSendTransact2ReassemblesSplitReply(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()
	go tree.Session.conn.Receive()

	replyParams := bytes.Repeat([]byte{0xAA}, 10)
	firstHalf := bytes.Repeat([]byte{0x01}, 200)
	secondHalf := bytes.Repeat([]byte{0x02}, 100)
	wantData := append(append([]byte(nil), firstHalf...), secondHalf...)

	type result struct {
		resp *smb1.Trans2Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := tree.SendTransact2(smb1.TRANS2_FIND_FIRST2, []byte{0x00}, nil, context.Background())
		done <- result{resp, err}
	}()

	frames := waitForFrames(t, getMockConn(tree.Session.conn), 1)
	reqHeader, _, _, err := smb1.DecodePacket(frames[0])
	if err != nil {
		t.Fatalf("failed to decode request: %v", err)
	}

	mock := getMockConn(tree.Session.conn)
	p1, d1 := trans2Fragment(len(replyParams), len(wantData), replyParams, firstHalf, 0, 0)
	respond(mock, reqHeader.MID, smb1.SMB_COM_TRANSACTION2, smb1.STATUS_SUCCESS, p1, d1)
	p2, d2 := trans2Fragment(len(replyParams), len(wantData), nil, secondHalf, 0, len(firstHalf))
	respond(mock, reqHeader.MID, smb1.SMB_COM_TRANSACTION2, smb1.STATUS_SUCCESS, p2, d2)

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("SendTransact2 returned error: %v", got.err)
		}
		if !bytes.Equal(got.resp.Data, wantData) {
			t.Errorf("reassembled data length = %d, want %d", len(got.resp.Data), len(wantData))
		}
		if !bytes.Equal(got.resp.Parameters, replyParams) {
			t.Errorf("reassembled parameters = %x, want %x", got.resp.Parameters, replyParams)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendTransact2 timed out waiting for the second message")
	}
}

// A reply that arrives whole in one message must not make the transport wait
// for a continuation that is never coming.
func TestSendTransact2SingleMessageReply(t *testing.T) {
	tree := setupTestTree()
	defer tree.Session.conn.Close()
	go tree.Session.conn.Receive()

	replyData := bytes.Repeat([]byte{0x07}, 64)

	type result struct {
		resp *smb1.Trans2Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := tree.SendTransact2(smb1.TRANS2_QUERY_PATH_INFORMATION, []byte{0x00}, nil, context.Background())
		done <- result{resp, err}
	}()

	frames := waitForFrames(t, getMockConn(tree.Session.conn), 1)
	reqHeader, _, _, err := smb1.DecodePacket(frames[0])
	if err != nil {
		t.Fatalf("failed to decode request: %v", err)
	}

	p, d := trans2Fragment(0, len(replyData), nil, replyData, 0, 0)
	respond(getMockConn(tree.Session.conn), reqHeader.MID, smb1.SMB_COM_TRANSACTION2, smb1.STATUS_SUCCESS, p, d)

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("SendTransact2 returned error: %v", got.err)
		}
		if !bytes.Equal(got.resp.Data, replyData) {
			t.Errorf("data = %x, want %x", got.resp.Data, replyData)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendTransact2 timed out on a single-message reply")
	}
}
