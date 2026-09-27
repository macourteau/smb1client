package client

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/macourteau/smb1client/internal/smb1"
)

// TestAbandonedMIDIsNotReusedBeforeItsReply checks that a request the client
// stopped waiting for keeps its MID until the server's reply to it arrives.
//
// The server still answers an abandoned request. Were its MID handed to a new
// request in the meantime, that late reply would be delivered as the new
// request's answer — the wrong command's result, silently. Each case abandons
// a request one way, steers allocation back onto its MID, and then lets the
// late reply land ahead of the new request's own.
func TestAbandonedMIDIsNotReusedBeforeItsReply(t *testing.T) {
	for _, tc := range []struct {
		name string
		// abandon leaves one request unanswered and abandoned, returning its
		// MID. Anything else it sent has been answered.
		abandon func(t *testing.T, mock *EnhancedMockConn, conn *Conn) uint16
	}{
		{
			name: "sendRecv cancelled by its context",
			abandon: func(t *testing.T, mock *EnhancedMockConn, conn *Conn) uint16 {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error)
				go func() {
					_, err := conn.sendRecv(smb1.NewHeader(smb1.SMB_COM_ECHO), nil, nil, ctx)
					done <- err
				}()
				synctest.Wait()
				cancel()
				if err := <-done; err != context.Canceled {
					t.Fatalf("sendRecv() error = %v, want context.Canceled", err)
				}
				return mock.GetRequests()[0].MID
			},
		},
		{
			name: "pipelined read whose drain gave up",
			abandon: func(t *testing.T, mock *EnhancedMockConn, conn *Conn) uint16 {
				conn.maxMpxCount = 2
				conn.capabilities = smb1.CAP_LARGE_FILES | smb1.CAP_LARGE_READX
				f := &File{
					session: &Session{conn: conn, uid: 100, trees: make(map[uint16]*Tree)},
					tid:     200,
					fid:     0x002A,
				}
				// The first chunk comes back short, ending the read; the
				// second is never answered within the drain bound.
				done := make(chan error)
				go func() {
					_, err := f.Read(make([]byte, 256<<10), context.Background())
					done <- err
				}()
				synctest.Wait()
				reqs := mock.GetRequests()
				mock.inner.addResponse(CreateReadResponse(reqs[0].MID, make([]byte, 10)))
				if err := <-done; err != nil {
					t.Fatalf("Read() error = %v, want nil", err)
				}
				return reqs[1].MID
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				mock := newEnhancedMockConnWithLogging(t)
				conn := NewConn(mock)
				conn.maxBufferSize = 65535
				defer conn.Close()
				go conn.Receive()

				abandoned := tc.abandon(t, mock, conn)

				// Steer allocation straight back onto the abandoned MID, as
				// the 16-bit counter eventually does on a busy connection.
				conn.mu.Lock()
				conn.nextMID = abandoned
				conn.mu.Unlock()

				type result struct {
					resp *response
					err  error
				}
				done := make(chan result)
				go func() {
					resp, err := conn.sendRecv(smb1.NewHeader(smb1.SMB_COM_ECHO), nil, nil, context.Background())
					done <- result{resp, err}
				}()
				synctest.Wait()
				reqs := mock.GetRequests()
				fresh := reqs[len(reqs)-1].MID
				if fresh == abandoned {
					t.Errorf("new request was given MID %d while its previous request's reply was still owed", fresh)
				}

				// The late reply lands first, then the new request's own.
				mock.inner.addResponse(CreateErrorResponse(abandoned, smb1.SMB_COM_READ_ANDX, smb1.STATUS_ACCESS_DENIED))
				synctest.Wait()
				h := smb1.NewHeader(smb1.SMB_COM_ECHO)
				h.MID = fresh
				h.Flags |= smb1.SMB_FLAGS_REPLY
				mock.inner.addResponse(h, nil, nil)

				got := <-done
				if got.err != nil {
					t.Fatalf("new request got error %v, want its own successful reply", got.err)
				}
				if got.resp.header.Command != smb1.SMB_COM_ECHO {
					t.Errorf("new request got a reply to command 0x%02X, want its own ECHO reply", got.resp.header.Command)
				}

				conn.mu.Lock()
				_, stillHeld := conn.pending[abandoned]
				conn.mu.Unlock()
				if stillHeld {
					t.Errorf("MID %d still reserved after its late reply arrived", abandoned)
				}
			})
		})
	}
}
