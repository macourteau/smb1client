package client

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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

// TestAbandonedTransactionMIDStaysReserved covers the one reply that spans
// several messages. A TRANS2 reply — a directory listing, most importantly —
// may still have fragments on the way when its reader stops, and each carries
// the same MID. Were that MID freed at the first late fragment, the ones after
// it would be reassembled into whichever request was given the MID next: a
// listing silently made of another listing's entries. So an abandoned
// transaction keeps its MID for the life of the connection.
func TestAbandonedTransactionMIDStaysReserved(t *testing.T) {
	const total = 300
	fragment := func(fill byte, disp, n int) ([]byte, []byte) {
		return trans2Fragment(0, total, nil, bytes.Repeat([]byte{fill}, n), 0, disp)
	}
	reply := func(mock *EnhancedMockConn, mid uint16, params, data []byte) {
		h := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
		h.MID = mid
		h.Flags |= smb1.SMB_FLAGS_REPLY
		mock.inner.addResponse(h, params, data)
	}

	for _, tc := range []struct {
		name string
		// stop ends the reader's interest after the first fragment arrived.
		stop func(mock *EnhancedMockConn, mid uint16, cancel context.CancelFunc)
	}{
		{
			name: "reader cancelled mid-reassembly",
			stop: func(_ *EnhancedMockConn, _ uint16, cancel context.CancelFunc) { cancel() },
		},
		{
			name: "reader failed mid-reassembly",
			stop: func(mock *EnhancedMockConn, mid uint16, _ context.CancelFunc) {
				// A fragment placed past the promised totals fails reassembly.
				p, d := fragment(0xEE, total, 10)
				reply(mock, mid, p, d)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				mock := newEnhancedMockConnWithLogging(t)
				conn := NewConn(mock)
				defer conn.Close()
				go conn.Receive()

				type result struct {
					trans *smb1.Trans2Response
					err   error
				}
				transact := func(ctx context.Context, done chan<- result) {
					_, trans, err := conn.sendRecvTransaction(smb1.NewHeader(smb1.SMB_COM_TRANSACTION2), nil, nil, ctx)
					done <- result{trans, err}
				}

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				first := make(chan result, 1)
				go transact(ctx, first)
				synctest.Wait()
				abandoned := mock.GetRequests()[0].MID

				p, d := fragment(0xAA, 0, 100)
				reply(mock, abandoned, p, d)
				synctest.Wait()
				tc.stop(mock, abandoned, cancel)
				if got := <-first; got.err == nil {
					t.Fatalf("abandoned transaction returned no error")
				}

				// One late fragment lands, then allocation comes round to the
				// abandoned MID while another is still on its way.
				p, d = fragment(0xAA, 100, 100)
				reply(mock, abandoned, p, d)
				synctest.Wait()
				conn.mu.Lock()
				conn.nextMID = abandoned
				conn.mu.Unlock()

				second := make(chan result, 1)
				go transact(context.Background(), second)
				synctest.Wait()
				reqs := mock.GetRequests()
				fresh := reqs[len(reqs)-1].MID
				if fresh == abandoned {
					t.Errorf("new transaction was given MID %d while the abandoned one's fragments were still arriving", fresh)
				}

				p, d = fragment(0xAA, 200, 100)
				reply(mock, abandoned, p, d)
				synctest.Wait()
				want := bytes.Repeat([]byte{0x55}, 50)
				p, d = trans2Fragment(0, len(want), nil, want, 0, 0)
				reply(mock, fresh, p, d)

				select {
				case got := <-second:
					if got.err != nil {
						t.Fatalf("new transaction failed: %v", got.err)
					}
					if !bytes.Equal(got.trans.Data, want) {
						t.Errorf("new transaction reassembled %d bytes not its own reply; late fragments leaked in", len(got.trans.Data))
					}
				case <-time.After(time.Minute):
					t.Fatal("new transaction never completed; late fragments were taken as its reply")
				}

				if _, reserved := pendingByState(conn); len(reserved) != 1 || reserved[0] != abandoned {
					t.Errorf("reserved MIDs %v, want the abandoned transaction's %d held for the connection's life", reserved, abandoned)
				}
			})
		})
	}
}

// TestMIDExhaustionTearsTheConnectionDown checks what happens once every MID
// is held — in practice by abandoned requests whose replies never came. The
// connection can issue nothing more, so it must fail as a dead connection,
// which callers and pools recognise and redial, rather than as a live one on
// which every call errors forever.
func TestMIDExhaustionTearsTheConnectionDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mock := newMockConn()
		conn := NewConn(mock)
		defer conn.Close()
		go conn.Receive()

		conn.mu.Lock()
		for mid := 0; mid <= 0xFFFF; mid++ {
			if uint16(mid) != reservedMID {
				conn.pending[uint16(mid)] = &pendingRequest{respCh: make(chan *response, 1), cancelled: true}
			}
		}
		conn.mu.Unlock()

		for _, attempt := range []string{"first request", "next request"} {
			_, err := conn.sendRecv(smb1.NewHeader(smb1.SMB_COM_ECHO), nil, nil, context.Background())
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("%s: error = %v, want one classified as a closed connection", attempt, err)
			}
		}

		select {
		case <-conn.done:
		default:
			t.Error("connection still open after running out of MIDs")
		}
		mock.mu.Lock()
		closed := mock.closed
		mock.mu.Unlock()
		if !closed {
			t.Error("socket left open after running out of MIDs")
		}
	})
}

// TestTransactionAbandonedWithFragmentBufferedStaysReserved pins the one case
// where a reply already sitting in the channel does not settle a request: a
// transaction's first fragment may have arrived unread when its reader gives
// up, with more of the reply still on the way.
func TestTransactionAbandonedWithFragmentBufferedStaysReserved(t *testing.T) {
	for _, tc := range []struct {
		name         string
		transaction  bool
		wantReserved bool
	}{
		{name: "transaction", transaction: true, wantReserved: true},
		{name: "single-message request", transaction: false, wantReserved: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				mock := newEnhancedMockConnWithLogging(t)
				conn := NewConn(mock)
				defer conn.Close()
				go conn.Receive()

				_, mid, finish, err := conn.beginRequest(smb1.NewHeader(smb1.SMB_COM_TRANSACTION2), nil, nil, context.Background(), tc.transaction)
				if err != nil {
					t.Fatalf("beginRequest() error = %v", err)
				}
				p, d := trans2Fragment(0, 300, nil, make([]byte, 100), 0, 0)
				h := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
				h.MID = mid
				h.Flags |= smb1.SMB_FLAGS_REPLY
				mock.inner.addResponse(h, p, d)
				synctest.Wait() // the fragment is now buffered, unread

				finish(true)

				_, reserved := pendingByState(conn)
				if got := len(reserved) == 1 && reserved[0] == mid; got != tc.wantReserved {
					t.Errorf("MID %d reserved after abandonment = %v, want %v (reserved: %v)", mid, got, tc.wantReserved, reserved)
				}
			})
		})
	}
}

// TestAbandonRacingItsReplyNeverStrandsTheMID races a sender giving up against
// its reply arriving. Whichever wins, the MID must end up free once the reply
// has been processed: handed over before the abandonment, the abandonment sees
// it in the channel; handed over after, the receive loop discards it as late.
// Only a hand-off made under the connection lock rules out the third ordering,
// where the reply lands in the channel of a request already marked abandoned
// and the MID is held for a reply that has in fact come and gone.
func TestAbandonRacingItsReplyNeverStrandsTheMID(t *testing.T) {
	mock := newEnhancedMockConn()
	conn := NewConn(mock)
	defer conn.Close()
	go conn.Receive()

	reply := func(mid uint16) {
		h := smb1.NewHeader(smb1.SMB_COM_ECHO)
		h.MID = mid
		h.Flags |= smb1.SMB_FLAGS_REPLY
		mock.inner.addResponse(h, nil, nil)
	}

	for i := 0; i < 5000; i++ {
		_, mid, finish, err := conn.beginRequest(smb1.NewHeader(smb1.SMB_COM_ECHO), nil, nil, context.Background(), false)
		if err != nil {
			t.Fatalf("beginRequest() error = %v", err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; finish(true) }()
		go func() { defer wg.Done(); <-start; reply(mid) }()
		close(start)
		wg.Wait()

		// The receive loop handles messages in order, so once a marker
		// request has its reply, the raced reply has been processed too.
		markerCh, marker, finishMarker, err := conn.beginRequest(smb1.NewHeader(smb1.SMB_COM_ECHO), nil, nil, context.Background(), false)
		if err != nil {
			t.Fatalf("beginRequest() error = %v", err)
		}
		reply(marker)
		<-markerCh
		finishMarker(false)

		if live, reserved := pendingByState(conn); len(live)+len(reserved) != 0 {
			t.Fatalf("iteration %d: MID %d stranded after its reply was processed (live %v, reserved %v)", i, mid, live, reserved)
		}
	}
}
