package client

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// slowServer answers READ_ANDX and WRITE_ANDX requests after a delay, the way
// smbd does when it serves them asynchronously, and records whether a CLOSE
// ever arrives while one of them is still unanswered. That overlap is what
// Samba 4.13 and later crash on, so the client must never produce it.
type slowServer struct {
	mock *EnhancedMockConn
	// replies tracks the goroutines holding back answers, so a test can
	// let them finish before its bubble ends whether or not the client waited.
	replies sync.WaitGroup

	mu          sync.Mutex
	outstanding map[uint16]bool // READ_ANDX/WRITE_ANDX MIDs received and not yet answered
	closeSawMax int             // most requests outstanding when a CLOSE arrived
	closes      int
}

// chunkReply is how the server answers one chunk: after delay, with either an
// error status or success. A read succeeds with data; a write succeeds having
// written its whole payload, or only written bytes when that is set.
// malformed answers success with no parameter words, which no reply decodes.
// never leaves the request unanswered.
type chunkReply struct {
	delay     time.Duration
	status    uint32
	data      []byte
	written   *uint32
	malformed bool
	never     bool
}

func newSlowServer(t *testing.T, reply func(chunk int, req SMBRequest) chunkReply) *slowServer {
	s := &slowServer{
		mock:        newEnhancedMockConnWithLogging(t),
		outstanding: make(map[uint16]bool),
	}
	var chunks int
	s.mock.SetAutoResponder(func(req SMBRequest) (*smb1.Header, []byte, []byte) {
		switch req.Command {
		case smb1.SMB_COM_READ_ANDX, smb1.SMB_COM_WRITE_ANDX:
			r := reply(chunks, req)
			chunks++
			s.mu.Lock()
			s.outstanding[req.MID] = true
			s.mu.Unlock()
			if r.never {
				return nil, nil, nil
			}
			s.replies.Add(1)
			go func() {
				defer s.replies.Done()
				time.Sleep(r.delay)
				var h *smb1.Header
				var params, data []byte
				switch {
				case r.status != smb1.STATUS_SUCCESS, r.malformed:
					h, params, data = CreateErrorResponse(req.MID, req.Command, r.status)
				case req.Command == smb1.SMB_COM_READ_ANDX:
					h, params, data = CreateReadResponse(req.MID, r.data)
				case r.written != nil:
					h, params, data = CreateWriteResponse(req.MID, *r.written)
				default:
					h, params, data = CreateWriteResponse(req.MID, uint32(len(req.WriteData)))
				}
				s.mu.Lock()
				delete(s.outstanding, req.MID)
				s.mu.Unlock()
				s.mock.inner.addResponse(h, params, data)
			}()
			return nil, nil, nil
		case smb1.SMB_COM_CLOSE:
			s.mu.Lock()
			s.closes++
			s.closeSawMax = max(s.closeSawMax, len(s.outstanding))
			s.mu.Unlock()
			return CreateCloseResponse(req.MID)
		}
		return nil, nil, nil
	})
	return s
}

func (s *slowServer) outstandingRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.outstanding)
}

// newDrainTestFile wires a File to s with a pipeline depth of eight, so a
// 512 KiB transfer is one full batch plus a straggler.
func newDrainTestFile(s *slowServer) (*File, *Conn) {
	conn := NewConn(s.mock)
	conn.maxBufferSize = 65535
	conn.maxMpxCount = 8
	conn.capabilities = smb1.CAP_LARGE_FILES | smb1.CAP_LARGE_READX
	session := &Session{
		conn:      conn,
		uid:       100,
		initiator: newMockInitiator(),
		trees:     make(map[uint16]*Tree),
	}
	return &File{session: session, tid: 200, fid: 0x002A, name: "frame.fit"}, conn
}

// TestFileReadPipelinedCollectsEveryReplyBeforeReturning covers every way a
// pipelined Read can stop before its last chunk. Whichever it is, the replies
// to requests already sent must be collected before Read returns, so that a
// Close issued straight after never reaches the server while a read on the
// same file is still pending there.
func TestFileReadPipelinedCollectsEveryReplyBeforeReturning(t *testing.T) {
	const chunk = 65520
	full := func(req SMBRequest) []byte { return make([]byte, req.ReadLength) }
	late := 50 * time.Millisecond

	for _, tc := range []struct {
		name        string
		reply       func(i int, req SMBRequest) chunkReply
		cancelAfter time.Duration
		wantN       int
		wantErr     error
	}{
		{
			name: "short first chunk",
			reply: func(i int, req SMBRequest) chunkReply {
				if i == 0 {
					return chunkReply{delay: time.Millisecond, data: make([]byte, 1000)}
				}
				return chunkReply{delay: late}
			},
			wantN: 1000,
		},
		{
			name: "short chunk after a full one",
			reply: func(i int, req SMBRequest) chunkReply {
				switch i {
				case 0:
					return chunkReply{delay: time.Millisecond, data: full(req)}
				case 1:
					return chunkReply{delay: 2 * time.Millisecond, data: make([]byte, 7)}
				}
				return chunkReply{delay: late}
			},
			wantN: chunk + 7,
		},
		{
			name: "empty first chunk at end of file",
			reply: func(i int, req SMBRequest) chunkReply {
				return chunkReply{delay: time.Millisecond + time.Duration(i)*late}
			},
			wantErr: io.EOF,
		},
		{
			name: "end-of-file status on the first chunk",
			reply: func(i int, req SMBRequest) chunkReply {
				if i == 0 {
					return chunkReply{delay: time.Millisecond, status: smb1.STATUS_END_OF_FILE}
				}
				return chunkReply{delay: late, status: smb1.STATUS_END_OF_FILE}
			},
			wantErr: io.EOF,
		},
		{
			name: "error on the first chunk",
			reply: func(i int, req SMBRequest) chunkReply {
				if i == 0 {
					return chunkReply{delay: time.Millisecond, status: smb1.STATUS_ACCESS_DENIED}
				}
				return chunkReply{delay: late, data: full(req)}
			},
			wantErr: errAny,
		},
		{
			name: "context cancelled mid-batch",
			reply: func(i int, req SMBRequest) chunkReply {
				return chunkReply{delay: late, data: full(req)}
			},
			cancelAfter: 10 * time.Millisecond,
			wantErr:     context.Canceled,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newSlowServer(t, tc.reply)
				f, conn := newDrainTestFile(s)
				defer conn.Close()
				defer s.replies.Wait()
				go conn.Receive()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if tc.cancelAfter > 0 {
					time.AfterFunc(tc.cancelAfter, cancel)
				}

				n, err := f.Read(make([]byte, 512<<10), ctx)

				if n != tc.wantN {
					t.Errorf("Read() n = %d, want %d", n, tc.wantN)
				}
				switch {
				case tc.wantErr == errAny:
					if err == nil || err == io.EOF {
						t.Errorf("Read() error = %v, want a read failure", err)
					}
				case tc.wantErr == io.EOF:
					if err != io.EOF {
						t.Errorf("Read() error = %v, want io.EOF itself", err)
					}
				case !errors.Is(err, tc.wantErr):
					t.Errorf("Read() error = %v, want %v", err, tc.wantErr)
				}

				if got := s.outstandingRequests(); got != 0 {
					t.Errorf("Read() returned with %d reads still unanswered on the server", got)
				}

				if err := f.Close(context.Background()); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
				if s.closeSawMax != 0 {
					t.Errorf("CLOSE reached the server with %d reads still pending on it", s.closeSawMax)
				}

				conn.mu.Lock()
				pending := len(conn.pending)
				conn.mu.Unlock()
				if pending != 0 {
					t.Errorf("%d MIDs still registered after Read and Close", pending)
				}
			})
		})
	}
}

// errAny marks a table case that expects some failure other than io.EOF.
var errAny = errors.New("any read failure")

// TestFileReadPipelinedDrainGivesUp checks that a reply which never comes
// cannot hold a Read that has already stopped: the drain is bounded, the
// result is the one the stop produced, and the abandoned MID is released.
func TestFileReadPipelinedDrainGivesUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSlowServer(t, func(i int, req SMBRequest) chunkReply {
			switch i {
			case 0:
				return chunkReply{delay: time.Millisecond, data: make([]byte, 1000)}
			case 1:
				return chunkReply{never: true}
			}
			return chunkReply{delay: 50 * time.Millisecond, data: make([]byte, req.ReadLength)}
		})
		f, conn := newDrainTestFile(s)
		defer conn.Close()
		defer s.replies.Wait()
		go conn.Receive()

		start := time.Now()
		n, err := f.Read(make([]byte, 512<<10), context.Background())
		elapsed := time.Since(start)

		if n != 1000 || err != nil {
			t.Errorf("Read() = %d, %v; want 1000, nil", n, err)
		}
		if elapsed < readDrainTimeout || elapsed > readDrainTimeout+time.Second {
			t.Errorf("Read() took %v, want it to give up on the silent reply after %v", elapsed, readDrainTimeout)
		}
		if got := s.outstandingRequests(); got != 1 {
			t.Errorf("%d reads unanswered on the server, want only the silent one", got)
		}

		conn.mu.Lock()
		pending := len(conn.pending)
		conn.mu.Unlock()
		if pending != 0 {
			t.Errorf("%d MIDs still registered after the drain gave up", pending)
		}
	})
}

// TestFileWritePipelinedCollectsEveryReplyBeforeReturning is the write-side
// counterpart: however a pipelined Write stops early, the chunks it already
// put on the wire are answered before it returns, so a Close straight after
// never overlaps a write still pending on the server. The count reported stays
// the contiguous prefix the server confirmed.
func TestFileWritePipelinedCollectsEveryReplyBeforeReturning(t *testing.T) {
	late := 50 * time.Millisecond
	fast := time.Millisecond
	half := uint32(1000)

	for _, tc := range []struct {
		name        string
		reply       func(i int, req SMBRequest) chunkReply
		cancelAfter time.Duration
		wantN       func(chunk int) int
		wantErr     error
	}{
		{
			name: "error on the first chunk",
			reply: func(i int, req SMBRequest) chunkReply {
				if i == 0 {
					return chunkReply{delay: fast, status: smb1.STATUS_ACCESS_DENIED}
				}
				return chunkReply{delay: late}
			},
			wantN:   func(int) int { return 0 },
			wantErr: errAny,
		},
		{
			name: "error after a confirmed chunk",
			reply: func(i int, req SMBRequest) chunkReply {
				switch i {
				case 0:
					return chunkReply{delay: fast}
				case 1:
					return chunkReply{delay: 2 * fast, status: smb1.STATUS_ACCESS_DENIED}
				}
				return chunkReply{delay: late}
			},
			wantN:   func(chunk int) int { return chunk },
			wantErr: errAny,
		},
		{
			name: "short write on the first chunk",
			reply: func(i int, req SMBRequest) chunkReply {
				if i == 0 {
					return chunkReply{delay: fast, written: &half}
				}
				return chunkReply{delay: late}
			},
			wantN:   func(int) int { return int(half) },
			wantErr: io.ErrShortWrite,
		},
		{
			name: "undecodable reply on the first chunk",
			reply: func(i int, req SMBRequest) chunkReply {
				if i == 0 {
					return chunkReply{delay: fast, malformed: true}
				}
				return chunkReply{delay: late}
			},
			wantN:   func(int) int { return 0 },
			wantErr: errAny,
		},
		{
			name: "context cancelled mid-batch",
			reply: func(i int, req SMBRequest) chunkReply {
				return chunkReply{delay: late}
			},
			cancelAfter: 10 * time.Millisecond,
			wantN:       func(chunk int) int { return 8 * chunk },
			wantErr:     context.Canceled,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newSlowServer(t, tc.reply)
				f, conn := newDrainTestFile(s)
				defer conn.Close()
				defer s.replies.Wait()
				go conn.Receive()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if tc.cancelAfter > 0 {
					time.AfterFunc(tc.cancelAfter, cancel)
				}

				n, err := f.Write(make([]byte, 512<<10), ctx)

				if want := tc.wantN(f.maxWriteChunk()); n != want {
					t.Errorf("Write() n = %d, want %d", n, want)
				}
				switch {
				case tc.wantErr == errAny:
					if err == nil {
						t.Errorf("Write() error = nil, want a write failure")
					}
				case !errors.Is(err, tc.wantErr):
					t.Errorf("Write() error = %v, want %v", err, tc.wantErr)
				}

				if got := s.outstandingRequests(); got != 0 {
					t.Errorf("Write() returned with %d writes still unanswered on the server", got)
				}

				if err := f.Close(context.Background()); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
				if s.closeSawMax != 0 {
					t.Errorf("CLOSE reached the server with %d writes still pending on it", s.closeSawMax)
				}
			})
		})
	}
}
