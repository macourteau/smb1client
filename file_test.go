package smb1

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// dataThenErrReader yields its payload and then a non-EOF error, the shape a
// connection failure mid-transfer takes on the Read path.
type dataThenErrReader struct {
	data []byte
	err  error
}

func (r *dataThenErrReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// eofWithDataReader returns its whole payload together with io.EOF in a
// single call — legal io.Reader behaviour that the copy loop must treat as a
// successful end, not an error.
type eofWithDataReader struct {
	data []byte
	done bool
}

func (r *eofWithDataReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.data), io.EOF
}

// shortWriter accepts at most limit bytes per call. A legal io.Writer never
// does this without an error, so the copy loop must convert it to
// io.ErrShortWrite instead of silently dropping data.
type shortWriter struct {
	buf   bytes.Buffer
	limit int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.buf.Write(p)
}

// failAfterWriter accepts the first payload then fails, reporting a partial
// count of zero on the failing call.
type failAfterWriter struct {
	buf   bytes.Buffer
	calls int
	err   error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > 1 {
		return 0, w.err
	}
	return w.buf.Write(p)
}

func TestCopyStreamCopiesAllData(t *testing.T) {
	want := bytes.Repeat([]byte("smb1"), 5000) // 20 KiB, several 4 KiB buffers

	for _, chunk := range []int{1, 7, 512, 4096} {
		src := &shortReader{data: append([]byte(nil), want...), chunk: chunk}
		var dst bytes.Buffer

		n, err := copyStream(&dst, src, make([]byte, 4096))
		if err != nil {
			t.Fatalf("chunk=%d: copyStream error: %v", chunk, err)
		}
		if n != int64(len(want)) {
			t.Errorf("chunk=%d: n = %d, want %d", chunk, n, len(want))
		}
		if !bytes.Equal(dst.Bytes(), want) {
			t.Errorf("chunk=%d: copied data differs from source", chunk)
		}
	}
}

func TestCopyStreamEmptySource(t *testing.T) {
	var dst bytes.Buffer
	n, err := copyStream(&dst, bytes.NewReader(nil), make([]byte, 64))
	if err != nil || n != 0 {
		t.Errorf("copyStream(empty) = %d, %v; want 0, nil", n, err)
	}
}

func TestCopyStreamEOFWithFinalData(t *testing.T) {
	want := []byte("final page")
	var dst bytes.Buffer

	n, err := copyStream(&dst, &eofWithDataReader{data: want}, make([]byte, 64))
	if err != nil {
		t.Fatalf("copyStream error: %v", err)
	}
	if n != int64(len(want)) || !bytes.Equal(dst.Bytes(), want) {
		t.Errorf("copyStream = %d bytes %q, want %d bytes %q", n, dst.Bytes(), len(want), want)
	}
}

func TestCopyStreamPropagatesReadError(t *testing.T) {
	sentinel := errors.New("connection lost")
	payload := []byte("partial")
	var dst bytes.Buffer

	n, err := copyStream(&dst, &dataThenErrReader{data: payload, err: sentinel}, make([]byte, 4))
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want %v", err, sentinel)
	}
	// Data read before the failure must have been delivered and counted.
	if n != int64(len(payload)) || !bytes.Equal(dst.Bytes(), payload) {
		t.Errorf("delivered %d bytes %q before error, want %d bytes %q", n, dst.Bytes(), len(payload), payload)
	}
}

func TestCopyStreamPropagatesWriteError(t *testing.T) {
	sentinel := errors.New("disk full")
	w := &failAfterWriter{err: sentinel}

	n, err := copyStream(w, &shortReader{data: bytes.Repeat([]byte("x"), 100), chunk: 10}, make([]byte, 10))
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want %v", err, sentinel)
	}
	if n != 10 {
		t.Errorf("n = %d, want 10 (only the first write succeeded)", n)
	}
}

func TestCopyStreamShortWrite(t *testing.T) {
	w := &shortWriter{limit: 3}

	n, err := copyStream(w, bytes.NewReader([]byte("0123456789")), make([]byte, 8))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("error = %v, want io.ErrShortWrite", err)
	}
	if n != 3 {
		t.Errorf("n = %d, want 3", n)
	}
}

// The interface set is part of the go-smb2 parity surface: io.Copy must pick
// WriteTo when reading from a File and ReadFrom when writing to one.
var (
	_ io.ReaderFrom   = (*File)(nil)
	_ io.WriterTo     = (*File)(nil)
	_ io.StringWriter = (*File)(nil)
)
