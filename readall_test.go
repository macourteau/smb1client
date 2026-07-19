package smb1

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// shortReader yields at most chunk bytes per Read and reports EOF only when it
// is genuinely exhausted. It mirrors File.readSequential, which returns a short
// count with a nil error when the server answers a READ_ANDX with less data
// than was asked for — legal io.Reader behaviour that a single Read call cannot
// distinguish from end-of-file.
type shortReader struct {
	data  []byte
	chunk int
	reads int
}

func (r *shortReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	r.reads++
	n := min(min(len(p), r.chunk), len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

// zeroReader always returns (0, nil) for a non-empty buffer. It is not a legal
// io.Reader, but readAll must not spin forever if one shows up.
type zeroReader struct{ calls int }

func (r *zeroReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls > 1000 {
		return 0, errors.New("zeroReader: readAll span too long, would have hung")
	}
	return 0, nil
}

func TestReadAllShortReadsDoNotTruncate(t *testing.T) {
	// A payload well past a single chunk, so a naive single-Read implementation
	// truncates visibly.
	want := bytes.Repeat([]byte("FITS"), 4096) // 16 KiB

	for _, chunk := range []int{1, 7, 512, 4096} {
		r := &shortReader{data: append([]byte(nil), want...), chunk: chunk}

		// The stat hint is exact here, which is the case that regressed: the
		// old code trusted it and returned whatever one Read produced.
		got, err := readAll(r, len(want))
		if err != nil {
			t.Fatalf("chunk=%d: readAll returned error: %v", chunk, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("chunk=%d: readAll truncated: got %d bytes, want %d", chunk, len(got), len(want))
		}
		if r.reads < 2 {
			t.Errorf("chunk=%d: expected multiple reads, got %d — test is not exercising the short-read path", chunk, r.reads)
		}
	}
}

func TestReadAllWrongSizeHint(t *testing.T) {
	want := bytes.Repeat([]byte("x"), 5000)

	// A stat hint that under-reports (file grew, or the server lied) must not
	// cap the result.
	got, err := readAll(&shortReader{data: append([]byte(nil), want...), chunk: 256}, 10)
	if err != nil {
		t.Fatalf("undersized hint: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("undersized hint: got %d bytes, want %d", len(got), len(want))
	}

	// An over-reporting hint must not pad the result with zeros.
	got, err = readAll(&shortReader{data: append([]byte(nil), want...), chunk: 256}, 1<<16)
	if err != nil {
		t.Fatalf("oversized hint: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("oversized hint: got %d bytes, want %d", len(got), len(want))
	}
}

func TestReadAllEmptyFile(t *testing.T) {
	got, err := readAll(&shortReader{chunk: 16}, 0)
	if err != nil {
		t.Fatalf("readAll: %v", err)
	}
	if got == nil {
		t.Error("readAll returned a nil slice for an empty file; want non-nil empty")
	}
	if len(got) != 0 {
		t.Errorf("readAll returned %d bytes for an empty file", len(got))
	}
}

func TestReadAllPropagatesError(t *testing.T) {
	sentinel := errors.New("boom")
	_, err := readAll(errReader{err: sentinel}, 0)
	if !errors.Is(err, sentinel) {
		t.Errorf("readAll error = %v, want %v", err, sentinel)
	}
}

func TestReadAllNegativeHint(t *testing.T) {
	want := []byte("hello")
	got, err := readAll(&shortReader{data: append([]byte(nil), want...), chunk: 2}, -1)
	if err != nil {
		t.Fatalf("readAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReadAllDoesNotHangOnZeroReader(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = readAll(&zeroReader{}, 0)
	}()
	<-done // The zeroReader's own call cap breaks the loop; hanging here fails by timeout.
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// The stat size is server-supplied. A hint far beyond the real file must not
// pre-allocate it, and must not change the bytes returned.
func TestReadAllHugeHintIsSafe(t *testing.T) {
	want := []byte("small file")

	// Deliberately absurd, as a corrupt server might report.
	got, err := readAll(&shortReader{data: append([]byte(nil), want...), chunk: 4}, maxReadFileHint)
	if err != nil {
		t.Fatalf("readAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
