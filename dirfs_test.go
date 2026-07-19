package smb1

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// fakeDirFSModTime is the timestamp every fake entry reports. A fixed value
// keeps Stat and ReadDir consistent, which fstest.TestFS verifies.
var fakeDirFSModTime = time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)

type fakeDirFSEntry struct {
	dir  bool
	data []byte
}

// fakeDirFSShare is an in-memory dirFSShare, in the same spirit as
// fakeGlobFS: keys are backslash-separated paths relative to the share root.
// It exists so the DirFS wrapper can be exercised without a server: Share's
// own methods are wire calls.
type fakeDirFSShare struct {
	entries map[string]fakeDirFSEntry
}

func newFakeDirFSShare() *fakeDirFSShare {
	return &fakeDirFSShare{entries: map[string]fakeDirFSEntry{
		"hello.txt":      {data: []byte("hello, world\n")},
		"empty.txt":      {},
		"alpha":          {dir: true},
		`alpha\a.txt`:    {data: []byte("alpha a")},
		"beta":           {dir: true},
		"sub":            {dir: true},
		`sub\inner.txt`:  {data: []byte("inner contents")},
		`sub\deep`:       {dir: true},
		`sub\deep\g.txt`: {data: []byte("deep file contents")},
	}}
}

func (f *fakeDirFSShare) stat(op, name string) (os.FileInfo, error) {
	e, ok := f.entries[name]
	if !ok {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
	}
	attrs := uint32(smb1.FILE_ATTRIBUTE_NORMAL)
	if e.dir {
		attrs = smb1.FILE_ATTRIBUTE_DIRECTORY
	}
	base := name
	if i := strings.LastIndexByte(name, '\\'); i != -1 {
		base = name[i+1:]
	}
	return &FileStat{
		FileName:       base,
		FileAttributes: attrs,
		EndOfFile:      int64(len(e.data)),
		LastWriteTime:  fakeDirFSModTime,
	}, nil
}

func (f *fakeDirFSShare) Stat(name string) (os.FileInfo, error) { return f.stat("stat", name) }

func (f *fakeDirFSShare) ReadDir(dirname string) ([]os.FileInfo, error) {
	// "" spells the share root and always exists.
	if dirname != "" {
		if e, ok := f.entries[dirname]; !ok || !e.dir {
			return nil, &fs.PathError{Op: "readdir", Path: dirname, Err: fs.ErrNotExist}
		}
	}
	// Map iteration order is random, which conveniently exercises the
	// name-sorting the fs.ReadDirFile wrapper must perform.
	var result []os.FileInfo
	for p := range f.entries {
		parent := ""
		if i := strings.LastIndexByte(p, '\\'); i != -1 {
			parent = p[:i]
		}
		if parent != dirname {
			continue
		}
		fi, err := f.stat("readdir", p)
		if err != nil {
			return nil, err
		}
		result = append(result, fi)
	}
	return result, nil
}

func (f *fakeDirFSShare) ReadFile(filename string) ([]byte, error) {
	e, ok := f.entries[filename]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: filename, Err: fs.ErrNotExist}
	}
	if e.dir {
		return nil, &fs.PathError{Op: "open", Path: filename, Err: errIsDirectory}
	}
	return append([]byte(nil), e.data...), nil
}

func (f *fakeDirFSShare) openRead(name string) (dirFSReadFile, error) {
	e, ok := f.entries[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if e.dir {
		return nil, &fs.PathError{Op: "open", Path: name, Err: errIsDirectory}
	}
	fi, err := f.stat("stat", name)
	if err != nil {
		return nil, err
	}
	return &fakeDirFSFile{Reader: bytes.NewReader(e.data), info: fi}, nil
}

// fakeDirFSFile serves file contents from memory; bytes.Reader supplies the
// Read, ReadAt and Seek behavior iotest.TestReader checks.
type fakeDirFSFile struct {
	*bytes.Reader
	info os.FileInfo
}

func (f *fakeDirFSFile) Stat() (os.FileInfo, error) { return f.info, nil }
func (f *fakeDirFSFile) Close() error               { return nil }

func newFakeDirFS(dirname string) *dirFS {
	return &dirFS{share: newFakeDirFSShare(), root: dirFSRoot(dirname)}
}

// The go-smb2 v1.1.0 DirFS satisfies exactly fs.StatFS, fs.ReadFileFS and
// fs.GlobFS beyond fs.FS (verified empirically against that package with
// runtime type assertions); the negative cases guard against accidentally
// widening the surface past parity.
func TestDirFSInterfaceParity(t *testing.T) {
	fsys := (&Share{}).DirFS(".")

	tests := []struct {
		iface string
		typ   reflect.Type
		want  bool
	}{
		{"fs.StatFS", reflect.TypeOf((*fs.StatFS)(nil)).Elem(), true},
		{"fs.ReadFileFS", reflect.TypeOf((*fs.ReadFileFS)(nil)).Elem(), true},
		{"fs.GlobFS", reflect.TypeOf((*fs.GlobFS)(nil)).Elem(), true},
		{"fs.ReadDirFS", reflect.TypeOf((*fs.ReadDirFS)(nil)).Elem(), false},
		{"fs.SubFS", reflect.TypeOf((*fs.SubFS)(nil)).Elem(), false},
	}
	for _, tt := range tests {
		if got := reflect.TypeOf(fsys).Implements(tt.typ); got != tt.want {
			t.Errorf("DirFS implements %s = %v, want %v", tt.iface, got, tt.want)
		}
	}
}

func TestDirFSRootMapping(t *testing.T) {
	tests := []struct {
		dirname string
		want    string
	}{
		{"", ""},
		{".", ""},
		{`.\`, ""},
		{`.\alpha`, "alpha"},
		{"./alpha", "alpha"},
		{"alpha", "alpha"},
		{"sub/deep", `sub\deep`},
		{`sub\deep`, `sub\deep`},
		{"  alpha  ", "alpha"},
	}
	for _, tt := range tests {
		if got := dirFSRoot(tt.dirname); got != tt.want {
			t.Errorf("dirFSRoot(%q) = %q, want %q", tt.dirname, got, tt.want)
		}
	}
}

func TestDirFSPathMapping(t *testing.T) {
	tests := []struct {
		root string
		name string
		want string
		ok   bool
	}{
		{"", ".", "", true},
		{"", "a", "a", true},
		{"", "a/b", `a\b`, true},
		{"sub", ".", "sub", true},
		{"sub", "a", `sub\a`, true},
		{`sub\deep`, "a/b", `sub\deep\a\b`, true},

		// io/fs invalid names must be rejected, not translated.
		{"", "", "", false},
		{"", "/", "", false},
		{"", "/a", "", false},
		{"", "a/", "", false},
		{"", "./a", "", false},
		{"", "a//b", "", false},
		{"", "..", "", false},
		{"", "../a", "", false},
		{"", "a/../b", "", false},

		// Valid per fs.ValidPath, but '\' and ':' have meaning on the SMB
		// side and would smuggle in extra path elements or stream syntax.
		{"", `a\b`, "", false},
		{"", "a:stream", "", false},
	}
	for _, tt := range tests {
		d := &dirFS{share: newFakeDirFSShare(), root: tt.root}
		got, ok := d.smbPath(tt.name)
		if got != tt.want || ok != tt.ok {
			t.Errorf("smbPath(root=%q, %q) = (%q, %v), want (%q, %v)",
				tt.root, tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

func TestDirFSTestFS(t *testing.T) {
	tests := []struct {
		name     string
		dirname  string
		expected []string
	}{
		{"share root", "", []string{
			"hello.txt", "empty.txt", "alpha/a.txt", "sub/inner.txt", "sub/deep/g.txt",
		}},
		{"dot root", ".", []string{"hello.txt", "sub/deep/g.txt"}},
		{"subdir root", "sub", []string{"inner.txt", "deep/g.txt"}},
		{"slash dirname", "sub/deep", []string{"g.txt"}},
		{"backslash dirname", `sub\deep`, []string{"g.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := fstest.TestFS(newFakeDirFS(tt.dirname), tt.expected...); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestDirFSErrors(t *testing.T) {
	// Each fs-level operation, with the Op its *fs.PathError must carry.
	ops := []struct {
		op   string
		call func(fsys fs.FS, name string) error
	}{
		{"open", func(fsys fs.FS, name string) error {
			f, err := fsys.Open(name)
			if err == nil {
				f.Close()
			}
			return err
		}},
		{"stat", func(fsys fs.FS, name string) error {
			_, err := fsys.(fs.StatFS).Stat(name)
			return err
		}},
		// ReadFile reports "open", matching where os.ReadFile fails.
		{"open", func(fsys fs.FS, name string) error {
			_, err := fsys.(fs.ReadFileFS).ReadFile(name)
			return err
		}},
	}

	tests := []struct {
		name    string
		root    string
		arg     string
		wantErr error
	}{
		{"invalid name", "", "../escape", fs.ErrInvalid},
		{"rooted name", "", "/hello.txt", fs.ErrInvalid},
		{"missing file", "", "nope.txt", fs.ErrNotExist},
		// The error path must stay the io/fs name, not the SMB path
		// "sub\nope.txt" the Share-level call actually failed on.
		{"missing under subdir root", "sub", "nope.txt", fs.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := newFakeDirFS(tt.root)
			for _, op := range ops {
				err := op.call(fsys, tt.arg)
				var pe *fs.PathError
				if !errors.As(err, &pe) {
					t.Fatalf("%s(%q) error = %v (%T), want *fs.PathError", op.op, tt.arg, err, err)
				}
				if pe.Op != op.op || pe.Path != tt.arg || !errors.Is(err, tt.wantErr) {
					t.Errorf("%s(%q) = &PathError{Op:%q, Path:%q, Err:%v}, want Op=%q Path=%q Err=%v",
						op.op, tt.arg, pe.Op, pe.Path, pe.Err, op.op, tt.arg, tt.wantErr)
				}
			}
		})
	}
}

func TestDirFSReadDirPaging(t *testing.T) {
	openDir := func(t *testing.T) fs.ReadDirFile {
		t.Helper()
		f, err := newFakeDirFS("").Open(".")
		if err != nil {
			t.Fatalf("Open(.) = %v", err)
		}
		d, ok := f.(fs.ReadDirFile)
		if !ok {
			t.Fatalf("Open(.) returned %T, not fs.ReadDirFile", f)
		}
		return d
	}
	names := func(entries []fs.DirEntry) []string {
		out := make([]string, len(entries))
		for i, e := range entries {
			out[i] = e.Name()
		}
		return out
	}
	sorted := []string{"alpha", "beta", "empty.txt", "hello.txt", "sub"}

	t.Run("batches", func(t *testing.T) {
		d := openDir(t)
		defer d.Close()
		var got []string
		for {
			entries, err := d.ReadDir(2)
			got = append(got, names(entries)...)
			if err == io.EOF {
				if len(entries) != 0 {
					t.Errorf("io.EOF arrived with %d entries; the final page must precede it", len(entries))
				}
				break
			}
			if err != nil {
				t.Fatalf("ReadDir(2) = %v", err)
			}
			if len(entries) == 0 {
				t.Fatal("ReadDir(2) returned no entries and no error")
			}
		}
		if !reflect.DeepEqual(got, sorted) {
			t.Errorf("paged ReadDir = %v, want %v", got, sorted)
		}
	})

	t.Run("all at once", func(t *testing.T) {
		d := openDir(t)
		defer d.Close()
		entries, err := d.ReadDir(-1)
		if err != nil {
			t.Fatalf("ReadDir(-1) = %v", err)
		}
		if got := names(entries); !reflect.DeepEqual(got, sorted) {
			t.Errorf("ReadDir(-1) = %v, want %v", got, sorted)
		}
		// Exhausted with n <= 0: empty result, nil error (not io.EOF).
		entries, err = d.ReadDir(-1)
		if len(entries) != 0 || err != nil {
			t.Errorf("ReadDir(-1) after exhaustion = (%v, %v), want (empty, nil)", names(entries), err)
		}
	})

	t.Run("read on directory", func(t *testing.T) {
		d := openDir(t)
		defer d.Close()
		if _, err := d.Read(make([]byte, 1)); err == nil {
			t.Error("Read on a directory succeeded, want error")
		} else {
			var pe *fs.PathError
			if !errors.As(err, &pe) || pe.Op != "read" || pe.Path != "." {
				t.Errorf("Read on a directory = %v, want *fs.PathError{Op:\"read\", Path:\".\"}", err)
			}
		}
	})
}

// The fs.File wrapper relies on File.ReadAt's io.ReaderAt contract: a short
// read at end of file carries io.EOF, and the sentinel must pass through the
// wrapper unwrapped.
func TestDirFSFileReadAtEOF(t *testing.T) {
	f := &dirFSFile{
		f:    &fakeDirFSFile{Reader: bytes.NewReader([]byte("abc"))},
		name: "abc.txt",
	}

	// A full read inside the file must stay error-free.
	if n, err := f.ReadAt(make([]byte, 2), 0); n != 2 || err != nil {
		t.Errorf("ReadAt(2, 0) = (%d, %v), want (2, nil)", n, err)
	}
	// A short read only happens at end of file and must carry io.EOF.
	if n, err := f.ReadAt(make([]byte, 5), 0); n != 3 || err != io.EOF {
		t.Errorf("ReadAt(5, 0) = (%d, %v), want (3, io.EOF)", n, err)
	}
}

// File.Stat reports the base element of the open path, which is exactly what
// fs.FileInfo requires; the wrapper must pass it through unchanged.
func TestDirFSFileStatName(t *testing.T) {
	f := &dirFSFile{
		f: &fakeDirFSFile{
			Reader: bytes.NewReader(nil),
			info:   &FileStat{FileName: "c.txt"},
		},
		name: "sub/c.txt",
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat() = %v", err)
	}
	if fi.Name() != "c.txt" {
		t.Errorf("Stat().Name() = %q, want %q", fi.Name(), "c.txt")
	}
}

func TestDirFSGlob(t *testing.T) {
	tests := []struct {
		name    string
		root    string
		pattern string
		want    []string
	}{
		{"root files", "", "*.txt", []string{"empty.txt", "hello.txt"}},
		{"subdir entries", "", "sub/*", []string{"sub/deep", "sub/inner.txt"}},
		{"under subdir root", "sub", "*", []string{"deep", "inner.txt"}},
		{"no match", "", "*.log", nil},
		// A path.Match escape: '[\h]' is the class {h}. Translating the
		// pattern to '\'-separated Share.Glob syntax would corrupt it, which
		// is why Glob runs client-side through fs.Glob instead.
		{"escaped class", "", `[\h]ello.txt`, []string{"hello.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := newFakeDirFS(tt.root).Glob(tt.pattern)
			if err != nil {
				t.Fatalf("Glob(%q) = %v", tt.pattern, err)
			}
			if !reflect.DeepEqual(matches, tt.want) {
				t.Errorf("Glob(%q) = %v, want %v", tt.pattern, matches, tt.want)
			}
		})
	}

	t.Run("bad pattern", func(t *testing.T) {
		if _, err := newFakeDirFS("").Glob("["); !errors.Is(err, path.ErrBadPattern) {
			t.Errorf("Glob(\"[\") = %v, want path.ErrBadPattern", err)
		}
	})
}
