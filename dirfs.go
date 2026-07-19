package smb1

import (
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/macourteau/smb1client/internal/smb1"
)

// DirFS returns an fs.FS presenting the share subtree rooted at dirname as a
// read-only file system. dirname is a share path in the same form the other
// Share methods accept ('\' or, with NORMALIZE_PATH, '/' separators); "" and
// "." both denote the share root.
//
// Names passed to the returned file system follow the io/fs rules instead:
// '/'-separated, rooted at dirname, validated with fs.ValidPath, with "."
// naming the root. Errors are *fs.PathError values carrying those io/fs
// names, and errors.Is against fs.ErrNotExist, fs.ErrInvalid, etc. works as
// io/fs documents.
//
// Matching go-smb2, the result also implements fs.StatFS, fs.ReadFileFS and
// fs.GlobFS (but not fs.ReadDirFS or fs.SubFS; fs.ReadDir and fs.Sub fall
// back to Open), and files opened on a directory implement fs.ReadDirFile.
func (s *Share) DirFS(dirname string) fs.FS {
	return &dirFS{share: s, root: dirFSRoot(dirname)}
}

// dirFSShare is the subset of Share behavior DirFS reads through, split out
// (like globLister) so the wrapper can be tested against an in-memory tree:
// Share's own methods are wire calls.
type dirFSShare interface {
	Stat(name string) (os.FileInfo, error)
	ReadDir(dirname string) ([]os.FileInfo, error)
	ReadFile(filename string) ([]byte, error)
	openRead(name string) (dirFSReadFile, error)
}

// dirFSReadFile is the read-side portion of *File that dirFS serves through
// fs.File. Seek and ReadAt are included so fs consumers that probe for
// io.Seeker or io.ReaderAt (io.SectionReader, archive/zip, ...) keep working.
type dirFSReadFile interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
	Stat() (os.FileInfo, error)
}

// openRead adapts Share.Open to the dirFSReadFile interface. The error path
// must not return the typed-nil *File, which would compare non-nil as an
// interface.
func (s *Share) openRead(name string) (dirFSReadFile, error) {
	f, err := s.Open(name)
	if err != nil {
		return nil, err
	}
	return f, nil
}

var _ dirFSShare = (*Share)(nil)

// dirFS implements fs.FS over a dirFSShare subtree.
type dirFS struct {
	share dirFSShare
	root  string // SMB path of the subtree root; "" is the share root
}

// Compile-time interface coverage, matching go-smb2's DirFS exactly:
// fs.StatFS, fs.ReadFileFS and fs.GlobFS, and fs.ReadDirFile for opened
// directories. go-smb2 implements neither fs.ReadDirFS nor fs.SubFS, so
// neither does dirFS; fs.ReadDir and fs.Sub degrade to the Open-based
// fallbacks.
var (
	_ fs.FS          = (*dirFS)(nil)
	_ fs.StatFS      = (*dirFS)(nil)
	_ fs.ReadFileFS  = (*dirFS)(nil)
	_ fs.GlobFS      = (*dirFS)(nil)
	_ fs.File        = (*dirFSFile)(nil)
	_ fs.ReadDirFile = (*dirFSDir)(nil)
)

// dirFSRoot maps the DirFS dirname argument (share-style path) to the SMB
// path of the subtree root, mirroring go-smb2's normalization: "" and "."
// (and leading ".\" elements) collapse to the share root.
func dirFSRoot(dirname string) string {
	p := normalizePath(dirname)
	for strings.HasPrefix(p, `.\`) {
		p = p[2:]
	}
	if p == "." {
		return ""
	}
	return p
}

// smbPath maps an io/fs name to the SMB path under the root. The boolean
// reports validity: fs.ValidPath rules, plus a rejection of '\' and ':',
// which are separator and stream syntax on the SMB side and would otherwise
// smuggle in extra path elements (os.DirFS rejects them on Windows for the
// same reason).
func (d *dirFS) smbPath(name string) (string, bool) {
	if !fs.ValidPath(name) || strings.ContainsAny(name, `\:`) {
		return "", false
	}
	if name == "." {
		return d.root, true
	}
	p := strings.ReplaceAll(name, "/", `\`)
	if d.root != "" {
		p = d.root + `\` + p
	}
	return p, true
}

// statInfo stats an SMB path, synthesizing the share root: "" is not a path
// TRANS2_QUERY_PATH_INFORMATION can address.
func (d *dirFS) statInfo(p string) (os.FileInfo, error) {
	if p == "" {
		return &FileStat{FileName: ".", FileAttributes: smb1.FILE_ATTRIBUTE_DIRECTORY}, nil
	}
	return d.share.Stat(p)
}

// reshapeError rewrites err into the *fs.PathError shape io/fs requires: Op
// from the fs-level operation and Path holding the io/fs name the caller
// used, not the SMB backslash path Share reports. The underlying cause is
// preserved so errors.Is(err, fs.ErrNotExist) and friends keep working.
func reshapeError(op, name string, err error) error {
	if pe, ok := err.(*fs.PathError); ok {
		return &fs.PathError{Op: op, Path: name, Err: pe.Err}
	}
	return &fs.PathError{Op: op, Path: name, Err: err}
}

func (d *dirFS) Open(name string) (fs.File, error) {
	p, ok := d.smbPath(name)
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	// Share.Open cannot hold a directory open (it requests
	// FILE_NON_DIRECTORY_FILE), so the type decides the wrapper: directories
	// are served from a listing snapshot, files from an open handle.
	fi, err := d.statInfo(p)
	if err != nil {
		return nil, reshapeError("open", name, err)
	}
	if fi.IsDir() {
		return &dirFSDir{fsys: d, name: name, path: p, info: fi}, nil
	}

	f, err := d.share.openRead(p)
	if err != nil {
		return nil, reshapeError("open", name, err)
	}
	return &dirFSFile{f: f, name: name}, nil
}

func (d *dirFS) Stat(name string) (fs.FileInfo, error) {
	p, ok := d.smbPath(name)
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	fi, err := d.statInfo(p)
	if err != nil {
		return nil, reshapeError("stat", name, err)
	}
	return fi, nil
}

func (d *dirFS) ReadFile(name string) ([]byte, error) {
	p, ok := d.smbPath(name)
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	data, err := d.share.ReadFile(p)
	if err != nil {
		return nil, reshapeError("open", name, err)
	}
	return data, nil
}

// Glob implements fs.GlobFS with io/fs pattern semantics: path.Match syntax
// over '/'-separated names, path.ErrBadPattern for malformed patterns, and
// '/'-separated matches. Share.Glob is deliberately not used here — its
// patterns treat '\' as a separator, so path.Match escapes (`[\a]`) cannot
// survive the translation. Delegating to fs.Glob over a view without the
// Glob method reuses the standard traversal, which reads the tree through
// Open like every other fallback.
func (d *dirFS) Glob(pattern string) ([]string, error) {
	return fs.Glob(dirFSGlobView{d}, pattern)
}

// dirFSGlobView exposes dirFS without its Glob method, so fs.Glob uses its
// generic implementation instead of recursing.
type dirFSGlobView struct{ d *dirFS }

func (v dirFSGlobView) Open(name string) (fs.File, error) { return v.d.Open(name) }

// dirFSFile adapts an open file handle to fs.File, rewriting error paths to
// the io/fs name the file was opened under.
type dirFSFile struct {
	f    dirFSReadFile
	name string
}

func (f *dirFSFile) Stat() (fs.FileInfo, error) {
	fi, err := f.f.Stat()
	if err != nil {
		return nil, reshapeError("stat", f.name, err)
	}
	return fi, nil
}

func (f *dirFSFile) Read(b []byte) (int, error) {
	n, err := f.f.Read(b)
	if err != nil && err != io.EOF {
		err = reshapeError("read", f.name, err)
	}
	return n, err
}

func (f *dirFSFile) ReadAt(b []byte, off int64) (int, error) {
	n, err := f.f.ReadAt(b, off)
	if err != nil && err != io.EOF {
		return n, reshapeError("read", f.name, err)
	}
	return n, err
}

func (f *dirFSFile) Seek(offset int64, whence int) (int64, error) {
	n, err := f.f.Seek(offset, whence)
	if err != nil {
		return n, reshapeError("seek", f.name, err)
	}
	return n, nil
}

func (f *dirFSFile) Close() error {
	if err := f.f.Close(); err != nil {
		return reshapeError("close", f.name, err)
	}
	return nil
}

// dirFSDir is the fs.ReadDirFile for a directory. SMB1 lists a directory by
// path rather than through an open handle, so ReadDir loads the full listing
// once and pages from the name-sorted snapshot; that provides the stateful
// paging fs.ReadDirFile requires on top of the stateless Share.ReadDir.
type dirFSDir struct {
	fsys *dirFS
	name string // io/fs name, for errors
	path string // SMB path
	info os.FileInfo

	loaded  bool
	entries []fs.DirEntry
	offset  int
}

func (d *dirFSDir) Stat() (fs.FileInfo, error) { return d.info, nil }

func (d *dirFSDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errIsDirectory}
}

func (d *dirFSDir) Close() error { return nil }

func (d *dirFSDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if !d.loaded {
		infos, err := d.fsys.share.ReadDir(d.path)
		if err != nil {
			return nil, reshapeError("readdir", d.name, err)
		}
		entries := make([]fs.DirEntry, len(infos))
		for i, fi := range infos {
			entries[i] = fs.FileInfoToDirEntry(fi)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		d.entries = entries
		d.loaded = true
	}

	rest := d.entries[d.offset:]
	if n <= 0 {
		d.offset = len(d.entries)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	if n > len(rest) {
		n = len(rest)
	}
	d.offset += n
	return rest[:n], nil
}

// errIsDirectory reports a Read on an open directory, matching the shape (if
// not the exact sentinel) of os.File's EISDIR failure.
var errIsDirectory = &InternalError{"is a directory"}
