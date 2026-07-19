package smb1

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/macourteau/smb1client/internal/smb1"
)

// fakeGlobFS is an in-memory globLister. Keys are backslash-separated paths
// relative to the share root; the value records whether the entry is a
// directory. It exists so the Glob traversal can be exercised without a
// server: Share's own Stat/ReadDir are wire calls.
type fakeGlobFS struct {
	entries map[string]bool // path -> isDir
}

func (f *fakeGlobFS) stat(op, name string) (os.FileInfo, error) {
	isDir, ok := f.entries[name]
	if !ok {
		return nil, &os.PathError{Op: op, Path: name, Err: os.ErrNotExist}
	}
	attrs := uint32(smb1.FILE_ATTRIBUTE_NORMAL)
	if isDir {
		attrs = smb1.FILE_ATTRIBUTE_DIRECTORY
	}
	base := name
	if i := strings.LastIndexByte(name, '\\'); i != -1 {
		base = name[i+1:]
	}
	return &FileStat{FileName: base, FileAttributes: attrs}, nil
}

func (f *fakeGlobFS) Stat(name string) (os.FileInfo, error)  { return f.stat("stat", name) }
func (f *fakeGlobFS) Lstat(name string) (os.FileInfo, error) { return f.stat("lstat", name) }

func (f *fakeGlobFS) ReadDir(dirname string) ([]os.FileInfo, error) {
	if dirname != "" {
		if isDir, ok := f.entries[dirname]; !ok || !isDir {
			return nil, &os.PathError{Op: "readdir", Path: dirname, Err: os.ErrNotExist}
		}
	}
	var result []os.FileInfo
	for path := range f.entries {
		parent := ""
		if i := strings.LastIndexByte(path, '\\'); i != -1 {
			parent = path[:i]
		}
		if parent != dirname {
			continue
		}
		fi, err := f.stat("readdir", path)
		if err != nil {
			return nil, err
		}
		result = append(result, fi)
	}
	return result, nil
}

func newFakeGlobFS() *fakeGlobFS {
	return &fakeGlobFS{entries: map[string]bool{
		"a.txt":            false,
		"b.txt":            false,
		"c.log":            false,
		"alpha":            true,
		"beta":             true,
		`alpha\d.txt`:      false,
		`alpha\e.log`:      false,
		`alpha\deep`:       true,
		`alpha\deep\g.txt`: false,
		`beta\f.txt`:       false,
	}}
}

func TestGlob(t *testing.T) {
	fs := newFakeGlobFS()

	tests := []struct {
		name    string
		pattern string
		want    []string
	}{
		{"root_extension", "*.txt", []string{"a.txt", "b.txt"}},
		{"root_all", "*", []string{"a.txt", "alpha", "b.txt", "beta", "c.log"}},
		{"subdir", `alpha\*.txt`, []string{`alpha\d.txt`}},
		{"meta_dir", `*\*.txt`, []string{`alpha\d.txt`, `beta\f.txt`}},
		{"meta_dir_two_levels", `*\*\*.txt`, []string{`alpha\deep\g.txt`}},
		{"question_mark_dir", `?lpha\*.log`, []string{`alpha\e.log`}},
		{"literal_hit", "a.txt", []string{"a.txt"}},
		{"literal_miss", "missing.txt", nil},
		{"empty_pattern", "", nil},
		{"no_matches", "*.exe", nil},
		{"file_as_dir", `a.txt\*`, nil},
		{"missing_dir", `nope\*`, nil},
		// '/' is accepted and results still use '\' (NORMALIZE_PATH default).
		{"slash_pattern", "alpha/*.txt", []string{`alpha\d.txt`}},
		{"dot_slash_pattern", `.\*.log`, []string{"c.log"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := globWith(fs, tt.pattern)
			if err != nil {
				t.Fatalf("Glob(%#q) error: %v", tt.pattern, err)
			}
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Glob(%#q) = %q, want %q", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestGlobBadPattern(t *testing.T) {
	fs := newFakeGlobFS()

	for _, pattern := range []string{"[", `alpha\[`, `[\*`} {
		if _, err := globWith(fs, pattern); !errors.Is(err, ErrBadPattern) {
			t.Errorf("Glob(%#q) error = %v, want ErrBadPattern", pattern, err)
		}
	}
}

// Share.Glob is a thin delegation to the traversal tested above; this only
// pins that a malformed pattern is rejected before any wire traffic, which is
// the sole path exercisable without a server.
func TestShareGlobBadPattern(t *testing.T) {
	fs := &Share{}
	if _, err := fs.Glob("["); !errors.Is(err, ErrBadPattern) {
		t.Errorf("Share.Glob(\"[\") error = %v, want ErrBadPattern", err)
	}
}
