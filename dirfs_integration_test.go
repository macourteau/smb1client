//go:build integration
// +build integration

package smb1_test

import (
	"fmt"
	"os"
	"testing"
	"testing/fstest"
)

// TestDirFSAgainstServer runs the io/fs conformance battery from
// testing/fstest against DirFS on the live test server. Everything happens
// inside a subdirectory whose name embeds the pid, so concurrent suites on
// the shared container cannot collide, and root-level noise (other tests'
// leftovers) stays outside the tree fstest walks.
func TestDirFSAgainstServer(t *testing.T) {
	session, cleanup := createTestSession(t)
	defer cleanup()

	share, cleanupShare := mountTestShare(t, session)
	defer cleanupShare()

	base := fmt.Sprintf("dirfs-fstest-%d", os.Getpid())
	if err := share.MkdirAll(base+`\sub\deep`, 0755); err != nil {
		t.Fatalf("MkdirAll(%s\\sub\\deep) = %v", base, err)
	}
	defer func() {
		if err := share.RemoveAll(base); err != nil {
			t.Errorf("cleanup RemoveAll(%s) = %v", base, err)
		}
	}()

	files := map[string]string{
		base + `\hello.txt`:      "hello, world\n",
		base + `\empty.txt`:      "",
		base + `\sub\inner.txt`:  "inner contents",
		base + `\sub\deep\g.txt`: "deep file contents",
	}
	for name, contents := range files {
		if err := share.WriteFile(name, []byte(contents), 0644); err != nil {
			t.Fatalf("WriteFile(%s) = %v", name, err)
		}
	}

	t.Run("Root", func(t *testing.T) {
		err := fstest.TestFS(share.DirFS(base),
			"hello.txt", "empty.txt", "sub/inner.txt", "sub/deep/g.txt")
		if err != nil {
			t.Fatal(err)
		}
	})

	// A nested dirname exercises the root-prefix path mapping.
	t.Run("Subdir", func(t *testing.T) {
		err := fstest.TestFS(share.DirFS(base+`\sub`), "inner.txt", "deep/g.txt")
		if err != nil {
			t.Fatal(err)
		}
	})
}
