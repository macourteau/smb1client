package smb1

import (
	"context"
	"io"
	"os"

	"github.com/macourteau/smb1client/internal/client"
)

// File represents an open file on an SMB share.
// It provides methods for reading, writing, and seeking within the file.
// File implements io.Reader, io.Writer, io.Seeker, io.ReaderAt, and io.WriterAt.
type File struct {
	f    *client.File    // internal file handle
	ctx  context.Context // context for operations
	name string          // file path
}

// Name returns the name of the file.
func (f *File) Name() string {
	return f.name
}

// Read reads up to len(b) bytes from the File.
// It returns the number of bytes read and any error encountered.
// At end of file, Read returns 0, io.EOF.
// For large reads (>= 128KB), this method uses request pipelining for improved performance.
func (f *File) Read(b []byte) (n int, err error) {
	// Use the internal pipelined Read() for improved performance
	n, err = f.f.Read(b, f.ctx)
	if err != nil && err != io.EOF {
		return n, &os.PathError{Op: "read", Path: f.name, Err: wrapError(err)}
	}
	return n, err
}

// ReadAt reads len(b) bytes from the File starting at byte offset off.
// It returns the number of bytes read and the error, if any.
// ReadAt always returns a non-nil error when n < len(b).
// At end of file, that error is io.EOF.
func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, &os.PathError{Op: "read", Path: f.name, Err: os.ErrInvalid}
	}

	n, err = f.f.ReadAt(b, off, f.ctx)
	if err != nil && err != io.EOF {
		return n, &os.PathError{Op: "read", Path: f.name, Err: wrapError(err)}
	}
	return n, err
}

// Write writes len(b) bytes to the File.
// It returns the number of bytes written and an error, if any.
// Write returns a non-nil error when n != len(b).
func (f *File) Write(b []byte) (n int, err error) {
	n, err = f.f.Write(b, f.ctx)
	return n, wrapError(err)
}

// WriteString is like Write, but writes the contents of string s rather than
// a slice of bytes.
func (f *File) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}

// WriteAt writes len(b) bytes to the File starting at byte offset off.
// It returns the number of bytes written and an error, if any.
// WriteAt returns a non-nil error when n != len(b).
func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, &os.PathError{Op: "write", Path: f.name, Err: os.ErrInvalid}
	}

	n, err = f.f.WriteAt(b, off, f.ctx)
	if err != nil {
		return n, &os.PathError{Op: "write", Path: f.name, Err: wrapError(err)}
	}
	return n, nil
}

// Seek sets the offset for the next Read or Write on file to offset,
// interpreted according to whence: 0 means relative to the origin of the file,
// 1 means relative to the current offset, and 2 means relative to the end.
// It returns the new offset and an error, if any.
func (f *File) Seek(offset int64, whence int) (int64, error) {
	newOffset, err := f.f.SeekContext(offset, whence, f.ctx)
	if err != nil {
		return 0, &os.PathError{Op: "seek", Path: f.name, Err: wrapError(err)}
	}
	return newOffset, nil
}

// Close closes the File, rendering it unusable for I/O.
// It returns an error, if any.
func (f *File) Close() error {
	err := f.f.Close(f.ctx)
	if err != nil {
		return &os.PathError{Op: "close", Path: f.name, Err: wrapError(err)}
	}
	return nil
}

// Stat returns the FileInfo structure describing file.
// If there is an error, it will be of type *os.PathError.
func (f *File) Stat() (os.FileInfo, error) {
	stat, err := f.f.Stat(f.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: f.name, Err: wrapError(err)}
	}

	// Convert internal FileStat to public FileStat
	fileStat := &FileStat{
		CreationTime:   convertFileTimeToTime(stat.CreationTime),
		LastAccessTime: convertFileTimeToTime(stat.LastAccessTime),
		LastWriteTime:  convertFileTimeToTime(stat.LastWriteTime),
		ChangeTime:     convertFileTimeToTime(stat.ChangeTime),
		EndOfFile:      stat.EndOfFile,
		AllocationSize: stat.AllocationSize,
		FileAttributes: stat.FileAttributes,
		FileName:       stat.FileName,
	}

	return fileStat, nil
}

// Readdir reads the contents of the directory associated with file and
// returns a slice of up to n FileInfo values, as would be returned
// by Lstat, in directory order. Subsequent calls on the same file will
// yield further FileInfos.
//
// If n > 0, Readdir returns at most n FileInfo structures. In this case,
// if Readdir returns an empty slice, it will return a non-nil error
// explaining why. At the end of a directory, the error is io.EOF.
//
// If n <= 0, Readdir returns all the FileInfo from the directory in
// a single slice. In this case, if Readdir succeeds (reads all
// the way to the end of the directory), it returns the slice and a
// nil error. If it encounters an error before the end of the
// directory, Readdir returns the FileInfo read until that point
// and a non-nil error.
//
// Note: This implementation uses the file's offset to track pagination
// state. Calling Seek() on the file will reset the directory reading
// position. Also note that this only works if the file was opened as
// a directory.
func (f *File) Readdir(n int) ([]os.FileInfo, error) {
	// Call internal implementation
	internalStats, err := f.f.Readdir(n, f.ctx)
	if err != nil && err != io.EOF {
		return nil, &os.PathError{Op: "readdir", Path: f.name, Err: wrapError(err)}
	}

	// Convert internal FileStat to public os.FileInfo
	result := make([]os.FileInfo, len(internalStats))
	for i, stat := range internalStats {
		result[i] = &FileStat{
			CreationTime:   convertFileTimeToTime(stat.CreationTime),
			LastAccessTime: convertFileTimeToTime(stat.LastAccessTime),
			LastWriteTime:  convertFileTimeToTime(stat.LastWriteTime),
			ChangeTime:     convertFileTimeToTime(stat.ChangeTime),
			EndOfFile:      stat.EndOfFile,
			AllocationSize: stat.AllocationSize,
			FileAttributes: stat.FileAttributes,
			FileName:       stat.FileName,
		}
	}

	// io.EOF passes through bare, together with any final page of entries,
	// so callers can page with the documented io.EOF contract; wrapping it in
	// a PathError would both hide the sentinel and drop the last batch.
	return result, err
}

// Readdirnames reads the contents of the directory associated with file and
// returns a slice of up to n names of files in the directory, in directory
// order. Paging behaves exactly as Readdir: subsequent calls on the same
// file yield further names, and with n > 0 the error at the end of the
// directory is io.EOF (possibly alongside the final page of names).
func (f *File) Readdirnames(n int) (names []string, err error) {
	stats, err := f.Readdir(n)
	if err != nil && err != io.EOF {
		return nil, err
	}

	names = make([]string, len(stats))
	for i, stat := range stats {
		names[i] = stat.Name()
	}
	return names, err
}

// Truncate changes the size of the file.
// It does not change the I/O offset.
// If there is an error, it will be of type *os.PathError.
func (f *File) Truncate(size int64) error {
	if size < 0 {
		return &os.PathError{Op: "truncate", Path: f.name, Err: os.ErrInvalid}
	}

	err := f.f.Truncate(size, f.ctx)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: f.name, Err: wrapError(err)}
	}

	return nil
}

// copyStreamBufferSize is the buffer used by ReadFrom and WriteTo. 128 KiB
// matches the threshold at which File.Read switches to pipelined requests,
// so a WriteTo-driven download uses the pipelined path on every full buffer.
const copyStreamBufferSize = 128 * 1024

// ReadFrom implements io.ReaderFrom: it reads from r until EOF and writes
// the data to f through the ordinary Write path in buffered chunks. Unlike
// go-smb2, no server-side copy is attempted when r is another File; the data
// always streams through the client.
func (f *File) ReadFrom(r io.Reader) (n int64, err error) {
	return copyStream(f, r, make([]byte, copyStreamBufferSize))
}

// WriteTo implements io.WriterTo: it reads f to EOF through the ordinary
// Read path and writes the data to w in buffered chunks. Like ReadFrom this
// is plain client-side streaming, not a server-side copy.
func (f *File) WriteTo(w io.Writer) (n int64, err error) {
	return copyStream(w, f, make([]byte, copyStreamBufferSize))
}

// copyStream copies src to dst through buf until EOF, with the same contract
// as io.Copy: a successful copy ends with a nil error, a short write reports
// io.ErrShortWrite, and data read before a failure is always delivered to
// dst first. It deliberately skips io.Copy's ReaderFrom/WriterTo delegation:
// File implements both, and delegating from inside them would recurse.
func copyStream(dst io.Writer, src io.Reader, buf []byte) (n int64, err error) {
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if werr != nil {
				return n, werr
			}
			if nw != nr {
				return n, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return n, nil
			}
			return n, rerr
		}
	}
}

// Sync commits the current contents of the file to stable storage.
// Typically, this means flushing the file system's in-memory copy
// of recently written data to disk.
func (f *File) Sync() error {
	// SMB1 doesn't have a direct flush/sync command for individual files
	// The SMB_COM_FLUSH command could be used, but it's not widely supported
	// For now, this is a no-op
	return nil
}

// Compile-time interface checks to ensure File implements standard interfaces
var (
	_ io.Reader       = (*File)(nil)
	_ io.Writer       = (*File)(nil)
	_ io.Seeker       = (*File)(nil)
	_ io.Closer       = (*File)(nil)
	_ io.ReaderAt     = (*File)(nil)
	_ io.WriterAt     = (*File)(nil)
	_ io.ReadCloser   = (*File)(nil)
	_ io.WriteCloser  = (*File)(nil)
	_ io.ReaderFrom   = (*File)(nil)
	_ io.WriterTo     = (*File)(nil)
	_ io.StringWriter = (*File)(nil)
)
