package smb1

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/macourteau/smb1client/internal/client"
	"github.com/macourteau/smb1client/internal/smb1"
	"github.com/macourteau/smb1client/internal/srvsvc"
)

// Constants for SMB operations and protocol parameters.
const (
	// maxRemoveRetries is the number of times to retry removing a directory when it
	// fails due to sharing violations (open search handles). The server should close
	// search handles automatically, but this may take time when using FIND operations.
	// Retries use exponential backoff with a cap of 1 second between attempts.
	maxRemoveRetries = 10

	// rapReceiveBufferSize is the maximum buffer size for RAP (Remote Administration
	// Protocol) responses. RAP is used for operations like NetShareEnum to list
	// available shares. This size matches the maximum SMB1 buffer size of 64KB - 1.
	rapReceiveBufferSize = 65535

	// findRequestBatchSize is the number of directory entries to request in each
	// FIND_FIRST2/FIND_NEXT2 transaction for optimal performance. Smaller batch
	// sizes prevent response truncation while minimizing the number of round trips.
	// A value of 100 balances memory usage with performance for typical directories.
	findRequestBatchSize = 100
)

// mapSMBErrorToOSError maps SMB protocol errors to os package errors.
// It checks for common error conditions (not found, permission denied) and
// wraps them in the appropriate os error type with proper context.
func mapSMBErrorToOSError(err error, op, path string) error {
	if err == nil {
		return nil
	}

	// Check for not-found errors using error classification
	if IsNotFoundError(err) {
		return &os.PathError{Op: op, Path: path, Err: os.ErrNotExist}
	}

	// Check for permission errors using error classification
	if IsPermissionError(err) {
		return &os.PathError{Op: op, Path: path, Err: os.ErrPermission}
	}

	// Return original error wrapped in PathError, classifying context and
	// transport failures on the way out.
	return &os.PathError{Op: op, Path: path, Err: wrapError(err)}
}

// mapSMBErrorToLinkError maps SMB protocol errors to os.LinkError for operations
// involving two paths (rename, link, etc.).
func mapSMBErrorToLinkError(err error, op, oldpath, newpath string) error {
	if err == nil {
		return nil
	}

	// Check for not-found errors using error classification
	if IsNotFoundError(err) {
		return &os.LinkError{Op: op, Old: oldpath, New: newpath, Err: os.ErrNotExist}
	}

	// Check for permission errors using error classification
	if IsPermissionError(err) {
		return &os.LinkError{Op: op, Old: oldpath, New: newpath, Err: os.ErrPermission}
	}

	// Return original error wrapped in LinkError, classifying context and
	// transport failures on the way out.
	return &os.LinkError{Op: op, Old: oldpath, New: newpath, Err: wrapError(err)}
}

// Session represents an authenticated SMB1 session.
// A session is created after successful protocol negotiation and authentication.
//
// The session is used to mount shares (Mount) and can be closed with Logoff.
// A single session can have multiple shares mounted simultaneously.
type Session struct {
	s    *client.Session // internal session
	conn *client.Conn    // underlying connection
	ctx  context.Context // default context for operations
	addr string          // remote address (for auto-completing UNC paths)
}

// WithContext returns a new Session that uses the provided context as its default.
// If ctx is nil, it returns nil and the original Session remains unmodified.
//
// The original Session is not modified - a new Session struct is returned
// that shares the same underlying connection and authentication but uses
// a different default context.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	sessionWithTimeout := session.WithContext(ctx)
//	share, err := sessionWithTimeout.Mount("Share")
func (c *Session) WithContext(ctx context.Context) *Session {
	if ctx == nil {
		return nil
	}
	return &Session{
		s:    c.s,
		conn: c.conn,
		ctx:  ctx,
		addr: c.addr,
	}
}

// Logoff terminates the SMB session and closes the connection.
//
// After calling Logoff, the session and any mounted shares should not be used.
// All open files are closed automatically by the server when the session ends.
//
// It's recommended to call Logoff in a defer statement:
//
//	session, err := dialer.Dial(conn)
//	if err != nil {
//		return err
//	}
//	defer session.Logoff()
func (c *Session) Logoff() error {
	logger := LoggerFromContext(c.ctx)
	logger.Debug("Logging off SMB1 session")

	// Perform SMB logoff (skip if internal session is nil, for mocks/tests)
	if c.s != nil {
		if err := c.s.Logoff(c.ctx); err != nil {
			// Even if logoff fails, close the connection
			if c.conn != nil {
				c.conn.Close()
			}
			return wrapError(err)
		}
	}

	// Close the underlying connection
	if c.conn != nil {
		return wrapError(c.conn.Close())
	}

	return nil
}

// Mount connects to a share on the server.
//
// The sharename can be specified in multiple formats:
//   - "ShareName" - just the share name (server name is added automatically)
//   - "\\server\ShareName" - full UNC path
//   - "server\ShareName" - UNC path without leading backslashes
//
// The server's NetBIOS name is automatically added if not present in the sharename.
// Note: SMB1 requires the NetBIOS name, not the IP address, in UNC paths.
//
// Examples:
//
//	// These are equivalent (assuming server name is "FILESERVER"):
//	share, err := session.Mount("Public")
//	share, err := session.Mount("\\FILESERVER\Public")
//	share, err := session.Mount("FILESERVER\Public")
//
// The returned Share inherits the Session's context (including any logger).
// Call Share.WithContext() if you need to use a different context for the share.
func (c *Session) Mount(sharename string) (*Share, error) {
	// Normalize the share name
	sharename = normalizePath(sharename)

	// If sharename doesn't contain a backslash, add server address
	if !strings.Contains(sharename, "\\") {
		// Per impacket reference implementation, SMB1 tree connect should use
		// the IP address, not the NetBIOS name
		addr := c.addr
		if idx := strings.LastIndex(addr, ":"); idx != -1 {
			addr = addr[:idx]
		}
		sharename = fmt.Sprintf(`\\%s\%s`, addr, sharename)
	}

	// Ensure sharename has leading backslashes
	if !strings.HasPrefix(sharename, `\\`) {
		sharename = `\\` + sharename
	}

	// Validate UNC path format
	if err := validateMountPath(sharename); err != nil {
		return nil, err
	}

	logger := LoggerFromContext(c.ctx)
	logger.Debug("Mounting share: %s", sharename)

	// Connect to the tree (share)
	tree, err := c.s.TreeConnect(sharename, c.ctx)
	if err != nil {
		return nil, wrapError(err)
	}

	logger.Debug("Share mounted successfully")

	return &Share{
		tree: tree,
		ctx:  c.ctx,
	}, nil
}

// isNotSupportedError checks if an error is STATUS_NOT_SUPPORTED.
func isNotSupportedError(err error) bool {
	if err == nil {
		return false
	}
	// Check if error message contains "not supported" status code
	errStr := err.Error()
	return strings.Contains(errStr, "0xC00000BB") || strings.Contains(strings.ToLower(errStr), "not supported")
}

// ListSharenames enumerates available shares on the server.
//
// This method first attempts to use the RAP (Remote Administration Protocol)
// NetShareEnum command for maximum compatibility with SMB1 servers. If RAP
// is not supported (STATUS_NOT_SUPPORTED), it falls back to the more modern
// RPC/SRVSVC NetShareEnumAll method.
//
// The returned list includes share names but not administrative metadata.
// Hidden shares (ending with $) and administrative shares (IPC$, ADMIN$, etc.)
// are included in the results.
//
// Example:
//
//	shares, err := session.ListSharenames()
//	if err != nil {
//		log.Fatal(err)
//	}
//	for _, share := range shares {
//		fmt.Println(share)
//	}
//
// Limitations:
//   - Returns only share names, not types or comments
//   - Requires IPC$ access (typically granted to all authenticated users)
func (c *Session) ListSharenames() ([]string, error) {
	logger := LoggerFromContext(c.ctx)

	// Try RAP first (faster, legacy compatible)
	logger.Debug("Attempting share enumeration via RAP (\\PIPE\\LANMAN)")
	shares, err := c.listSharenamesRAP()
	if err == nil {
		logger.Debug("RAP share enumeration succeeded, found %d shares", len(shares))
		return shares, nil
	}

	// Check if error is STATUS_NOT_SUPPORTED
	if !isNotSupportedError(err) {
		// RAP failed for reason other than not supported
		logger.Debug("RAP share enumeration failed: %v", err)
		return nil, err
	}

	// RAP not supported, try RPC/SRVSVC
	logger.Debug("RAP not supported, falling back to RPC/SRVSVC")
	shares, err = c.listSharenamesRPC()
	if err != nil {
		logger.Debug("RPC share enumeration failed: %v", err)
		return nil, fmt.Errorf("share enumeration failed (RAP not supported, RPC failed): %w", err)
	}

	logger.Debug("RPC share enumeration succeeded, found %d shares", len(shares))
	return shares, nil
}

// listSharenamesRAP enumerates shares using RAP NetShareEnum.
func (c *Session) listSharenamesRAP() ([]string, error) {
	logger := LoggerFromContext(c.ctx)
	logger.Debug("Listing shares using RAP NetShareEnum")

	// Connect to IPC$ share for RAP operations
	ipcShare, err := c.s.TreeConnect(fmt.Sprintf(`\\%s\IPC$`, c.addr), c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPC$ share: %w", err)
	}
	defer func() {
		// Best effort disconnect from IPC$
		if disconnectErr := c.s.TreeDisconnect(ipcShare.TID, c.ctx); disconnectErr != nil {
			logger.Warn("Warning: failed to disconnect from IPC$: %v", disconnectErr)
		}
	}()

	// Create NetShareEnum RAP request (info level 1)
	req := &smb1.NetShareEnumRequest{
		InfoLevel:  1,                    // Level 1 provides name, type, and comment
		ReceiveBuf: rapReceiveBufferSize, // Maximum receive buffer
	}

	// Encode RAP request
	params, data, err := smb1.EncodeNetShareEnumRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode NetShareEnum request: %w", err)
	}

	logger.Debug("Sending RAP NetShareEnum request to \\PIPE\\LANMAN")

	// Send TRANSACTION request to \PIPE\LANMAN
	transResp, err := ipcShare.SendTransaction(`\PIPE\LANMAN`, params, data, c.ctx)
	if err != nil {
		return nil, fmt.Errorf("NetShareEnum transaction failed: %w", err)
	}

	logger.Debug("Received RAP response: %d param bytes, %d data bytes", len(transResp.Parameters), len(transResp.Data))

	// Decode NetShareEnum response
	shareResp, err := smb1.DecodeNetShareEnumResponse(transResp.Parameters, transResp.Data, req.InfoLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to decode NetShareEnum response: %w", err)
	}

	logger.Debug("Found %d shares (%d available)", shareResp.EntryCount, shareResp.Available)

	// Extract share names
	shares := make([]string, 0, len(shareResp.Shares))
	for _, share := range shareResp.Shares {
		shares = append(shares, share.Name)
	}

	return shares, nil
}

// listSharenamesRPC enumerates shares using RPC/SRVSVC NetShareEnumAll.
func (c *Session) listSharenamesRPC() ([]string, error) {
	logger := LoggerFromContext(c.ctx)
	logger.Debug("Listing shares using RPC/SRVSVC NetShareEnumAll")

	// Connect to IPC$ share for RPC operations
	ipcShare, err := c.s.TreeConnect(fmt.Sprintf(`\\%s\IPC$`, c.addr), c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPC$ share: %w", err)
	}
	defer func() {
		// Best effort disconnect from IPC$
		if disconnectErr := c.s.TreeDisconnect(ipcShare.TID, c.ctx); disconnectErr != nil {
			logger.Warn("Warning: failed to disconnect from IPC$: %v", disconnectErr)
		}
	}()

	// Open \srvsvc named pipe
	pipe, err := ipcShare.OpenNamedPipe(`\srvsvc`, c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open \\srvsvc pipe: %w", err)
	}
	defer pipe.Close(c.ctx)

	// Bind to SRVSVC interface
	contextID, err := ipcShare.RPCBind(pipe, srvsvc.InterfaceUUID, srvsvc.InterfaceVersion, c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to bind SRVSVC interface: %w", err)
	}

	// Prepare NetShareEnumAll request
	requestData := srvsvc.EncodeNetShareEnumAllRequest(c.addr)

	// Send RPC request
	callID := uint32(1)
	responseData, err := ipcShare.RPCRequest(pipe, contextID, srvsvc.OpNetShareEnumAll, requestData, callID, c.ctx)
	if err != nil {
		return nil, fmt.Errorf("NetShareEnumAll RPC request failed: %w", err)
	}

	// Decode response
	shareInfos, err := srvsvc.DecodeNetShareEnumAllResponse(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode share enumeration response: %w", err)
	}

	// Extract share names
	shares := make([]string, 0, len(shareInfos))
	for _, info := range shareInfos {
		shares = append(shares, info.Name)
	}

	return shares, nil
}

// Share represents a mounted SMB share (tree connection).
// The share provides file system operations like opening files,
// creating directories, and listing directory contents.
type Share struct {
	tree *client.Tree    // internal tree connection
	ctx  context.Context // default context for operations
}

// WithContext returns a new Share that uses the provided context as its default.
// If ctx is nil, it returns nil and the original Share remains unmodified.
//
// The original Share is not modified - a new Share struct is returned
// that uses the same underlying tree connection but with a different
// default context.
func (fs *Share) WithContext(ctx context.Context) *Share {
	if ctx == nil {
		return nil
	}
	return &Share{
		tree: fs.tree,
		ctx:  ctx,
	}
}

// Umount disconnects from the share (sends TREE_DISCONNECT).
//
// After calling Umount, the share should not be used. All open files
// on this share are closed automatically by the server.
//
// It's recommended to call Umount in a defer statement:
//
//	share, err := session.Mount("Public")
//	if err != nil {
//		return err
//	}
//	defer share.Umount()
func (fs *Share) Umount() error {
	logger := LoggerFromContext(fs.ctx)
	logger.Debug("Unmounting share")
	return wrapError(fs.tree.Session.TreeDisconnect(fs.tree.TID, fs.ctx))
}

// Create creates or truncates the named file. If the file already exists,
// it is truncated. If the file does not exist, it is created with mode 0666.
// If successful, methods on the returned File can be used for I/O;
// the associated file descriptor has mode O_RDWR.
// If there is an error, it will be of type *os.PathError.
func (fs *Share) Create(name string) (*File, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

// Open opens the named file for reading. If successful, methods on
// the returned file can be used for reading; the associated file
// descriptor has mode O_RDONLY.
// If there is an error, it will be of type *os.PathError.
func (fs *Share) Open(name string) (*File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

// OpenFile is the generalized open call; most users will use Open or Create
// instead. It opens the named file with specified flag (O_RDONLY etc.) and
// perm (before umask), if applicable. If successful, methods on the returned
// File can be used for I/O. If there is an error, it will be of type
// *os.PathError.
func (fs *Share) OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	// Store original name for File.Name() to return
	originalName := name

	// Normalize the path (convert forward slashes, trim spaces)
	name = normalizePath(name)

	// Validate the path
	if err := validateFilePath(name); err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}

	// Convert os flags to SMB access flags
	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = smb1.GENERIC_READ | smb1.SYNCHRONIZE
	case os.O_WRONLY:
		access = smb1.GENERIC_WRITE | smb1.SYNCHRONIZE
	case os.O_RDWR:
		access = smb1.GENERIC_READ | smb1.GENERIC_WRITE | smb1.SYNCHRONIZE
	}
	if flag&os.O_CREATE != 0 {
		access |= smb1.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		access &^= smb1.GENERIC_WRITE
		access |= smb1.FILE_APPEND_DATA
	}

	// Share access (allow other processes to read/write)
	sharemode := smb1.FILE_SHARE_READ | smb1.FILE_SHARE_WRITE

	// Convert os flags to SMB create disposition
	var createmode uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL):
		createmode = smb1.FILE_CREATE
	case flag&(os.O_CREATE|os.O_TRUNC) == (os.O_CREATE | os.O_TRUNC):
		createmode = smb1.FILE_OVERWRITE_IF
	case flag&os.O_CREATE == os.O_CREATE:
		createmode = smb1.FILE_OPEN_IF
	case flag&os.O_TRUNC == os.O_TRUNC:
		createmode = smb1.FILE_OVERWRITE
	default:
		createmode = smb1.FILE_OPEN
	}

	// Create options
	createOptions := smb1.FILE_NON_DIRECTORY_FILE

	// Open the file
	f, err := fs.tree.OpenFile(name, access, sharemode, createmode, createOptions, fs.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: wrapError(err)}
	}

	// Wrap in public File type
	file := &File{
		f:    f,
		ctx:  fs.ctx,
		name: originalName, // Use original path for File.Name()
	}

	// If O_APPEND, seek to end
	if flag&os.O_APPEND != 0 {
		_, err := f.SeekContext(0, io.SeekEnd, fs.ctx)
		if err != nil {
			f.Close(fs.ctx)
			return nil, &os.PathError{Op: "open", Path: name, Err: wrapError(err)}
		}
	}

	return file, nil
}

// Mkdir creates a new directory with the specified name and permission
// bits (before umask).
// If there is an error, it will be of type *os.PathError.
func (fs *Share) Mkdir(name string, perm os.FileMode) error {
	name = normalizePath(name)

	if err := validateFilePath(name); err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}

	// Open with FILE_DIRECTORY_FILE option
	f, err := fs.tree.OpenFile(
		name,
		smb1.FILE_WRITE_ATTRIBUTES,
		smb1.FILE_SHARE_READ|smb1.FILE_SHARE_WRITE,
		smb1.FILE_CREATE,
		smb1.FILE_DIRECTORY_FILE,
		fs.ctx,
	)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: wrapError(err)}
	}

	// Close immediately
	if err := f.Close(fs.ctx); err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: wrapError(err)}
	}

	return nil
}

// MkdirAll creates a directory named path, along with any necessary parents,
// and returns nil, or else returns an error. The permission bits perm (before
// umask) are used for all directories that MkdirAll creates. If path is
// already a directory, MkdirAll does nothing and returns nil.
func (fs *Share) MkdirAll(path string, perm os.FileMode) error {
	path = normalizePath(path)

	// Split path into components
	parts := strings.Split(path, "\\")

	// Build path incrementally
	currentPath := ""
	for _, part := range parts {
		if part == "" {
			continue
		}

		if currentPath == "" {
			currentPath = part
		} else {
			currentPath = currentPath + "\\" + part
		}

		// Try to create directory, ignore error if it already exists
		err := fs.Mkdir(currentPath, perm)
		if err != nil && !IsExistError(err) {
			return err
		}
	}

	return nil
}

// Remove removes the named file or (empty) directory.
// If there is an error, it will be of type *os.PathError.
func (fs *Share) Remove(name string) error {
	name = normalizePath(name)

	if err := validateFilePath(name); err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	// Check if it's a directory to use appropriate flags
	stat, err := fs.Stat(name)
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	// Open the file/directory with DELETE access and FILE_DELETE_ON_CLOSE option
	// This will mark it for deletion. When we close the handle, it will be deleted.
	access := smb1.DELETE
	sharemode := smb1.FILE_SHARE_READ | smb1.FILE_SHARE_WRITE | smb1.FILE_SHARE_DELETE
	createmode := smb1.FILE_OPEN // Must exist
	createOptions := smb1.FILE_DELETE_ON_CLOSE

	// Use FILE_DIRECTORY_FILE for directories, FILE_NON_DIRECTORY_FILE for files
	if stat.IsDir() {
		createOptions |= smb1.FILE_DIRECTORY_FILE
	} else {
		createOptions |= smb1.FILE_NON_DIRECTORY_FILE
	}

	f, err := fs.tree.OpenFile(name, access, sharemode, createmode, createOptions, fs.ctx)
	if err != nil {
		// For directories, if we get a sharing violation, it might be because a search
		// handle from ReadDir() is still open. The server should close it eventually,
		// so retry with increasing delays.
		errStr := err.Error()
		if stat.IsDir() && (strings.Contains(errStr, "share access flags are incompatible") ||
			strings.Contains(errStr, "STATUS_SHARING_VIOLATION")) {
			// Retry with exponential backoff (total ~5 seconds)
			for i := 0; i < maxRemoveRetries; i++ {
				delay := time.Duration(50*(1<<uint(i))) * time.Millisecond // 50ms, 100ms, 200ms, ...
				if delay > 1*time.Second {
					delay = 1 * time.Second
				}

				// Check for context cancellation during sleep
				select {
				case <-time.After(delay):
					// Continue with retry
				case <-fs.ctx.Done():
					return &os.PathError{Op: "remove", Path: name, Err: wrapError(fs.ctx.Err())}
				}

				f, err = fs.tree.OpenFile(name, access, sharemode, createmode, createOptions, fs.ctx)
				if err == nil {
					break
				}
			}
			if err != nil {
				return mapSMBErrorToOSError(err, "remove", name)
			}
			// Fall through to close and return
		} else {
			return mapSMBErrorToOSError(err, "remove", name)
		}
	}

	// Close the file to complete the deletion
	if err := f.Close(fs.ctx); err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: wrapError(err)}
	}

	return nil
}

// RemoveAll removes path and any children it contains.
// It removes everything it can but returns the first error
// it encounters. If the path does not exist, RemoveAll
// returns nil (no error).
func (fs *Share) RemoveAll(path string) error {
	path = normalizePath(path)

	// Check if path exists
	exists, err := fs.Exists(path)
	if err != nil {
		return &os.PathError{Op: "remove", Path: path, Err: err}
	}
	if !exists {
		return nil
	}

	// Check if it's a directory
	isDir, err := fs.IsDir(path)
	if err != nil {
		return &os.PathError{Op: "remove", Path: path, Err: err}
	}

	// If it's a file, just remove it
	if !isDir {
		return fs.Remove(path)
	}

	// It's a directory - recursively remove children
	entries, err := fs.ReadDir(path)
	if err != nil {
		return &os.PathError{Op: "remove", Path: path, Err: err}
	}

	// Remove each child
	for _, entry := range entries {
		childPath := path
		if path == "" {
			childPath = entry.Name()
		} else {
			childPath = path + "\\" + entry.Name()
		}

		if err := fs.RemoveAll(childPath); err != nil {
			return err
		}
	}

	// Remove the directory itself
	return fs.Remove(path)
}

// Rename renames (moves) oldpath to newpath. Files and directories can be
// renamed within a directory or moved between directories on the same share.
//
// Unlike os.Rename, Rename does not replace an existing newpath: the
// underlying SMB_COM_RENAME command fails with STATUS_OBJECT_NAME_COLLISION
// if newpath already exists (use IsExistError to detect this case). This
// matches go-smb2, whose Rename also does not overwrite an existing target.
// If there is an error, it will be of type *os.LinkError.
func (fs *Share) Rename(oldpath, newpath string) error {
	oldpath = normalizePath(oldpath)
	newpath = normalizePath(newpath)

	if err := validateFilePath(oldpath); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	if err := validateFilePath(newpath); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	// Send rename request using helper
	err := fs.tree.SendRename(oldpath, newpath, fs.ctx)
	if err != nil {
		return mapSMBErrorToLinkError(err, "rename", oldpath, newpath)
	}

	return nil
}

// Truncate changes the size of the named file. It opens the file write-only,
// resizes it, and closes it; the file must already exist.
// A negative size returns os.ErrInvalid; other errors are of type
// *os.PathError.
func (fs *Share) Truncate(name string, size int64) error {
	if size < 0 {
		return os.ErrInvalid
	}

	f, err := fs.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	err = f.Truncate(size)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Stat returns a FileInfo describing the named file.
// If there is an error, it will be of type *os.PathError.
func (fs *Share) Stat(name string) (os.FileInfo, error) {
	name = normalizePath(name)

	if err := validateFilePath(name); err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	// Query both basic info (timestamps, attributes) and standard info (size, directory flag)
	// First query: SMB_QUERY_FILE_BASIC_INFO
	useUnicode := (fs.tree.GetCapabilities() & smb1.CAP_UNICODE) != 0
	params, err := smb1.EncodeQueryPathInfo(name, smb1.SMB_QUERY_FILE_BASIC_INFO, useUnicode)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	trans2Resp, err := fs.tree.SendTransact2(smb1.TRANS2_QUERY_PATH_INFORMATION, params, nil, fs.ctx)
	if err != nil {
		return nil, mapSMBErrorToOSError(err, "stat", name)
	}

	// Decode basic info
	basicInfo, err := smb1.DecodeFileBasicInfo(trans2Resp.Data)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	// Second query: SMB_QUERY_FILE_STANDARD_INFO (for size and directory flag)
	params2, err := smb1.EncodeQueryPathInfo(name, smb1.SMB_QUERY_FILE_STANDARD_INFO, useUnicode)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	trans2Resp2, err := fs.tree.SendTransact2(smb1.TRANS2_QUERY_PATH_INFORMATION, params2, nil, fs.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: wrapError(err)}
	}

	standardInfo, err := smb1.DecodeFileStandardInfo(trans2Resp2.Data)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	// Extract filename from path
	filename := name
	if idx := strings.LastIndex(name, "\\"); idx != -1 {
		filename = name[idx+1:]
	}

	// Merge attributes if directory flag is present in standard info
	attrs := basicInfo.Attributes
	if standardInfo.Directory != 0 {
		attrs |= smb1.FILE_ATTRIBUTE_DIRECTORY
	}

	// Create FileStat
	fileStat := &FileStat{
		CreationTime:   convertFileTimeToTime(basicInfo.CreationTime),
		LastAccessTime: convertFileTimeToTime(basicInfo.LastAccessTime),
		LastWriteTime:  convertFileTimeToTime(basicInfo.LastWriteTime),
		ChangeTime:     convertFileTimeToTime(basicInfo.ChangeTime),
		EndOfFile:      int64(standardInfo.EndOfFile),
		AllocationSize: int64(standardInfo.AllocationSize),
		FileAttributes: attrs,
		FileName:       filename,
	}

	return fileStat, nil
}

// Lstat returns a FileInfo describing the named file.
// If the file is a symbolic link, the returned FileInfo
// describes the symbolic link. Lstat makes no attempt to follow the link.
// If there is an error, it will be of type *os.PathError.
//
// Note: SMB1 doesn't have separate lstat semantics, so this is the same as Stat.
func (fs *Share) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries sorted by filename.
func (fs *Share) ReadDir(dirname string) ([]os.FileInfo, error) {
	dirname = normalizePath(dirname)

	// Empty path means root directory - don't validate
	if dirname != "" {
		if err := validateFilePath(dirname); err != nil {
			return nil, &os.PathError{Op: "readdir", Path: dirname, Err: err}
		}
	}

	// Build search pattern (directory\* or \* for root)
	// Note: SMB requires backslash prefix for search patterns
	searchPattern := dirname
	if dirname == "" {
		searchPattern = "\\*"
	} else {
		if !strings.HasSuffix(searchPattern, "\\") {
			searchPattern += "\\"
		}
		searchPattern += "*"
	}

	// Create FIND_FIRST2 request
	// Use SMB_FIND_CLOSE_AT_EOS to ensure the server closes the search handle
	// when the search completes. This prevents search handles from being left open,
	// which would block directory deletion operations.
	findReq := &smb1.FindFirst2Request{
		SearchAttributes:  smb1.SMB_SEARCH_ATTRIBUTE_DIRECTORY | smb1.SMB_SEARCH_ATTRIBUTE_HIDDEN | smb1.SMB_SEARCH_ATTRIBUTE_SYSTEM,
		SearchCount:       findRequestBatchSize,                   // Request entries in batches for optimal performance
		Flags:             smb1.SMB_FIND_CLOSE_AT_EOS,             // Close automatically at end of search
		InformationLevel:  smb1.SMB_FIND_FILE_BOTH_DIRECTORY_INFO, // 0x0104
		SearchStorageType: 0,
		FileName:          searchPattern,
		UseUnicode:        (fs.tree.GetCapabilities() & smb1.CAP_UNICODE) != 0,
	}

	params, err := smb1.EncodeFindFirst2(findReq)
	if err != nil {
		return nil, &os.PathError{Op: "readdir", Path: dirname, Err: err}
	}

	logger := LoggerFromContext(fs.ctx)
	logger.Debug("FIND_FIRST2 params: %d bytes: %x", len(params), params)

	trans2Resp, err := fs.tree.SendTransact2(smb1.TRANS2_FIND_FIRST2, params, nil, fs.ctx)
	if err != nil {
		return nil, mapSMBErrorToOSError(err, "readdir", dirname)
	}

	findResp, err := smb1.DecodeFindFirst2Response(trans2Resp.Parameters, trans2Resp.Data, smb1.SMB_FIND_FILE_BOTH_DIRECTORY_INFO)
	if err != nil {
		return nil, &os.PathError{Op: "readdir", Path: dirname, Err: err}
	}

	var allFiles []smb1.FileBothDirectoryInfo
	allFiles = append(allFiles, findResp.Files...)

	// If there are more entries, use FIND_NEXT2 to get them
	sid := findResp.SID
	for findResp.EndOfSearch == 0 && findResp.SearchCount > 0 {
		// Check if context has been canceled
		select {
		case <-fs.ctx.Done():
			return nil, &os.PathError{Op: "readdir", Path: dirname, Err: wrapError(fs.ctx.Err())}
		default:
		}

		// Create FIND_NEXT2 request
		findNextReq := &smb1.FindNext2Request{
			SID:              sid,
			SearchCount:      findRequestBatchSize, // Request entries in batches for optimal performance
			InformationLevel: smb1.SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
			ResumeKey:        0,                                // Server will continue from last position
			Flags:            smb1.SMB_FIND_CONTINUE_FROM_LAST, // Continue, but don't auto-close
			FileName:         searchPattern,
			UseUnicode:       (fs.tree.GetCapabilities() & smb1.CAP_UNICODE) != 0,
		}

		params2, err := smb1.EncodeFindNext2(findNextReq)
		if err != nil {
			return nil, &os.PathError{Op: "readdir", Path: dirname, Err: err}
		}

		trans2Resp2, err := fs.tree.SendTransact2(smb1.TRANS2_FIND_NEXT2, params2, nil, fs.ctx)
		if err != nil {
			return nil, &os.PathError{Op: "readdir", Path: dirname, Err: wrapError(err)}
		}

		findNextResp, err := smb1.DecodeFindNext2Response(trans2Resp2.Parameters, trans2Resp2.Data, smb1.SMB_FIND_FILE_BOTH_DIRECTORY_INFO)
		if err != nil {
			return nil, &os.PathError{Op: "readdir", Path: dirname, Err: err}
		}

		allFiles = append(allFiles, findNextResp.Files...)
		findResp.EndOfSearch = findNextResp.EndOfSearch
		findResp.SearchCount = findNextResp.SearchCount
	}

	// Note: We don't explicitly close the search handle. The server will close it
	// automatically after a timeout. Implementing SMB_COM_FIND_CLOSE2 would require
	// adding a new command type beyond TRANS2, which is not currently supported.
	// For RemoveAll() operations, we rely on the server closing the search handle
	// before we attempt to delete the directory.

	// Convert to []os.FileInfo
	result := make([]os.FileInfo, 0, len(allFiles))
	for _, f := range allFiles {
		// Skip "." and ".." entries
		if f.FileName == "." || f.FileName == ".." {
			continue
		}

		fileStat := &FileStat{
			CreationTime:   convertFileTimeToTime(f.CreationTime),
			LastAccessTime: convertFileTimeToTime(f.LastAccessTime),
			LastWriteTime:  convertFileTimeToTime(f.LastWriteTime),
			ChangeTime:     convertFileTimeToTime(f.ChangeTime),
			EndOfFile:      int64(f.EndOfFile),
			AllocationSize: int64(f.AllocationSize),
			FileAttributes: f.FileAttributes,
			FileName:       f.FileName,
		}
		result = append(result, fileStat)
	}

	return result, nil
}

// Readdir reads the directory named by dirname and returns
// a list of up to n directory entries.
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
// Note: This implementation does not maintain state between calls.
// When n > 0, it reads all entries and returns the first n, then
// returns io.EOF on subsequent calls. For proper pagination with
// state tracking, use the standard library's fs.ReadDir or open
// the directory as a File and call File.Readdir.
func (fs *Share) Readdir(dirname string, n int) ([]os.FileInfo, error) {
	// For n <= 0, delegate to ReadDir which returns all entries
	if n <= 0 {
		return fs.ReadDir(dirname)
	}

	// For n > 0, read all entries and return first n
	// Note: This is not ideal for large directories, but matches the
	// stateless nature of this API. The proper way to paginate is to
	// open the directory as a File and call File.Readdir(n) which
	// can maintain state between calls.
	allEntries, err := fs.ReadDir(dirname)
	if err != nil {
		return nil, err
	}

	// If we have fewer entries than requested, return all with io.EOF
	if len(allEntries) <= n {
		if len(allEntries) == 0 {
			return nil, io.EOF
		}
		return allEntries, io.EOF
	}

	// Return first n entries
	return allEntries[:n], nil
}

// ReadFile reads the file named by filename and returns the contents.
// A successful call returns err == nil, not err == EOF.
// Because ReadFile reads the whole file, it does not treat an EOF from Read
// as an error to be reported.
//
// Stat only sizes the initial buffer. Read is an io.Reader and may legally
// return fewer bytes than requested without an error, so the loop below runs
// to EOF and grows the buffer rather than trusting either the stat size or a
// single Read to have delivered the whole file.
//
// Prefer Open plus io.CopyBuffer (or CopyTo) for large files: ReadFile holds
// the entire contents in memory.
func (fs *Share) ReadFile(filename string) ([]byte, error) {
	f, err := fs.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Size the buffer from Stat when it is available; a failure here costs a
	// few reallocations, not correctness, so it is not fatal.
	var size int
	if stat, statErr := f.Stat(); statErr == nil {
		if s := stat.Size(); s > 0 {
			// The size is server-supplied. Cap what it can pre-allocate: a
			// corrupt or hostile response claiming a gigantic file would
			// otherwise panic the process in make(), and int(s) would truncate
			// unpredictably on a 32-bit build. Genuinely large files still read
			// completely — the growth loop just reallocates a few more times,
			// and callers with files this size should be using Open plus
			// io.CopyBuffer anyway.
			if s > maxReadFileHint {
				s = maxReadFileHint
			}
			size = int(s)
		}
	}

	return readAll(f, size)
}

// maxReadFileHint bounds the buffer ReadFile pre-allocates from a server's
// reported file size. It is a hint, never a contract: capping it trades a few
// reallocations on large files for immunity to an absurd stat response.
const maxReadFileHint = 64 << 20 // 64 MiB

// readAll reads r to EOF, using sizeHint only to size the initial allocation.
// It tolerates short reads: an io.Reader may return fewer bytes than requested
// with a nil error, so the caller cannot infer EOF from a short read.
func readAll(r io.Reader, sizeHint int) ([]byte, error) {
	if sizeHint < 0 {
		sizeHint = 0
	}

	// One byte of slack lets the final Read observe EOF without growing again.
	data := make([]byte, 0, sizeHint+1)
	for {
		// Keep len < cap so Read never receives a zero-length buffer, which it
		// answers with (0, nil) — an infinite loop.
		if len(data) >= cap(data) {
			data = append(data, 0)[:len(data)]
		}

		n, err := r.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data, err
		}
	}
}

// WriteFile writes data to a file named by filename.
// If the file does not exist, WriteFile creates it with permissions perm
// (before umask); otherwise WriteFile truncates it before writing.
func (fs *Share) WriteFile(filename string, data []byte, perm os.FileMode) error {
	f, err := fs.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := f.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// Exists checks if a file or directory exists at the given path.
// It returns true if the file/directory exists, false if it does not exist.
// If there is an error other than "not found", it returns false and the error.
func (fs *Share) Exists(name string) (bool, error) {
	_, err := fs.Stat(name)
	if err == nil {
		return true, nil
	}
	if IsNotFoundError(err) {
		return false, nil
	}
	return false, err
}

// IsDir checks if the given path exists and is a directory.
// It returns true if the path exists and is a directory.
// If the path does not exist or is not a directory, it returns false.
// If there is an error checking the path, it returns false and the error.
func (fs *Share) IsDir(name string) (bool, error) {
	stat, err := fs.Stat(name)
	if err != nil {
		if IsNotFoundError(err) {
			return false, nil
		}
		return false, err
	}
	return stat.IsDir(), nil
}

// Walk walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root. All errors that arise visiting files
// and directories are filtered by walkFn.
//
// Walk follows the same semantics as filepath.Walk:
//   - The files are walked in lexical order
//   - Walk does not follow symbolic links
//   - If walkFn returns filepath.SkipDir when invoked on a directory,
//     Walk skips the directory's contents
//   - If walkFn returns any other non-nil error, Walk stops immediately
//
// Note: Unlike filepath.Walk, paths passed to walkFn use backslashes (\)
// as the separator, consistent with SMB conventions.
func (fs *Share) Walk(root string, walkFn filepath.WalkFunc) error {
	root = normalizePath(root)

	// Convert "." to "" because SMB doesn't support querying "."
	// Both represent the root of the share
	if root == "." {
		root = ""
	}

	// Get info about the root
	// For empty root (share root), we can't call Stat because it requires a path,
	// so we create a synthetic directory entry
	var info os.FileInfo
	var err error

	if root == "" {
		// Create a synthetic FileInfo for the root directory
		info = &FileStat{
			FileName:       "",
			FileAttributes: smb1.FILE_ATTRIBUTE_DIRECTORY,
			EndOfFile:      0,
		}
	} else {
		info, err = fs.Stat(root)
		if err != nil {
			err = walkFn(root, nil, err)
			if err == filepath.SkipDir {
				return nil
			}
			return err
		}
	}

	err = fs.walk(root, info, walkFn)
	if err == filepath.SkipDir {
		return nil
	}
	return err
}

// walk recursively walks the directory tree
func (fs *Share) walk(path string, info os.FileInfo, walkFn filepath.WalkFunc) error {
	err := walkFn(path, info, nil)
	if err != nil {
		if info.IsDir() && err == filepath.SkipDir {
			return nil
		}
		return err
	}

	if !info.IsDir() {
		return nil
	}

	// Read directory contents
	entries, err := fs.ReadDir(path)
	if err != nil {
		return walkFn(path, info, err)
	}

	// Walk each entry
	for _, entry := range entries {
		entryPath := path
		if path == "" {
			entryPath = entry.Name()
		} else {
			entryPath = path + "\\" + entry.Name()
		}

		err = fs.walk(entryPath, entry, walkFn)
		if err != nil {
			if !entry.IsDir() || err != filepath.SkipDir {
				return err
			}
		}
	}

	return nil
}

// Glob returns the names of all files matching pattern, or nil if there is
// no matching file. The pattern syntax is that of Match, and matches are
// returned in lexical order. Glob ignores file system errors such as
// directories that cannot be read; the only possible returned error is
// ErrBadPattern, when pattern is malformed.
//
// Unlike filepath.Glob, results use '\' as the separator, and patterns are
// relative to the share root (a leading '\' matches nothing, since this
// library rejects absolute paths).
func (fs *Share) Glob(pattern string) (matches []string, err error) {
	return globWith(fs, pattern)
}

// globLister is the subset of Share that the glob traversal reads through,
// split out so the traversal can be tested against an in-memory tree.
type globLister interface {
	Lstat(name string) (os.FileInfo, error)
	Stat(name string) (os.FileInfo, error)
	ReadDir(dirname string) ([]os.FileInfo, error)
}

// globWith implements Glob over any globLister.
func globWith(fs globLister, pattern string) (matches []string, err error) {
	pattern = normPattern(pattern)

	// Reject a malformed pattern up front, so it is reported even when
	// nothing on the share could have reached the bad chunk.
	if _, err := Match(pattern, ""); err != nil {
		return nil, err
	}

	if !hasGlobMeta(pattern) {
		// No wildcards: the pattern is a literal path, present or not.
		if _, err := fs.Lstat(pattern); err != nil {
			return nil, nil
		}
		return []string{pattern}, nil
	}

	dir, file := splitLastSep(pattern)
	dir = cleanGlobDir(dir)

	if !hasGlobMeta(dir) {
		return globDir(fs, dir, file, nil)
	}

	// The directory part itself contains wildcards; expand it first. A fixed
	// point (dir == pattern) could never terminate, so treat it as malformed.
	if dir == pattern {
		return nil, ErrBadPattern
	}

	dirs, err := globWith(fs, dir)
	if err != nil {
		return nil, err
	}
	for _, d := range dirs {
		matches, err = globDir(fs, d, file, matches)
		if err != nil {
			return matches, err
		}
	}
	return matches, nil
}

// globDir appends the entries of dir whose names match pattern, in lexical
// order. Directories that do not exist, are not directories, or cannot be
// read contribute nothing rather than an error: a glob describes what
// exists.
func globDir(fs globLister, dir, pattern string, matches []string) ([]string, error) {
	if dir == "." {
		// "." denotes the share root, which Stat cannot address; ReadDir
		// spells it "".
		dir = ""
	} else {
		fi, err := fs.Stat(dir)
		if err != nil || !fi.IsDir() {
			return matches, nil
		}
	}

	entries, err := fs.ReadDir(dir)
	if err != nil {
		return matches, nil
	}

	for _, entry := range entries {
		ok, err := Match(pattern, entry.Name())
		if err != nil {
			return matches, err
		}
		if ok {
			matches = append(matches, joinGlob(dir, entry.Name()))
		}
	}
	sort.Strings(matches)
	return matches, nil
}

// splitLastSep splits pattern after the last path separator, leaving the
// separator on the directory part.
func splitLastSep(pattern string) (dir, file string) {
	i := strings.LastIndexByte(pattern, '\\')
	return pattern[:i+1], pattern[i+1:]
}

// cleanGlobDir converts the directory part of a pattern (which still carries
// its trailing separator) into a path the traversal can look up. An empty
// directory part means the share root, spelled "." so a root pattern stays
// distinguishable from an empty one.
func cleanGlobDir(dir string) string {
	switch dir {
	case "":
		return "."
	case string(PathSeparator):
		return dir
	default:
		return dir[:len(dir)-1] // chop the trailing separator
	}
}

// joinGlob joins a directory produced by the glob traversal with an entry
// name. The root is spelled "" by then, keeping matches relative just as the
// pattern addressed them.
func joinGlob(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + string(PathSeparator) + name
}

// CopyFile copies a file within the share from src to dst.
// If dst already exists, it will be overwritten.
// The file contents are copied by reading from src and writing to dst.
// Both paths must be relative paths within the share.
func (fs *Share) CopyFile(src, dst string) error {
	// Open source file for reading
	srcFile, err := fs.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Get source file info for permissions
	srcInfo, err := fs.Stat(src)
	if err != nil {
		return err
	}

	// Check if source is a directory
	if srcInfo.IsDir() {
		return &os.PathError{Op: "copy", Path: src, Err: os.ErrInvalid}
	}

	// Create destination file
	dstFile, err := fs.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode().Perm())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy contents
	_, err = io.Copy(dstFile, srcFile)
	return err
}

// CopyFrom uploads a file from the local filesystem to the share.
// The localPath is a path on the local filesystem, and remotePath is
// a relative path within the share. If remotePath already exists, it
// will be overwritten.
func (fs *Share) CopyFrom(localPath, remotePath string) error {
	// Open local file for reading
	localFile, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer localFile.Close()

	// Get local file info for permissions
	localInfo, err := localFile.Stat()
	if err != nil {
		return err
	}

	// Check if source is a directory
	if localInfo.IsDir() {
		return &os.PathError{Op: "copy", Path: localPath, Err: os.ErrInvalid}
	}

	// Create remote file
	remoteFile, err := fs.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, localInfo.Mode().Perm())
	if err != nil {
		return err
	}
	defer remoteFile.Close()

	// Copy contents
	_, err = io.Copy(remoteFile, localFile)
	return err
}

// CopyTo downloads a file from the share to the local filesystem.
// The remotePath is a relative path within the share, and localPath is
// a path on the local filesystem. If localPath already exists, it will
// be overwritten.
func (fs *Share) CopyTo(remotePath, localPath string) error {
	// Open remote file for reading
	remoteFile, err := fs.Open(remotePath)
	if err != nil {
		return err
	}
	defer remoteFile.Close()

	// Get remote file info for permissions
	remoteInfo, err := fs.Stat(remotePath)
	if err != nil {
		return err
	}

	// Check if source is a directory
	if remoteInfo.IsDir() {
		return &os.PathError{Op: "copy", Path: remotePath, Err: os.ErrInvalid}
	}

	// Create local file
	localFile, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, remoteInfo.Mode().Perm())
	if err != nil {
		return err
	}
	defer localFile.Close()

	// Copy contents
	_, err = io.Copy(localFile, remoteFile)
	return err
}

// validateFilePath validates that the path is safe for SMB operations.
// It protects against directory traversal attacks by:
// 1. Rejecting null bytes and absolute paths
// 2. Normalizing path components and tracking depth
// 3. Detecting attempts to escape the root using ".."
//
// The validation works by splitting the path into components and tracking
// the depth as we process each component. Any ".." component decreases depth,
// while non-empty components increase it. If depth ever goes negative, the path
// attempts to traverse above the root and is rejected.
func validateFilePath(path string) error {
	if path == "" {
		return &InternalError{"empty path"}
	}

	// Reject absolute paths (paths starting with backslash)
	if strings.HasPrefix(path, "\\") {
		return &InternalError{"absolute paths not allowed (use relative paths)"}
	}

	// Reject null bytes immediately - these can be used to bypass validation
	// by terminating strings early in C-based systems
	if strings.Contains(path, "\x00") {
		return &InternalError{"path contains null bytes"}
	}

	// Reject forward slashes - these should have been normalized by normalizePath
	// before validation. If they're still present, something is wrong.
	if strings.Contains(path, "/") {
		return &InternalError{"path contains forward slashes (must be normalized first)"}
	}

	// Split path by backslash and validate each component
	// We track depth to detect ".." sequences that would escape the root
	components := strings.Split(path, "\\")
	depth := 0

	for _, component := range components {
		// Skip empty components (from double slashes like "a\\\\b")
		if component == "" {
			continue
		}

		// Skip current directory references
		if component == "." {
			continue
		}

		// Handle parent directory references
		if component == ".." {
			depth--
			// If depth goes negative, we're trying to escape the root
			if depth < 0 {
				return &InternalError{"path attempts to traverse above root directory"}
			}
			continue
		}

		// Regular component - increase depth
		depth++
	}

	// Additional safety check: reject paths that end at a negative depth
	// This should be caught above, but defense in depth
	if depth < 0 {
		return &InternalError{"path attempts to traverse above root directory"}
	}

	return nil
}

// PathSeparator is the path separator used in SMB paths.
const PathSeparator = '\\'

// IsPathSeparator reports whether c is the SMB path separator.
func IsPathSeparator(c uint8) bool {
	return c == PathSeparator
}

// NORMALIZE_PATH controls whether '/' in user-supplied paths and patterns is
// converted to the SMB separator '\' before use. It is enabled by default;
// when disabled, paths containing '/' are rejected by validation instead of
// being rewritten. The variable mirrors go-smb2's of the same name for
// source compatibility.
var NORMALIZE_PATH = true

// normalizePath converts forward slashes to backslashes and trims whitespace.
// This function is called for every file operation (hot path), so it's optimized
// to avoid allocations when no changes are needed.
//
// Note: We use strings.TrimSpace (Unicode-aware) rather than ASCII-only trimming
// because Windows filenames can contain Unicode characters, including Unicode
// whitespace like non-breaking space (U+00A0). While rare in practice, we prefer
// correctness over micro-optimization here.
func normalizePath(path string) string {
	// Trim Unicode whitespace
	trimmed := strings.TrimSpace(path)

	// With normalization disabled, forward slashes are left in place for
	// validateFilePath to reject, mirroring go-smb2's NORMALIZE_PATH=false
	// mode. Whitespace trimming is separator-independent and still applies.
	if !NORMALIZE_PATH {
		return trimmed
	}

	// Fast path: no trimming needed and no slashes to replace
	if trimmed == path && !strings.Contains(path, "/") {
		return path // Zero allocations
	}

	// If no slashes to replace, return trimmed result
	// strings.TrimSpace returns a slice of the original when possible (low/no allocation)
	if !strings.Contains(trimmed, "/") {
		return trimmed
	}

	// Replace slashes (this allocates a new string)
	return strings.ReplaceAll(trimmed, "/", "\\")
}

// validateMountPath validates that the path is a proper UNC path.
// UNC paths must be in format: \\server\share
func validateMountPath(path string) error {
	if !strings.HasPrefix(path, `\\`) {
		return &InternalError{fmt.Sprintf("invalid UNC path: %s (must start with \\\\)", path)}
	}

	// Remove leading \\
	path = path[2:]

	// Split into server and share
	parts := strings.SplitN(path, `\`, 2)
	if len(parts) != 2 {
		return &InternalError{"invalid UNC path: missing share name (format: \\\\server\\share)"}
	}

	server := parts[0]
	share := parts[1]

	if server == "" {
		return &InternalError{"invalid UNC path: empty server name"}
	}

	if share == "" {
		return &InternalError{"invalid UNC path: empty share name"}
	}

	// Share name shouldn't contain additional backslashes
	if strings.Contains(share, `\`) {
		return &InternalError{"invalid UNC path: share name contains backslash (format: \\\\server\\share)"}
	}

	return nil
}
