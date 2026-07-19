package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/macourteau/smb1client/internal/erref"
	"github.com/macourteau/smb1client/internal/logging"
	"github.com/macourteau/smb1client/internal/smb1"
)

// SMBProtocolOverhead is the estimated space needed for SMB protocol headers,
// parameters, and padding when calculating maximum data transfer sizes.
//
// Breakdown:
//   - NetBIOS session header: 4 bytes
//   - SMB header: 32 bytes
//   - WRITE_ANDX/READ_ANDX parameter block: ~27 bytes
//   - Data offset alignment/padding: ~16 bytes
//   - Safety margin for extensions: ~945 bytes
//
// Total: 1024 bytes
//
// This constant is used to calculate the maximum payload size that fits
// within the negotiated MaxBufferSize, ensuring protocol messages don't
// exceed the server's buffer limits.
const SMBProtocolOverhead = 1024

// File represents an open file on the SMB share.
type File struct {
	session *Session   // parent session
	tid     uint16     // tree ID
	fid     uint16     // file ID
	name    string     // file path
	offset  int64      // current read/write position
	mu      sync.Mutex // protects offset
}

// readChunk represents a chunk of data to be read in a pipelined read operation
type readChunk struct {
	offset    int64
	size      int
	bufOffset int
	mid       uint16
	respCh    chan *response
}

// writeChunk represents a chunk of data to be written in a pipelined write operation
type writeChunk struct {
	offset int64
	data   []byte
	mid    uint16
	respCh chan *response
}

// FileStat represents file metadata returned by File.Stat().
type FileStat struct {
	CreationTime   uint64 // FILETIME format
	LastAccessTime uint64 // FILETIME format
	LastWriteTime  uint64 // FILETIME format
	ChangeTime     uint64 // FILETIME format
	EndOfFile      int64  // File size
	AllocationSize int64  // Allocated size on disk
	FileAttributes uint32 // SMB file attributes
	FileName       string // File name
}

// OpenFile opens or creates a file on the share.
// The access, shareAccess, disposition, and createOptions parameters follow NT semantics.
// Returns a file handle that can be used for read/write operations.
func (t *Tree) OpenFile(name string, access, shareAccess, disposition, createOptions uint32, ctx context.Context) (*File, error) {
	logger := logging.FromContext(ctx)
	logger.Debug("OpenFile: opening file %s", name)

	// Determine if we should use Unicode
	useUnicode := (t.Session.conn.capabilities & smb1.CAP_UNICODE) != 0

	// Calculate name length in bytes
	var nameLength uint16
	if useUnicode {
		// Unicode: each character is 2 bytes in UTF-16LE
		nameLength = uint16(len(name) * 2)
	} else {
		// ASCII: one byte per character
		nameLength = uint16(len(name))
	}

	// Create NT_CREATE_ANDX request
	req := &smb1.NTCreateRequest{
		AndXCommand:        smb1.SMB_COM_NO_ANDX_COMMAND,
		NameLength:         nameLength,
		Flags:              0,
		RootDirectoryFID:   0,
		DesiredAccess:      access,
		AllocationSize:     0,
		FileAttributes:     smb1.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:        shareAccess,
		CreateDisposition:  disposition,
		CreateOptions:      createOptions,
		ImpersonationLevel: smb1.SECURITY_IMPERSONATION,
		SecurityFlags:      0,
		FileName:           name,
		UseUnicode:         useUnicode,
	}

	params, data, err := smb1.EncodeNTCreateRequest(req)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode nt create request: %w", err)
	}

	header := smb1.NewHeader(smb1.SMB_COM_NT_CREATE_ANDX)
	header.UID = t.Session.uid
	header.TID = t.TID

	resp, err := t.Session.conn.sendRecv(header, params, data, ctx)
	if err != nil {
		return nil, fmt.Errorf("smb1: nt create failed: %w", err)
	}

	if resp.err != nil {
		return nil, fmt.Errorf("smb1: nt create returned error: %w", resp.err)
	}

	// Decode NT_CREATE_ANDX response
	createResp, err := smb1.DecodeNTCreateResponse(resp.params, resp.data)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to decode nt create response: %w", err)
	}

	// Create file struct
	f := &File{
		session: t.Session,
		tid:     t.TID,
		fid:     createResp.FID,
		name:    name,
		offset:  0,
	}

	return f, nil
}

// Close closes the file.
func (f *File) Close(ctx context.Context) error {
	// Create CLOSE request
	req := &smb1.CloseRequest{
		FID:           f.fid,
		LastWriteTime: 0, // Don't update timestamp
	}

	params, data, err := smb1.EncodeCloseRequest(req)
	if err != nil {
		return fmt.Errorf("smb1: failed to encode close request: %w", err)
	}

	header := smb1.NewHeader(smb1.SMB_COM_CLOSE)
	header.UID = f.session.uid
	header.TID = f.tid

	resp, err := f.session.conn.sendRecv(header, params, data, ctx)
	if err != nil {
		return fmt.Errorf("smb1: close failed: %w", err)
	}

	if resp.err != nil {
		return fmt.Errorf("smb1: close returned error: %w", resp.err)
	}

	return nil
}

// Read reads data from the file at the current offset.
// It advances the file offset by the number of bytes read.
// For buffers larger than maxDataPerRead, it automatically chunks the read operation.
// This method uses request pipelining for improved performance on large reads.
func (f *File) Read(buf []byte, ctx context.Context) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	f.mu.Lock()
	offset := f.offset
	f.mu.Unlock()

	const pipelineThreshold = 128 * 1024
	var totalRead int
	var err error

	logger := logging.FromContext(ctx)

	// Check if server supports pipelining
	maxMpxCount := int(f.session.conn.maxMpxCount)
	supportsPipelining := maxMpxCount > 1

	// Calculate maxDataPerRead for log message
	supportsLargeReadX := (f.session.conn.capabilities & smb1.CAP_LARGE_READX) != 0
	maxDataPerRead := 65520
	if supportsLargeReadX {
		maxDataPerRead = 130048
	}

	if !supportsPipelining || len(buf) < pipelineThreshold {
		logger.Debug("File.Read: using sequential read for %d bytes", len(buf))
		totalRead, err = f.readSequential(buf, offset, ctx)
	} else {
		numChunks := (len(buf) + maxDataPerRead - 1) / maxDataPerRead
		logger.Debug("File.Read: using PIPELINED read for %d bytes (%d chunks, %d bytes/chunk)", len(buf), numChunks, maxDataPerRead)
		totalRead, err = f.readPipelined(buf, offset, ctx)
	}

	// Update offset
	f.mu.Lock()
	f.offset += int64(totalRead)
	f.mu.Unlock()

	return totalRead, err
}

// readSequential performs a sequential read using ReadAt
func (f *File) readSequential(buf []byte, offset int64, ctx context.Context) (int, error) {
	// Calculate maximum read size based on negotiated buffer size and CAP_LARGE_READX
	supportsLargeReadX := (f.session.conn.capabilities & smb1.CAP_LARGE_READX) != 0
	maxDataPerRead := 65520 // Default: 64KB
	if supportsLargeReadX {
		maxDataPerRead = 130048 // 127KB when CAP_LARGE_READX available
	}

	// Respect maxBufferSize if it's smaller
	if f.session.conn.maxBufferSize > 0 {
		calculatedMax := int(f.session.conn.maxBufferSize) - SMBProtocolOverhead
		if calculatedMax > 0 && calculatedMax < maxDataPerRead {
			maxDataPerRead = calculatedMax
		}
	}

	totalRead := 0

	for totalRead < len(buf) {
		remaining := len(buf) - totalRead
		chunkSize := remaining
		if chunkSize > maxDataPerRead {
			chunkSize = maxDataPerRead
		}

		n, err := f.ReadAt(buf[totalRead:totalRead+chunkSize], offset+int64(totalRead), ctx)
		totalRead += n

		if err != nil {
			// ReadAt reports end of file as io.EOF. Per the io.Reader
			// contract, deliver any data read with a nil error; the next
			// call reports EOF.
			if err == io.EOF && totalRead > 0 {
				return totalRead, nil
			}
			return totalRead, err
		}
	}

	return totalRead, nil
}

// readPipelined performs a pipelined read for improved performance
func (f *File) readPipelined(buf []byte, offset int64, ctx context.Context) (int, error) {
	logger := logging.FromContext(ctx)

	// Ensure cancelled requests are cleaned up when function exits
	defer f.session.conn.cleanupCancelledRequests()

	// Calculate maximum read size based on CAP_LARGE_READX capability
	supportsLargeReadX := (f.session.conn.capabilities & smb1.CAP_LARGE_READX) != 0
	maxDataPerRead := 65520 // Default: 64KB
	if supportsLargeReadX {
		maxDataPerRead = 130048 // 127KB when CAP_LARGE_READX available
	}

	// Calculate number of chunks needed
	totalSize := len(buf)
	numChunks := (totalSize + maxDataPerRead - 1) / maxDataPerRead

	// Determine pipeline depth based on server's MaxMpxCount
	maxPipeline := int(f.session.conn.maxMpxCount)
	if maxPipeline == 0 {
		// Server didn't specify, use safe default
		maxPipeline = 30
	} else if maxPipeline > 50 {
		// Cap at 50 for safety with servers advertising very high values
		maxPipeline = 50
	}
	// Otherwise use the server's advertised MaxMpxCount

	// Don't pipeline more than the number of chunks
	if maxPipeline > numChunks {
		maxPipeline = numChunks
	}

	logger.Debug("readPipelined: %d bytes in %d chunks, pipeline depth %d", totalSize, numChunks, maxPipeline)

	// Create chunks for tracking pipelined reads
	chunks := make([]*readChunk, numChunks)
	for i := 0; i < numChunks; i++ {
		chunkOffset := i * maxDataPerRead
		chunkSize := maxDataPerRead
		if chunkOffset+chunkSize > totalSize {
			chunkSize = totalSize - chunkOffset
		}

		chunks[i] = &readChunk{
			offset:    offset + int64(chunkOffset),
			size:      chunkSize,
			bufOffset: chunkOffset,
			respCh:    make(chan *response, 1),
		}
	}

	// Send initial batch of pipelined requests
	var sendErr error
	sent := 0
	for i := 0; i < maxPipeline && i < numChunks; i++ {
		if err := f.sendReadRequest(chunks[i], ctx); err != nil {
			sendErr = err
			break
		}
		sent++
	}

	if sendErr != nil {
		// Mark any successfully allocated MIDs as cancelled
		f.session.conn.mu.Lock()
		for i := 0; i < sent; i++ {
			if req, ok := f.session.conn.pending[chunks[i].mid]; ok {
				req.cancelled = true
			}
		}
		f.session.conn.mu.Unlock()
		return 0, sendErr
	}

	// Process responses and send remaining requests
	totalRead := 0
	nextToSend := maxPipeline

	// Helper function to mark pending requests as cancelled.
	// The Receive() goroutine will check this flag and skip sending responses.
	// Cleanup (deletion from pending map) happens when responses arrive or on connection close.
	cleanupPending := func(startFrom int, endAt int) {
		f.session.conn.mu.Lock()
		for j := startFrom; j < endAt; j++ {
			if req, ok := f.session.conn.pending[chunks[j].mid]; ok {
				req.cancelled = true
			}
		}
		f.session.conn.mu.Unlock()
	}

	for i := 0; i < numChunks; i++ {
		// Only process chunks that were actually sent
		// Chunks 0..sent-1 were sent in initial batch
		// Chunks sent..nextToSend-1 were sent as responses came in
		if i >= nextToSend {
			// This chunk was never sent, skip remaining chunks
			break
		}

		chunk := chunks[i]

		// Wait for this chunk's response
		var resp *response
		select {
		case resp = <-chunk.respCh:
			// Cleanup this MID
			f.session.conn.mu.Lock()
			delete(f.session.conn.pending, chunk.mid)
			f.session.conn.mu.Unlock()
		case <-ctx.Done():
			// Mark current chunk and all pending requests as cancelled
			f.session.conn.mu.Lock()
			if req, ok := f.session.conn.pending[chunk.mid]; ok {
				req.cancelled = true
			}
			f.session.conn.mu.Unlock()
			cleanupPending(i+1, nextToSend)
			return totalRead, ctx.Err()
		case <-f.session.conn.done:
			// Connection closed - setError() or Close() will clean up all pending MIDs
			// including the current chunk, so no explicit cleanup needed here
			return totalRead, f.session.conn.err
		}

		// Handle response error
		if resp.err != nil {
			if resp.header != nil && resp.header.Status == smb1.STATUS_END_OF_FILE {
				// EOF reached - clean up remaining pending requests
				cleanupPending(i+1, nextToSend)
				if totalRead > 0 {
					return totalRead, nil
				}
				return 0, io.EOF
			}
			// Clean up remaining pending requests
			cleanupPending(i+1, nextToSend)
			return totalRead, fmt.Errorf("smb1: read failed: %w", resp.err)
		}

		// Decode response
		readResp, err := smb1.DecodeReadResponse(resp.params, resp.data)
		if err != nil {
			// Clean up remaining pending requests
			cleanupPending(i+1, nextToSend)
			return totalRead, fmt.Errorf("smb1: failed to decode read response: %w", err)
		}

		// Copy data to buffer at correct offset
		n := copy(buf[chunk.bufOffset:chunk.bufOffset+chunk.size], readResp.Data)
		totalRead += n

		// If we got less than requested, we've reached EOF
		if n < chunk.size {
			// Clean up remaining pending requests
			cleanupPending(i+1, nextToSend)
			if totalRead > 0 {
				// Per io.Reader contract: return data with nil error,
				// next Read() will return (0, io.EOF)
				return totalRead, nil
			}
			return 0, io.EOF
		}

		// Send next request if any remain
		if nextToSend < numChunks {
			if err := f.sendReadRequest(chunks[nextToSend], ctx); err != nil {
				// Clean up remaining pending requests (including the one we just failed to send)
				cleanupPending(i+1, nextToSend)
				return totalRead, err
			}
			nextToSend++
		}
	}

	return totalRead, nil
}

// sendReadRequest sends a single pipelined read request
func (f *File) sendReadRequest(chunk *readChunk, ctx context.Context) error {
	logger := logging.FromContext(ctx)

	// Create READ_ANDX request
	req := &smb1.ReadRequest{
		AndXCommand:             smb1.SMB_COM_NO_ANDX_COMMAND,
		FID:                     f.fid,
		Offset:                  uint64(chunk.offset),
		MaxCountOfBytesToReturn: uint16(chunk.size & 0xFFFF), // Low 16 bits
		MinCountOfBytesToReturn: 0,
		MaxCountHigh:            uint16((chunk.size >> 16) & 0xFFFF), // High 16 bits
		Timeout:                 0,
		Remaining:               0,
	}

	supportsLargeFiles := (f.session.conn.capabilities & smb1.CAP_LARGE_FILES) != 0
	supportsLargeReadX := (f.session.conn.capabilities & smb1.CAP_LARGE_READX) != 0
	params, data, err := smb1.EncodeReadRequest(req, supportsLargeFiles, supportsLargeReadX)
	if err != nil {
		return fmt.Errorf("smb1: failed to encode read request: %w", err)
	}

	// Send request without waiting (pipelined)
	header := smb1.NewHeader(smb1.SMB_COM_READ_ANDX)
	header.UID = f.session.uid
	header.TID = f.tid

	// Allocate MID and register response channel
	f.session.conn.mu.Lock()

	// Check if connection is closed
	select {
	case <-f.session.conn.done:
		f.session.conn.mu.Unlock()
		return f.session.conn.err
	default:
	}

	mid, err := f.session.conn.allocateMID()
	if err != nil {
		f.session.conn.mu.Unlock()
		return err
	}

	header.MID = mid
	chunk.mid = mid
	f.session.conn.pending[mid] = &pendingRequest{respCh: chunk.respCh, cancelled: false}
	f.session.conn.mu.Unlock()

	logger.Debug("sendReadRequest: MID %d, offset %d, size %d", mid, chunk.offset, chunk.size)

	// Encode and send packet
	packet, err := smb1.EncodePacket(header, params, data)
	if err != nil {
		// Cleanup on error
		f.session.conn.mu.Lock()
		delete(f.session.conn.pending, mid)
		f.session.conn.mu.Unlock()
		return fmt.Errorf("smb1: failed to encode packet: %w", err)
	}

	if err := f.session.conn.netbiosConn.WritePacketContext(ctx, packet); err != nil {
		// Cleanup on error
		f.session.conn.mu.Lock()
		delete(f.session.conn.pending, mid)
		f.session.conn.mu.Unlock()
		f.session.conn.setError(fmt.Errorf("smb1: failed to send packet: %w", err))
		return err
	}

	return nil
}

// ReadAt reads data from the file at the specified offset.
// It does not change the file offset.
// Following io.ReaderAt, ReadAt returns a non-nil error whenever it reads
// fewer than len(buf) bytes: a short read only happens at end of file and
// carries io.EOF, and reading at or past end of file returns 0, io.EOF.
func (f *File) ReadAt(buf []byte, offset int64, ctx context.Context) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	var n int
	for n < len(buf) {
		m, err := f.readAtChunk(buf[n:], offset+int64(n), ctx)
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// readAtChunk issues a single READ_ANDX for up to maxDataPerRead bytes at the
// given offset. A response shorter than the request is reported as io.EOF:
// requests never exceed what the server negotiated, so a short response only
// happens at end of file.
func (f *File) readAtChunk(buf []byte, offset int64, ctx context.Context) (int, error) {
	logger := logging.FromContext(ctx)

	// Calculate maximum read size per operation
	// SMB1 READ_ANDX supports large reads via CAP_LARGE_READX capability extension.
	// Without CAP_LARGE_READX: MaxCountOfBytesToReturn uint16 limits to 65535 bytes (use 65520 for alignment)
	// With CAP_LARGE_READX: MaxCountHigh + MaxCountOfBytesToReturn allows up to 127KB (NetBIOS limit)
	supportsLargeReadX := (f.session.conn.capabilities & smb1.CAP_LARGE_READX) != 0
	maxDataPerRead := 65520 // Default: 64KB
	if supportsLargeReadX {
		maxDataPerRead = 130048 // 127KB when CAP_LARGE_READX available (same as writes)
	}

	readSize := len(buf)
	if readSize > maxDataPerRead {
		readSize = maxDataPerRead
	}

	logger.Debug("readAtChunk: reading %d bytes from %s at offset %d (CAP_LARGE_READX=%v)", readSize, f.name, offset, supportsLargeReadX)

	// Create READ_ANDX request
	req := &smb1.ReadRequest{
		AndXCommand:             smb1.SMB_COM_NO_ANDX_COMMAND,
		FID:                     f.fid,
		Offset:                  uint64(offset),
		MaxCountOfBytesToReturn: uint16(readSize & 0xFFFF), // Low 16 bits
		MinCountOfBytesToReturn: 0,
		MaxCountHigh:            uint16((readSize >> 16) & 0xFFFF), // High 16 bits
		Timeout:                 0,
		Remaining:               0,
	}

	supportsLargeFiles := (f.session.conn.capabilities & smb1.CAP_LARGE_FILES) != 0
	params, data, err := smb1.EncodeReadRequest(req, supportsLargeFiles, supportsLargeReadX)
	if err != nil {
		return 0, fmt.Errorf("smb1: failed to encode read request: %w", err)
	}

	header := smb1.NewHeader(smb1.SMB_COM_READ_ANDX)
	header.UID = f.session.uid
	header.TID = f.tid

	resp, err := f.session.conn.sendRecv(header, params, data, ctx)
	if err != nil {
		// If we got a response, check for EOF status
		if resp != nil && resp.header.Status == smb1.STATUS_END_OF_FILE {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("smb1: read failed: %w", err)
	}

	if resp.err != nil {
		return 0, fmt.Errorf("smb1: read returned error: %w", resp.err)
	}

	// Decode READ_ANDX response
	readResp, err := smb1.DecodeReadResponse(resp.params, resp.data)
	if err != nil {
		return 0, fmt.Errorf("smb1: failed to decode read response: %w", err)
	}

	// Copy data to buffer
	n := copy(buf, readResp.Data)

	if n < readSize {
		return n, io.EOF
	}

	return n, nil
}

// Write writes data to the file at the current offset.
// It advances the file offset by the number of bytes written.
// For data larger than maxBufferSize, it automatically chunks the write operation.
// Returns io.ErrShortWrite if not all bytes could be written.
func (f *File) Write(data []byte, ctx context.Context) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	f.mu.Lock()
	offset := f.offset
	f.mu.Unlock()

	// For small writes (< 256KB), use sequential WriteAt for simplicity
	// For larger writes, use pipelining for better performance
	const pipelineThreshold = 256 * 1024
	var totalWritten int
	var err error

	logger := logging.FromContext(ctx)

	// Check if server supports pipelining
	maxMpxCount := int(f.session.conn.maxMpxCount)
	supportsPipelining := maxMpxCount > 1

	if !supportsPipelining || len(data) < pipelineThreshold {
		logger.Debug("File.Write: using sequential write for %d bytes", len(data))
		totalWritten, err = f.writeSequential(data, offset, ctx)
	} else {
		logger.Debug("File.Write: using PIPELINED write for %d bytes (%d chunks)", len(data), (len(data)+65519)/65520)
		totalWritten, err = f.writePipelined(data, offset, ctx)
	}

	// Update offset
	f.mu.Lock()
	f.offset += int64(totalWritten)
	f.mu.Unlock()

	return totalWritten, err
}

// writeSequential performs a sequential write using WriteAt
func (f *File) writeSequential(data []byte, offset int64, ctx context.Context) (int, error) {
	// Calculate maximum write size based on negotiated buffer size
	// Fall back to 130048 (127KB) if maxBufferSize is not set
	maxDataPerWrite := 130048
	if f.session.conn.maxBufferSize > 0 {
		calculatedMax := int(f.session.conn.maxBufferSize) - SMBProtocolOverhead
		if calculatedMax > 0 && calculatedMax < maxDataPerWrite {
			maxDataPerWrite = calculatedMax
		}
	}

	totalWritten := 0

	for totalWritten < len(data) {
		remaining := len(data) - totalWritten
		chunkSize := remaining
		if chunkSize > maxDataPerWrite {
			chunkSize = maxDataPerWrite
		}

		n, err := f.WriteAt(data[totalWritten:totalWritten+chunkSize], offset+int64(totalWritten), ctx)
		totalWritten += n

		if err != nil {
			return totalWritten, err
		}

		// If we wrote less than requested, return error
		if n < chunkSize {
			return totalWritten, io.ErrShortWrite
		}
	}

	return totalWritten, nil
}

// writePipelined performs a pipelined write for improved performance
func (f *File) writePipelined(data []byte, offset int64, ctx context.Context) (int, error) {
	logger := logging.FromContext(ctx)

	// Ensure cancelled requests are cleaned up when function exits
	defer f.session.conn.cleanupCancelledRequests()

	const maxDataPerWrite = 130048 // 127KB

	// Calculate number of chunks needed
	totalSize := len(data)
	numChunks := (totalSize + maxDataPerWrite - 1) / maxDataPerWrite

	// Determine pipeline depth based on server's MaxMpxCount
	maxPipeline := int(f.session.conn.maxMpxCount)
	if maxPipeline == 0 {
		// Server didn't specify, use safe default
		maxPipeline = 30
	} else if maxPipeline > 50 {
		// Cap at 50 for safety with servers advertising very high values
		maxPipeline = 50
	}
	// Otherwise use the server's advertised MaxMpxCount

	// Don't pipeline more than the number of chunks
	if maxPipeline > numChunks {
		maxPipeline = numChunks
	}

	logger.Debug("writePipelined: %d bytes in %d chunks, pipeline depth %d", totalSize, numChunks, maxPipeline)

	// Create chunks for tracking pipelined writes
	chunks := make([]*writeChunk, numChunks)
	for i := 0; i < numChunks; i++ {
		chunkOffset := i * maxDataPerWrite
		chunkSize := maxDataPerWrite
		if chunkOffset+chunkSize > totalSize {
			chunkSize = totalSize - chunkOffset
		}

		chunks[i] = &writeChunk{
			offset: offset + int64(chunkOffset),
			data:   data[chunkOffset : chunkOffset+chunkSize],
			respCh: make(chan *response, 1),
		}
	}

	// Send initial batch of pipelined requests
	var sendErr error
	sent := 0
	for i := 0; i < maxPipeline && i < numChunks; i++ {
		if err := f.sendWriteRequest(chunks[i], ctx); err != nil {
			sendErr = err
			break
		}
		sent++
	}

	if sendErr != nil {
		// Mark any successfully allocated MIDs as cancelled
		f.session.conn.mu.Lock()
		for i := 0; i < sent; i++ {
			if req, ok := f.session.conn.pending[chunks[i].mid]; ok {
				req.cancelled = true
			}
		}
		f.session.conn.mu.Unlock()
		return 0, sendErr
	}

	// Process responses and send remaining requests
	totalWritten := 0
	nextToSend := maxPipeline

	// Helper function to mark pending requests as cancelled.
	// The Receive() goroutine will check this flag and skip sending responses.
	// Cleanup (deletion from pending map) happens when responses arrive or on connection close.
	cleanupPending := func(startFrom int, endAt int) {
		f.session.conn.mu.Lock()
		for j := startFrom; j < endAt; j++ {
			if req, ok := f.session.conn.pending[chunks[j].mid]; ok {
				req.cancelled = true
			}
		}
		f.session.conn.mu.Unlock()
	}

	for i := 0; i < numChunks; i++ {
		// Only process chunks that were actually sent
		// Chunks 0..sent-1 were sent in initial batch
		// Chunks sent..nextToSend-1 were sent as responses came in
		if i >= nextToSend {
			// This chunk was never sent, skip remaining chunks
			break
		}

		chunk := chunks[i]

		// Wait for this chunk's response
		var resp *response
		select {
		case resp = <-chunk.respCh:
			// Cleanup this MID
			f.session.conn.mu.Lock()
			delete(f.session.conn.pending, chunk.mid)
			f.session.conn.mu.Unlock()
		case <-ctx.Done():
			// Mark current chunk and all pending requests as cancelled
			f.session.conn.mu.Lock()
			if req, ok := f.session.conn.pending[chunk.mid]; ok {
				req.cancelled = true
			}
			f.session.conn.mu.Unlock()
			cleanupPending(i+1, nextToSend)
			return totalWritten, ctx.Err()
		case <-f.session.conn.done:
			// Connection closed - setError() or Close() will clean up all pending MIDs
			// including the current chunk, so no explicit cleanup needed here
			return totalWritten, f.session.conn.err
		}

		// Handle response error
		if resp.err != nil {
			// Clean up remaining pending requests
			cleanupPending(i+1, nextToSend)
			return totalWritten, fmt.Errorf("smb1: write failed: %w", resp.err)
		}

		// Decode response
		writeResp, err := smb1.DecodeWriteResponse(resp.params, resp.data)
		if err != nil {
			// Clean up remaining pending requests
			cleanupPending(i+1, nextToSend)
			return totalWritten, fmt.Errorf("smb1: failed to decode write response: %w", err)
		}

		// Check bytes written
		bytesWritten := int(writeResp.GetBytesWritten())
		totalWritten += bytesWritten

		// If we wrote less than requested, it's an error
		if bytesWritten < len(chunk.data) {
			// Clean up remaining pending requests
			cleanupPending(i+1, nextToSend)
			return totalWritten, io.ErrShortWrite
		}

		// Send next request if any remain
		if nextToSend < numChunks {
			if err := f.sendWriteRequest(chunks[nextToSend], ctx); err != nil {
				// Clean up remaining pending requests (including the one we just failed to send)
				cleanupPending(i+1, nextToSend)
				return totalWritten, err
			}
			nextToSend++
		}
	}

	return totalWritten, nil
}

// sendWriteRequest sends a single pipelined write request
func (f *File) sendWriteRequest(chunk *writeChunk, ctx context.Context) error {
	logger := logging.FromContext(ctx)

	writeSize := len(chunk.data)

	// Create WRITE_ANDX request
	req := &smb1.WriteRequest{
		AndXCommand:    smb1.SMB_COM_NO_ANDX_COMMAND,
		FID:            f.fid,
		Offset:         uint64(chunk.offset),
		Timeout:        0,
		WriteMode:      0,
		Remaining:      0,
		DataLengthHigh: uint16(writeSize >> 16),    // High 16 bits
		DataLength:     uint16(writeSize & 0xFFFF), // Low 16 bits
		DataOffset:     0,                          // Will be calculated by encoder
		Data:           chunk.data,
	}

	supportsLargeFiles := (f.session.conn.capabilities & smb1.CAP_LARGE_FILES) != 0
	params, data, err := smb1.EncodeWriteRequest(req, supportsLargeFiles)
	if err != nil {
		return fmt.Errorf("smb1: failed to encode write request: %w", err)
	}

	// Send request without waiting (pipelined)
	header := smb1.NewHeader(smb1.SMB_COM_WRITE_ANDX)
	header.UID = f.session.uid
	header.TID = f.tid

	// Allocate MID and register response channel
	f.session.conn.mu.Lock()

	// Check if connection is closed
	select {
	case <-f.session.conn.done:
		f.session.conn.mu.Unlock()
		return f.session.conn.err
	default:
	}

	mid, err := f.session.conn.allocateMID()
	if err != nil {
		f.session.conn.mu.Unlock()
		return err
	}

	header.MID = mid
	chunk.mid = mid
	f.session.conn.pending[mid] = &pendingRequest{respCh: chunk.respCh, cancelled: false}
	f.session.conn.mu.Unlock()

	logger.Debug("sendWriteRequest: MID %d, offset %d, size %d", mid, chunk.offset, len(chunk.data))

	// Encode and send packet
	packet, err := smb1.EncodePacket(header, params, data)
	if err != nil {
		// Cleanup on error
		f.session.conn.mu.Lock()
		delete(f.session.conn.pending, mid)
		f.session.conn.mu.Unlock()
		return fmt.Errorf("smb1: failed to encode packet: %w", err)
	}

	if err := f.session.conn.netbiosConn.WritePacketContext(ctx, packet); err != nil {
		// Cleanup on error
		f.session.conn.mu.Lock()
		delete(f.session.conn.pending, mid)
		f.session.conn.mu.Unlock()
		f.session.conn.setError(fmt.Errorf("smb1: failed to send packet: %w", err))
		return err
	}

	return nil
}

// WriteAt writes data to the file at the specified offset.
// It does not change the file offset.
func (f *File) WriteAt(data []byte, offset int64, ctx context.Context) (int, error) {
	logger := logging.FromContext(ctx)

	if len(data) == 0 {
		return 0, nil
	}

	// Calculate maximum write size per operation
	// NetBIOS session layer limits messages to 131072 bytes (128KB)
	// We need overhead for SMB headers (~1KB), so aim for ~127KB max data
	const maxDataPerWrite = 130048 // Same as smbclient uses (127KB)
	writeSize := len(data)
	if writeSize > maxDataPerWrite {
		writeSize = maxDataPerWrite
	}

	logger.Debug("WriteAt: writing %d bytes to %s at offset %d", writeSize, f.name, offset)

	// Create WRITE_ANDX request
	// DataLengthHigh (16 bits) + DataLength (16 bits) = 32-bit total data length
	req := &smb1.WriteRequest{
		AndXCommand:    smb1.SMB_COM_NO_ANDX_COMMAND,
		FID:            f.fid,
		Offset:         uint64(offset),
		Timeout:        0,
		WriteMode:      0,
		Remaining:      0,
		DataLengthHigh: uint16(writeSize >> 16),    // High 16 bits
		DataLength:     uint16(writeSize & 0xFFFF), // Low 16 bits
		DataOffset:     0,                          // Will be calculated by encoder
		Data:           data[:writeSize],
	}

	supportsLargeFiles := (f.session.conn.capabilities & smb1.CAP_LARGE_FILES) != 0
	params, writeData, err := smb1.EncodeWriteRequest(req, supportsLargeFiles)
	if err != nil {
		return 0, fmt.Errorf("smb1: failed to encode write request: %w", err)
	}

	header := smb1.NewHeader(smb1.SMB_COM_WRITE_ANDX)
	header.UID = f.session.uid
	header.TID = f.tid

	resp, err := f.session.conn.sendRecv(header, params, writeData, ctx)
	if err != nil {
		return 0, fmt.Errorf("smb1: write failed: %w", err)
	}

	if resp.err != nil {
		return 0, fmt.Errorf("smb1: write returned error: %w", resp.err)
	}

	// Decode WRITE_ANDX response
	writeResp, err := smb1.DecodeWriteResponse(resp.params, resp.data)
	if err != nil {
		return 0, fmt.Errorf("smb1: failed to decode write response: %w", err)
	}

	bytesWritten := int(writeResp.GetBytesWritten())
	return bytesWritten, nil
}

// Stat returns file information for the open file.
// It queries both basic info (timestamps, attributes) and standard info (size).
func (f *File) Stat(ctx context.Context) (*FileStat, error) {
	// Query both basic info and standard info using TRANS2_QUERY_FILE_INFORMATION
	// First query: SMB_QUERY_FILE_BASIC_INFO
	params1, err := smb1.EncodeQueryFileInfo(f.fid, smb1.SMB_QUERY_FILE_BASIC_INFO)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode query file info request: %w", err)
	}

	// Create tree helper to send TRANS2 requests
	tree := &Tree{
		Session: f.session,
		TID:     f.tid,
	}

	trans2Resp, err := tree.SendTransact2(smb1.TRANS2_QUERY_FILE_INFORMATION, params1, nil, ctx)
	if err != nil {
		return nil, fmt.Errorf("smb1: query file info (basic) failed: %w", err)
	}

	// Decode basic info
	basicInfo, err := smb1.DecodeFileBasicInfo(trans2Resp.Data)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to decode file basic info: %w", err)
	}

	// Second query: SMB_QUERY_FILE_STANDARD_INFO
	params2, err := smb1.EncodeQueryFileInfo(f.fid, smb1.SMB_QUERY_FILE_STANDARD_INFO)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode query file info request: %w", err)
	}

	trans2Resp2, err := tree.SendTransact2(smb1.TRANS2_QUERY_FILE_INFORMATION, params2, nil, ctx)
	if err != nil {
		return nil, fmt.Errorf("smb1: query file info (standard) failed: %w", err)
	}

	standardInfo, err := smb1.DecodeFileStandardInfo(trans2Resp2.Data)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to decode file standard info: %w", err)
	}

	// Merge attributes if directory flag is present
	attrs := basicInfo.Attributes
	if standardInfo.Directory != 0 {
		attrs |= smb1.FILE_ATTRIBUTE_DIRECTORY
	}

	// Create FileStat structure
	fileStat := &FileStat{
		CreationTime:   basicInfo.CreationTime,
		LastAccessTime: basicInfo.LastAccessTime,
		LastWriteTime:  basicInfo.LastWriteTime,
		ChangeTime:     basicInfo.ChangeTime,
		EndOfFile:      int64(standardInfo.EndOfFile),
		AllocationSize: int64(standardInfo.AllocationSize),
		FileAttributes: attrs,
		FileName:       baseName(f.name),
	}

	return fileStat, nil
}

// baseName returns the last element of a backslash-separated SMB path,
// matching go-smb2 and os.File.Stat().Name(): trailing separators are
// trimmed, and a path with no elements (the share root) yields "".
func baseName(path string) string {
	end := len(path)
	for end > 0 && path[end-1] == '\\' {
		end--
	}
	start := end
	for start > 0 && path[start-1] != '\\' {
		start--
	}
	return path[start:end]
}

// Truncate changes the size of the file.
// It does not change the I/O offset.
func (f *File) Truncate(size int64, ctx context.Context) error {
	if size < 0 {
		return fmt.Errorf("smb1: negative truncate size")
	}

	// Create FILE_END_OF_FILE_INFORMATION data (just the EndOfFile field)
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, uint64(size))

	// Encode SET_FILE_INFORMATION request
	params, dataBytes, err := smb1.EncodeSetFileInfo(f.fid, smb1.FILE_END_OF_FILE_INFORMATION, data)
	if err != nil {
		return fmt.Errorf("smb1: failed to encode set file info request: %w", err)
	}

	// Create tree helper to send TRANS2 requests
	tree := &Tree{
		Session: f.session,
		TID:     f.tid,
	}

	_, err = tree.SendTransact2(smb1.TRANS2_SET_FILE_INFORMATION, params, dataBytes, ctx)
	if err != nil {
		return fmt.Errorf("smb1: set file info failed: %w", err)
	}

	return nil
}

// Tree returns a Tree helper bound to this file's session and tree ID, for
// tree-scoped requests (such as TRANS2_QUERY_FS_INFORMATION) that must go to
// the same tree the file was opened on.
func (f *File) Tree() *Tree {
	return &Tree{
		Session: f.session,
		TID:     f.tid,
	}
}

// QueryBasicInfo queries SMB_QUERY_FILE_BASIC_INFO for the open file.
// Unlike Stat, it returns the attributes exactly as the server reports them,
// without merging in the directory flag — callers that read-modify-write the
// attributes must not echo back bits the server never set.
func (f *File) QueryBasicInfo(ctx context.Context) (*smb1.FileBasicInfo, error) {
	params, err := smb1.EncodeQueryFileInfo(f.fid, smb1.SMB_QUERY_FILE_BASIC_INFO)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode query file info request: %w", err)
	}

	resp, err := f.Tree().SendTransact2(smb1.TRANS2_QUERY_FILE_INFORMATION, params, nil, ctx)
	if err != nil {
		return nil, fmt.Errorf("smb1: query file info (basic) failed: %w", err)
	}

	info, err := smb1.DecodeFileBasicInfo(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to decode file basic info: %w", err)
	}
	return info, nil
}

// SetBasicInfo sets SMB_SET_FILE_BASIC_INFO on the open file. Zero-valued
// timestamps and a zero attributes field mean "leave unchanged" on the wire,
// so callers set only the fields they intend to change.
func (f *File) SetBasicInfo(info *smb1.FileBasicInfo, ctx context.Context) error {
	params, dataBytes, err := smb1.EncodeSetFileInfo(f.fid, smb1.SMB_SET_FILE_BASIC_INFO, smb1.EncodeFileBasicInfo(info))
	if err != nil {
		return fmt.Errorf("smb1: failed to encode set file info request: %w", err)
	}

	_, err = f.Tree().SendTransact2(smb1.TRANS2_SET_FILE_INFORMATION, params, dataBytes, ctx)
	if err != nil {
		return fmt.Errorf("smb1: set file info failed: %w", err)
	}
	return nil
}

// SetAttributes sets the extended file attributes of the open file. It first
// tries TRANS2_SET_FILE_INFORMATION at the SMB_SET_FILE_BASIC_INFO level,
// with all timestamps zero ("leave unchanged"). Legacy servers that reject
// attribute changes at that level with STATUS_NOT_SUPPORTED get the
// core-protocol SMB_COM_SET_INFORMATION fallback instead, which is
// path-based: it addresses the file by the path it was opened with rather
// than by handle, and carries the DOS 16-bit attribute subset (see
// dosAttributes). Any other error is returned as-is, with no fallback
// attempt.
func (f *File) SetAttributes(attrs uint32, ctx context.Context) error {
	info := &smb1.FileBasicInfo{Attributes: attrs}
	params, dataBytes, err := smb1.EncodeSetFileInfo(f.fid, smb1.SMB_SET_FILE_BASIC_INFO, smb1.EncodeFileBasicInfo(info))
	if err != nil {
		return fmt.Errorf("smb1: failed to encode set file info request: %w", err)
	}

	_, err = f.Tree().SendTransact2(smb1.TRANS2_SET_FILE_INFORMATION, params, dataBytes, ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, erref.STATUS_NOT_SUPPORTED) {
		return fmt.Errorf("smb1: set file info failed: %w", err)
	}

	if err := f.Tree().SendSetInformation(f.name, dosAttributes(attrs), 0, ctx); err != nil {
		return fmt.Errorf("smb1: set information failed: %w", err)
	}
	return nil
}

// Seek sets the file offset for the next Read or Write.
// It returns the new offset.
// This method implements the io.Seeker interface.
func (f *File) Seek(offset int64, whence int) (int64, error) {
	return f.SeekContext(offset, whence, context.Background())
}

// GetOffset returns the current file offset.
// This is thread-safe and can be called concurrently.
func (f *File) GetOffset() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.offset
}

// SeekContext sets the file offset for the next Read or Write with context support.
// It returns the new offset.
func (f *File) SeekContext(offset int64, whence int, ctx context.Context) (int64, error) {
	logger := logging.FromContext(ctx)
	var newOffset int64

	switch whence {
	case io.SeekStart:
		f.mu.Lock()
		f.offset = offset
		newOffset = f.offset
		f.mu.Unlock()
	case io.SeekCurrent:
		f.mu.Lock()
		f.offset += offset
		newOffset = f.offset
		f.mu.Unlock()
	case io.SeekEnd:
		// Query file size using Stat()
		stat, err := f.Stat(ctx)
		if err != nil {
			return 0, fmt.Errorf("smb1: failed to get file size for SeekEnd: %w", err)
		}
		f.mu.Lock()
		f.offset = stat.EndOfFile + offset
		newOffset = f.offset
		f.mu.Unlock()
	default:
		return 0, fmt.Errorf("smb1: invalid whence value: %d", whence)
	}

	if newOffset < 0 {
		f.mu.Lock()
		f.offset = 0
		f.mu.Unlock()
		return 0, fmt.Errorf("smb1: negative seek position")
	}

	logger.Debug("SeekContext: seek completed, new offset=%d", newOffset)
	return newOffset, nil
}

// Readdir reads the contents of the directory associated with file and returns
// a slice of up to n FileInfo values, as would be returned by Stat, in directory
// order. Subsequent calls on the same file will yield further FileInfos.
//
// If n > 0, Readdir returns at most n FileInfo structures. In this case, if
// Readdir returns an empty slice, it will return a non-nil error explaining why.
// At the end of a directory, the error is io.EOF.
//
// If n <= 0, Readdir returns all the FileInfo from the directory in a single
// slice. In this case, if Readdir succeeds (reads all the way to the end of
// the directory), it returns the slice and a nil error.
//
// This implementation maintains state in the File's offset field to track
// pagination across multiple calls.
func (f *File) Readdir(n int, ctx context.Context) ([]FileStat, error) {
	logger := logging.FromContext(ctx)
	logger.Debug("Readdir: reading directory %s (n=%d)", f.name, n)

	// Get tree from session
	f.session.mu.Lock()
	tree, exists := f.session.trees[f.tid]
	f.session.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("smb1: tree connection not found")
	}

	// Build search pattern (directory\*)
	searchPattern := f.name
	if searchPattern == "" {
		searchPattern = "\\*"
	} else {
		if searchPattern[len(searchPattern)-1] != '\\' {
			searchPattern += "\\"
		}
		searchPattern += "*"
	}

	// For n <= 0, read all entries at once
	if n <= 0 {
		entries, err := f.readdirAll(tree, searchPattern, ctx)
		if err != nil {
			return nil, err
		}
		return entries, nil
	}

	// For n > 0, we need to implement pagination
	// Since we can't store arbitrary state in the File struct, we'll use the offset field
	// to track our position in the results. This means we need to read all entries
	// on the first call and cache them conceptually.
	//
	// However, since we can't add fields to File without breaking the API, we'll
	// implement a simpler approach: read all entries and return the first n,
	// then return io.EOF on subsequent calls.
	//
	// This is a limitation of the current design - proper pagination would require
	// additional state storage.

	entries, err := f.readdirAll(tree, searchPattern, ctx)
	if err != nil {
		return nil, err
	}

	// Check if offset is beyond entries (subsequent calls)
	f.mu.Lock()
	offset := int(f.offset)
	f.mu.Unlock()

	if offset >= len(entries) {
		return nil, io.EOF
	}

	// Return next batch of n entries
	endIdx := offset + n
	if endIdx > len(entries) {
		endIdx = len(entries)
	}

	result := entries[offset:endIdx]

	// Update offset for next call
	f.mu.Lock()
	f.offset = int64(endIdx)
	f.mu.Unlock()

	// If we've returned all entries, return io.EOF
	if endIdx >= len(entries) {
		if len(result) == 0 {
			return nil, io.EOF
		}
		return result, io.EOF
	}

	return result, nil
}

// TransactNamedPipe sends a transaction to an already-opened named pipe using its FID.
// This is used for RPC operations over named pipes.
// Unlike SendTransaction which uses pipe names for RAP, this method uses the FID
// from an NT_CREATE_ANDX operation and performs the transaction using the
// TransactNamedPipe SMB function (0x0026). If the server doesn't support that,
// it falls back to using Write/Read operations.
func (f *File) TransactNamedPipe(data []byte, ctx context.Context) ([]byte, error) {
	logger := logging.FromContext(ctx)
	logger.Debug("TransactNamedPipe: sending %d bytes to pipe FID=%d", len(data), f.fid)

	// First, try the proper SMB TransactNamedPipe function (0x0026)
	allParams, dataBytes, err := smb1.EncodeTransactNamedPipeRequest(f.fid, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode TransactNamedPipe request: %w", err)
	}

	header := smb1.NewHeader(smb1.SMB_COM_TRANSACTION)
	header.UID = f.session.uid
	header.TID = f.tid

	resp, err := f.session.conn.sendRecv(header, allParams, dataBytes, ctx)
	if err == nil && resp.err == nil {
		// Success with TransactNamedPipe function
		transResp, err := smb1.DecodeTransactionResponse(resp.params, resp.data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode TransactNamedPipe response: %w", err)
		}
		logger.Debug("TransactNamedPipe: received %d bytes from pipe FID=%d", len(transResp.Data), f.fid)
		return transResp.Data, nil
	}

	// If TransactNamedPipe is not supported, fall back to Write/Read
	// This handles servers that only support basic pipe operations
	logger.Debug("TransactNamedPipe: TransactNmPipe function not supported, falling back to Write/Read")

	// Write the request data to the named pipe
	// Named pipes are sequential streams
	_, err = f.Write(data, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to write to named pipe: %w", err)
	}

	// Read the response from the named pipe
	response := make([]byte, 65536) // Max buffer size for SMB1
	n, err := f.Read(response, ctx)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read from named pipe: %w", err)
	}

	logger.Debug("TransactNamedPipe: received %d bytes from pipe FID=%d (via Write/Read)", n, f.fid)
	return response[:n], nil
}

// readdirAll reads all directory entries using TRANS2_FIND_FIRST2/FIND_NEXT2.
func (f *File) readdirAll(tree *Tree, searchPattern string, ctx context.Context) ([]FileStat, error) {
	logger := logging.FromContext(ctx)
	logger.Debug("readdirAll: searching for %s", searchPattern)

	// Create FIND_FIRST2 request
	findReq := &smb1.FindFirst2Request{
		SearchAttributes:  smb1.SMB_SEARCH_ATTRIBUTE_DIRECTORY | smb1.SMB_SEARCH_ATTRIBUTE_HIDDEN | smb1.SMB_SEARCH_ATTRIBUTE_SYSTEM,
		SearchCount:       100,
		Flags:             smb1.SMB_FIND_CLOSE_AT_EOS,
		InformationLevel:  smb1.SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
		SearchStorageType: 0,
		FileName:          searchPattern,
		UseUnicode:        (tree.GetCapabilities() & smb1.CAP_UNICODE) != 0,
	}

	params, err := smb1.EncodeFindFirst2(findReq)
	if err != nil {
		return nil, err
	}

	trans2Resp, err := tree.SendTransact2(smb1.TRANS2_FIND_FIRST2, params, nil, ctx)
	if err != nil {
		return nil, err
	}

	findResp, err := smb1.DecodeFindFirst2Response(trans2Resp.Parameters, trans2Resp.Data, smb1.SMB_FIND_FILE_BOTH_DIRECTORY_INFO)
	if err != nil {
		return nil, err
	}

	var allFiles []smb1.FileBothDirectoryInfo
	allFiles = append(allFiles, findResp.Files...)

	// If there are more entries, use FIND_NEXT2 to get them
	sid := findResp.SID
	for findResp.EndOfSearch == 0 && findResp.SearchCount > 0 {
		// Check if context has been canceled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Create FIND_NEXT2 request
		findNextReq := &smb1.FindNext2Request{
			SID:              sid,
			SearchCount:      100,
			InformationLevel: smb1.SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
			ResumeKey:        0,
			Flags:            smb1.SMB_FIND_CONTINUE_FROM_LAST,
			FileName:         searchPattern,
			UseUnicode:       (tree.GetCapabilities() & smb1.CAP_UNICODE) != 0,
		}

		params2, err := smb1.EncodeFindNext2(findNextReq)
		if err != nil {
			return nil, err
		}

		trans2Resp2, err := tree.SendTransact2(smb1.TRANS2_FIND_NEXT2, params2, nil, ctx)
		if err != nil {
			return nil, err
		}

		findNextResp, err := smb1.DecodeFindNext2Response(trans2Resp2.Parameters, trans2Resp2.Data, smb1.SMB_FIND_FILE_BOTH_DIRECTORY_INFO)
		if err != nil {
			return nil, err
		}

		allFiles = append(allFiles, findNextResp.Files...)
		findResp.EndOfSearch = findNextResp.EndOfSearch
		findResp.SearchCount = findNextResp.SearchCount
	}

	// Convert to []FileStat
	result := make([]FileStat, 0, len(allFiles))
	for _, file := range allFiles {
		// Skip "." and ".." entries
		if file.FileName == "." || file.FileName == ".." {
			continue
		}

		fileStat := FileStat{
			CreationTime:   file.CreationTime,
			LastAccessTime: file.LastAccessTime,
			LastWriteTime:  file.LastWriteTime,
			ChangeTime:     file.ChangeTime,
			EndOfFile:      int64(file.EndOfFile),
			AllocationSize: int64(file.AllocationSize),
			FileAttributes: file.FileAttributes,
			FileName:       file.FileName,
		}
		result = append(result, fileStat)
	}

	return result, nil
}
