package smb1

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/macourteau/smb1client/internal/utf16le"
)

// NTCreateRequest represents an SMB_COM_NT_CREATE_ANDX request.
// This command opens or creates a file with NT-style semantics.
//
// Request format (AndX command, WordCount = 24):
//
//	Parameters (48 bytes = 24 words):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-5:   Reserved
//	  5-7:   NameLength (uint16)
//	  7-11:  Flags (uint32)
//	  11-15: RootDirectoryFID (uint32)
//	  15-19: DesiredAccess (uint32)
//	  19-27: AllocationSize (uint64)
//	  27-31: FileAttributes (uint32)
//	  31-35: ShareAccess (uint32)
//	  35-39: CreateDisposition (uint32)
//	  39-43: CreateOptions (uint32)
//	  43-47: ImpersonationLevel (uint32)
//	  47-48: SecurityFlags (uint8)
//	Data:
//	  FileName (null-terminated string)
type NTCreateRequest struct {
	AndXCommand        uint8  // Chained command (usually SMB_COM_NO_ANDX_COMMAND)
	AndXReserved       uint8  // Reserved (must be 0)
	AndXOffset         uint16 // Offset to next command
	Reserved           uint8  // Reserved (must be 0)
	NameLength         uint16 // Length of file name in bytes
	Flags              uint32 // Flags (request oplock, extended response, etc.)
	RootDirectoryFID   uint32 // FID of root directory (usually 0)
	DesiredAccess      uint32 // Access mask (GENERIC_READ, etc.)
	AllocationSize     uint64 // Initial allocation size
	FileAttributes     uint32 // File attributes
	ShareAccess        uint32 // Share access flags
	CreateDisposition  uint32 // Create disposition (open, create, etc.)
	CreateOptions      uint32 // Create options
	ImpersonationLevel uint32 // Security impersonation level
	SecurityFlags      uint8  // Security flags
	FileName           string // File name
	UseUnicode         bool   // Whether to use Unicode strings
}

// NTCreateResponse represents an SMB_COM_NT_CREATE_ANDX response.
//
// Response format (AndX command, WordCount = 34 or 42):
//
//	Parameters (68 bytes = 34 words):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-5:   OpLockLevel (uint8)
//	  5-7:   FID (uint16)
//	  7-11:  CreateAction (uint32)
//	  11-19: CreationTime (uint64)
//	  19-27: LastAccessTime (uint64)
//	  27-35: LastWriteTime (uint64)
//	  35-43: ChangeTime (uint64)
//	  43-47: FileAttributes (uint32)
//	  47-55: AllocationSize (uint64)
//	  55-63: EndOfFile (uint64)
//	  63-65: FileType (uint16)
//	  65-67: IPCState (uint16)
//	  67-68: IsDirectory (uint8)
type NTCreateResponse struct {
	AndXCommand    uint8  // Chained command
	AndXReserved   uint8  // Reserved
	AndXOffset     uint16 // Offset to next command
	OpLockLevel    uint8  // OpLock level granted
	FID            uint16 // File ID
	CreateAction   uint32 // Action taken (opened, created, truncated)
	CreationTime   uint64 // File creation time (FILETIME)
	LastAccessTime uint64 // Last access time (FILETIME)
	LastWriteTime  uint64 // Last write time (FILETIME)
	ChangeTime     uint64 // Change time (FILETIME)
	FileAttributes uint32 // File attributes
	AllocationSize uint64 // Allocated size
	EndOfFile      uint64 // End of file offset
	FileType       uint16 // File type
	IPCState       uint16 // IPC state (for named pipes)
	IsDirectory    uint8  // 1 if directory, 0 if file
}

// ReadRequest represents an SMB_COM_READ_ANDX request.
// This command reads data from a file.
//
// Request format (AndX command, WordCount = 10 or 12):
//
//	Parameters (20 or 24 bytes):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-6:   FID (uint16)
//	  6-10:  Offset (uint32)
//	  10-12: MaxCountOfBytesToReturn (uint16)
//	  12-14: MinCountOfBytesToReturn (uint16)
//	  14-16: MaxCountHigh (uint16, for files with CAP_LARGE_READX) OR Timeout (uint32, for pipes)
//	  16-18: Reserved (uint16, for files) OR Timeout cont'd (for pipes)
//	  18-20: Remaining (uint16)
//	  20-24: OffsetHigh (uint32, optional for large files)
type ReadRequest struct {
	AndXCommand             uint8  // Chained command (usually SMB_COM_NO_ANDX_COMMAND)
	AndXReserved            uint8  // Reserved (must be 0)
	AndXOffset              uint16 // Offset to next command
	FID                     uint16 // File ID
	Offset                  uint64 // Byte offset to read from (64-bit)
	MaxCountOfBytesToReturn uint16 // Maximum bytes to return (low 16 bits)
	MinCountOfBytesToReturn uint16 // Minimum bytes to return
	MaxCountHigh            uint16 // High 16 bits of max count (for CAP_LARGE_READX)
	Timeout                 uint32 // Timeout in milliseconds (for named pipes, unused for files)
	Remaining               uint16 // Bytes remaining to satisfy request
}

// ReadResponse represents an SMB_COM_READ_ANDX response.
//
// Response format (AndX command, WordCount = 12):
//
//	Parameters (24 bytes = 12 words):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-6:   Remaining (uint16)
//	  6-8:   DataCompactionMode (uint16)
//	  8-10:  Reserved (uint16)
//	  10-12: DataLength (uint16)
//	  12-14: DataOffset (uint16)
//	  14-18: DataLengthHigh (uint32)
//	  18-24: Reserved (6 bytes)
//	Data:
//	  Pad (to align data to DataOffset)
//	  Data (DataLength bytes)
type ReadResponse struct {
	AndXCommand        uint8  // Chained command
	AndXReserved       uint8  // Reserved
	AndXOffset         uint16 // Offset to next command
	Remaining          uint16 // Bytes remaining to be read
	DataCompactionMode uint16 // Data compaction mode
	Reserved           uint16 // Reserved
	DataLength         uint16 // Length of data (low 16 bits)
	DataOffset         uint16 // Offset of data from start of SMB header
	DataLengthHigh     uint32 // High 32 bits of data length
	Data               []byte // File data
}

// WriteRequest represents an SMB_COM_WRITE_ANDX request.
// This command writes data to a file.
//
// Request format (AndX command, WordCount = 12 or 14):
//
//	Parameters (24 or 28 bytes):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-6:   FID (uint16)
//	  6-10:  Offset (uint32)
//	  10-14: Timeout (uint32)
//	  14-16: WriteMode (uint16)
//	  16-18: Remaining (uint16)
//	  18-20: DataLengthHigh (uint16)
//	  20-22: DataLength (uint16)
//	  22-24: DataOffset (uint16)
//	  24-28: OffsetHigh (uint32, optional for large files)
//	Data:
//	  Pad (to align data to DataOffset)
//	  Data (DataLength bytes)
type WriteRequest struct {
	AndXCommand    uint8  // Chained command (usually SMB_COM_NO_ANDX_COMMAND)
	AndXReserved   uint8  // Reserved (must be 0)
	AndXOffset     uint16 // Offset to next command
	FID            uint16 // File ID
	Offset         uint64 // Byte offset to write to (64-bit)
	Timeout        uint32 // Timeout in milliseconds
	WriteMode      uint16 // Write mode flags
	Remaining      uint16 // Bytes remaining to write
	DataLengthHigh uint16 // High 16 bits of data length
	DataLength     uint16 // Length of data (low 16 bits)
	DataOffset     uint16 // Offset of data from start of SMB header
	Data           []byte // Data to write
}

// WriteResponse represents an SMB_COM_WRITE_ANDX response.
//
// Response format (AndX command, WordCount = 6):
//
//	Parameters (12 bytes = 6 words):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-6:   Count (uint16)
//	  6-8:   Remaining (uint16)
//	  8-12:  CountHigh (uint32)
type WriteResponse struct {
	AndXCommand  uint8  // Chained command
	AndXReserved uint8  // Reserved
	AndXOffset   uint16 // Offset to next command
	Count        uint16 // Number of bytes written (low 16 bits)
	Remaining    uint16 // Bytes remaining to be written
	CountHigh    uint32 // High 32 bits of bytes written
}

// CloseRequest represents an SMB_COM_CLOSE request.
// This command closes a file.
//
// Request format (WordCount = 3):
//
//	Parameters (6 bytes = 3 words):
//	  0-2:  FID (uint16)
//	  2-6:  LastWriteTime (uint32)
type CloseRequest struct {
	FID           uint16 // File ID
	LastWriteTime uint32 // Last write time (0 = don't update)
}

// CloseResponse represents an SMB_COM_CLOSE response.
// This response is empty (WordCount = 0, ByteCount = 0).
type CloseResponse struct {
	// No fields - this is an empty response
}

// NT Create flags
const (
	NT_CREATE_REQUEST_OPLOCK            uint32 = 0x00000002 // Request exclusive oplock
	NT_CREATE_REQUEST_OPBATCH           uint32 = 0x00000004 // Request batch oplock
	NT_CREATE_OPEN_TARGET_DIR           uint32 = 0x00000008 // Open target directory
	NT_CREATE_REQUEST_EXTENDED_RESPONSE uint32 = 0x00000010 // Request extended response
)

// Create action flags for NTCreateResponse.CreateAction
const (
	FILE_SUPERSEDED  uint32 = 0x00000000 // File was superseded
	FILE_OPENED      uint32 = 0x00000001 // File was opened
	FILE_CREATED     uint32 = 0x00000002 // File was created
	FILE_OVERWRITTEN uint32 = 0x00000003 // File was overwritten
)

// OpLock level constants
const (
	OPLOCK_NONE      uint8 = 0x00 // No oplock granted
	OPLOCK_EXCLUSIVE uint8 = 0x01 // Exclusive oplock granted
	OPLOCK_BATCH     uint8 = 0x02 // Batch oplock granted
	OPLOCK_LEVEL_II  uint8 = 0x03 // Level II oplock granted
)

// File type constants
const (
	FILE_TYPE_DISK              uint16 = 0x0000 // Disk file
	FILE_TYPE_BYTE_MODE_PIPE    uint16 = 0x0001 // Byte-mode named pipe
	FILE_TYPE_MESSAGE_MODE_PIPE uint16 = 0x0002 // Message-mode named pipe
	FILE_TYPE_PRINTER           uint16 = 0x0003 // Printer
)

// Write mode flags
const (
	WRITE_THROUGH            uint16 = 0x0001 // Write through to disk
	WRITE_MODE_RAW           uint16 = 0x0002 // Use raw mode
	WRITE_MODE_MESSAGE_START uint16 = 0x0008 // Message mode pipe start
)

// Impersonation level constants
const (
	SECURITY_ANONYMOUS      uint32 = 0x00000000
	SECURITY_IDENTIFICATION uint32 = 0x00000001
	SECURITY_IMPERSONATION  uint32 = 0x00000002
	SECURITY_DELEGATION     uint32 = 0x00000003
)

// EncodeNTCreateRequest encodes an SMB_COM_NT_CREATE_ANDX request.
func EncodeNTCreateRequest(req *NTCreateRequest) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: nt create request is nil")
	}

	if req.FileName == "" {
		return nil, nil, fmt.Errorf("smb1: file name is empty")
	}

	// Parameters: 24 words = 48 bytes
	params := make([]byte, 48)

	// AndX header (4 bytes)
	params[0] = req.AndXCommand
	params[1] = req.AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], req.AndXOffset)

	// NT Create parameters
	params[4] = req.Reserved
	binary.LittleEndian.PutUint16(params[5:7], req.NameLength)
	binary.LittleEndian.PutUint32(params[7:11], req.Flags)
	binary.LittleEndian.PutUint32(params[11:15], req.RootDirectoryFID)
	binary.LittleEndian.PutUint32(params[15:19], req.DesiredAccess)
	binary.LittleEndian.PutUint64(params[19:27], req.AllocationSize)
	binary.LittleEndian.PutUint32(params[27:31], req.FileAttributes)
	binary.LittleEndian.PutUint32(params[31:35], req.ShareAccess)
	binary.LittleEndian.PutUint32(params[35:39], req.CreateDisposition)
	binary.LittleEndian.PutUint32(params[39:43], req.CreateOptions)
	binary.LittleEndian.PutUint32(params[43:47], req.ImpersonationLevel)
	params[47] = req.SecurityFlags

	// Data section: file name (null-terminated SMB_STRING)
	var data []byte

	if req.UseUnicode {
		// For NT_CREATE_ANDX, the Unicode string must be aligned to a 2-byte boundary
		// from the start of the SMB header. The Data section starts at offset 83
		// (Header=32 + WordCount=1 + Parameters=48 + ByteCount=2), which is odd.
		// Therefore, we always need 1 byte of padding for Unicode.
		data = append(data, 0)
		nameBytes := utf16le.EncodeStringToBytes(req.FileName)
		data = append(data, nameBytes...)
		// Add Unicode null terminator (2 bytes)
		data = append(data, 0, 0)
	} else {
		data = append(data, []byte(req.FileName)...)
		// Add ASCII null terminator (1 byte)
		data = append(data, 0)
	}

	return params, data, nil
}

// DecodeNTCreateResponse decodes an SMB_COM_NT_CREATE_ANDX response.
func DecodeNTCreateResponse(params, data []byte) (*NTCreateResponse, error) {
	// Validate parameters size (should be at least 68 bytes = 34 words)
	if len(params) < 68 {
		return nil, fmt.Errorf("smb1: nt create response parameters too short: got %d bytes, need at least 68", len(params))
	}

	resp := &NTCreateResponse{}

	// Parse AndX header
	resp.AndXCommand = params[0]
	resp.AndXReserved = params[1]
	resp.AndXOffset = binary.LittleEndian.Uint16(params[2:4])

	// Parse NT Create response parameters
	resp.OpLockLevel = params[4]
	resp.FID = binary.LittleEndian.Uint16(params[5:7])
	resp.CreateAction = binary.LittleEndian.Uint32(params[7:11])
	resp.CreationTime = binary.LittleEndian.Uint64(params[11:19])
	resp.LastAccessTime = binary.LittleEndian.Uint64(params[19:27])
	resp.LastWriteTime = binary.LittleEndian.Uint64(params[27:35])
	resp.ChangeTime = binary.LittleEndian.Uint64(params[35:43])
	resp.FileAttributes = binary.LittleEndian.Uint32(params[43:47])
	resp.AllocationSize = binary.LittleEndian.Uint64(params[47:55])
	resp.EndOfFile = binary.LittleEndian.Uint64(params[55:63])
	resp.FileType = binary.LittleEndian.Uint16(params[63:65])
	resp.IPCState = binary.LittleEndian.Uint16(params[65:67])
	resp.IsDirectory = params[67]

	return resp, nil
}

// EncodeReadRequest encodes an SMB_COM_READ_ANDX request.
// supportsLargeFiles controls whether the 64-bit file offset extension is used.
// supportsLargeReadX controls whether MaxCountHigh is used for large reads (CAP_LARGE_READX).
func EncodeReadRequest(req *ReadRequest, supportsLargeFiles bool, supportsLargeReadX bool) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: read request is nil")
	}

	var params []byte

	if supportsLargeFiles {
		// WordCount = 12 (24 bytes)
		params = make([]byte, 24)

		// AndX header (4 bytes)
		params[0] = req.AndXCommand
		params[1] = req.AndXReserved
		binary.LittleEndian.PutUint16(params[2:4], req.AndXOffset)

		// Read parameters
		binary.LittleEndian.PutUint16(params[4:6], req.FID)
		binary.LittleEndian.PutUint32(params[6:10], uint32(req.Offset))
		binary.LittleEndian.PutUint16(params[10:12], req.MaxCountOfBytesToReturn)
		binary.LittleEndian.PutUint16(params[12:14], req.MinCountOfBytesToReturn)

		// Bytes 14-18: MaxCountHigh (for files with CAP_LARGE_READX) OR Timeout (for named pipes)
		if supportsLargeReadX {
			// For files with CAP_LARGE_READX: use MaxCountHigh + Reserved
			binary.LittleEndian.PutUint16(params[14:16], req.MaxCountHigh)
			binary.LittleEndian.PutUint16(params[16:18], 0) // Reserved
		} else {
			// For named pipes or when CAP_LARGE_READX not available: use Timeout
			binary.LittleEndian.PutUint32(params[14:18], req.Timeout)
		}

		binary.LittleEndian.PutUint16(params[18:20], req.Remaining)
		binary.LittleEndian.PutUint32(params[20:24], uint32(req.Offset>>32)) // OffsetHigh
	} else {
		// WordCount = 10 (20 bytes)
		params = make([]byte, 20)

		// AndX header (4 bytes)
		params[0] = req.AndXCommand
		params[1] = req.AndXReserved
		binary.LittleEndian.PutUint16(params[2:4], req.AndXOffset)

		// Read parameters
		binary.LittleEndian.PutUint16(params[4:6], req.FID)
		binary.LittleEndian.PutUint32(params[6:10], uint32(req.Offset))
		binary.LittleEndian.PutUint16(params[10:12], req.MaxCountOfBytesToReturn)
		binary.LittleEndian.PutUint16(params[12:14], req.MinCountOfBytesToReturn)
		binary.LittleEndian.PutUint32(params[14:18], req.Timeout)
		binary.LittleEndian.PutUint16(params[18:20], req.Remaining)
	}

	// Data section is empty for read request
	data := []byte{}

	return params, data, nil
}

// DecodeReadResponse decodes an SMB_COM_READ_ANDX response.
func DecodeReadResponse(params, data []byte) (*ReadResponse, error) {
	// Validate parameters size (should be at least 24 bytes = 12 words)
	if len(params) < 24 {
		return nil, fmt.Errorf("smb1: read response parameters too short: got %d bytes, need at least 24", len(params))
	}

	resp := &ReadResponse{}

	// Parse AndX header
	resp.AndXCommand = params[0]
	resp.AndXReserved = params[1]
	resp.AndXOffset = binary.LittleEndian.Uint16(params[2:4])

	// Parse read response parameters
	resp.Remaining = binary.LittleEndian.Uint16(params[4:6])
	resp.DataCompactionMode = binary.LittleEndian.Uint16(params[6:8])
	resp.Reserved = binary.LittleEndian.Uint16(params[8:10])
	resp.DataLength = binary.LittleEndian.Uint16(params[10:12])
	resp.DataOffset = binary.LittleEndian.Uint16(params[12:14])
	resp.DataLengthHigh = binary.LittleEndian.Uint32(params[14:18])

	// Calculate total data length (combine low and high parts)
	totalDataLength := uint64(resp.DataLength) | (uint64(resp.DataLengthHigh) << 16)

	// Extract data from data section
	if totalDataLength > 0 {
		// DataOffset is an absolute offset from the SMB header where the file data starts.
		// The ByteCount section starts at: Header(32) + WordCount(1) + Params(len) + ByteCount(2)
		// The server may insert padding bytes to align the file data.
		byteCountSectionOffset := HeaderSize + 1 + len(params) + 2

		// Calculate how many padding bytes precede the actual file data
		padding := int(resp.DataOffset) - byteCountSectionOffset

		// Validate padding is reasonable
		if padding < 0 || padding > len(data) {
			padding = 0 // Safety fallback
		}

		// Check we have enough data after skipping padding
		if padding+int(totalDataLength) > len(data) {
			return nil, fmt.Errorf("smb1: data too short: got %d bytes, need %d (including %d padding bytes)",
				len(data), padding+int(totalDataLength), padding)
		}

		resp.Data = make([]byte, totalDataLength)
		copy(resp.Data, data[padding:padding+int(totalDataLength)])
	}

	return resp, nil
}

// EncodeWriteRequest encodes an SMB_COM_WRITE_ANDX request.
func EncodeWriteRequest(req *WriteRequest, supportsLargeFiles bool) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: write request is nil")
	}

	var params []byte
	var paramsLen int

	if supportsLargeFiles {
		// WordCount = 14 (28 bytes)
		paramsLen = 28
		params = make([]byte, paramsLen)

		// AndX header (4 bytes)
		params[0] = req.AndXCommand
		params[1] = req.AndXReserved
		binary.LittleEndian.PutUint16(params[2:4], req.AndXOffset)

		// Calculate DataOffset: Header(32) + WordCount(1) + Params(28) + ByteCount(2) = 63
		dataOffset := uint16(HeaderSize + 1 + paramsLen + 2)

		// Write parameters
		binary.LittleEndian.PutUint16(params[4:6], req.FID)
		binary.LittleEndian.PutUint32(params[6:10], uint32(req.Offset))
		binary.LittleEndian.PutUint32(params[10:14], req.Timeout)
		binary.LittleEndian.PutUint16(params[14:16], req.WriteMode)
		binary.LittleEndian.PutUint16(params[16:18], req.Remaining)
		binary.LittleEndian.PutUint16(params[18:20], req.DataLengthHigh)
		binary.LittleEndian.PutUint16(params[20:22], req.DataLength)
		binary.LittleEndian.PutUint16(params[22:24], dataOffset)
		binary.LittleEndian.PutUint32(params[24:28], uint32(req.Offset>>32)) // OffsetHigh
	} else {
		// WordCount = 12 (24 bytes)
		paramsLen = 24
		params = make([]byte, paramsLen)

		// AndX header (4 bytes)
		params[0] = req.AndXCommand
		params[1] = req.AndXReserved
		binary.LittleEndian.PutUint16(params[2:4], req.AndXOffset)

		// Calculate DataOffset: Header(32) + WordCount(1) + Params(24) + ByteCount(2) = 59
		dataOffset := uint16(HeaderSize + 1 + paramsLen + 2)

		// Write parameters
		binary.LittleEndian.PutUint16(params[4:6], req.FID)
		binary.LittleEndian.PutUint32(params[6:10], uint32(req.Offset))
		binary.LittleEndian.PutUint32(params[10:14], req.Timeout)
		binary.LittleEndian.PutUint16(params[14:16], req.WriteMode)
		binary.LittleEndian.PutUint16(params[16:18], req.Remaining)
		binary.LittleEndian.PutUint16(params[18:20], req.DataLengthHigh)
		binary.LittleEndian.PutUint16(params[20:22], req.DataLength)
		binary.LittleEndian.PutUint16(params[22:24], dataOffset)
	}

	// Data section contains the data to write
	data := make([]byte, len(req.Data))
	copy(data, req.Data)

	return params, data, nil
}

// DecodeWriteResponse decodes an SMB_COM_WRITE_ANDX response.
func DecodeWriteResponse(params, data []byte) (*WriteResponse, error) {
	// Validate parameters size (should be at least 12 bytes = 6 words)
	if len(params) < 12 {
		return nil, fmt.Errorf("smb1: write response parameters too short: got %d bytes, need at least 12", len(params))
	}

	resp := &WriteResponse{}

	// Parse AndX header
	resp.AndXCommand = params[0]
	resp.AndXReserved = params[1]
	resp.AndXOffset = binary.LittleEndian.Uint16(params[2:4])

	// Parse write response parameters
	resp.Count = binary.LittleEndian.Uint16(params[4:6])
	resp.Remaining = binary.LittleEndian.Uint16(params[6:8])
	resp.CountHigh = binary.LittleEndian.Uint32(params[8:12])

	return resp, nil
}

// EncodeCloseRequest encodes an SMB_COM_CLOSE request.
func EncodeCloseRequest(req *CloseRequest) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: close request is nil")
	}

	// Parameters: 3 words = 6 bytes
	params := make([]byte, 6)
	binary.LittleEndian.PutUint16(params[0:2], req.FID)
	binary.LittleEndian.PutUint32(params[2:6], req.LastWriteTime)

	// Data section is empty
	data := []byte{}

	return params, data, nil
}

// DecodeCloseResponse decodes an SMB_COM_CLOSE response.
// This response is empty (WordCount = 0, ByteCount = 0).
func DecodeCloseResponse(params, data []byte) (*CloseResponse, error) {
	// Validate empty response
	if len(params) != 0 {
		return nil, fmt.Errorf("smb1: close response should have no parameters, got %d bytes", len(params))
	}
	if len(data) != 0 {
		return nil, fmt.Errorf("smb1: close response should have no data, got %d bytes", len(data))
	}

	return &CloseResponse{}, nil
}

// GetBytesWritten returns the total number of bytes written (combining Count and CountHigh).
func (r *WriteResponse) GetBytesWritten() uint64 {
	return uint64(r.Count) | (uint64(r.CountHigh) << 16)
}

// GetDataLength returns the total length of data read (combining DataLength and DataLengthHigh).
func (r *ReadResponse) GetDataLength() uint64 {
	return uint64(r.DataLength) | (uint64(r.DataLengthHigh) << 16)
}

// IsDirectory returns true if the opened file is a directory.
func (r *NTCreateResponse) IsDir() bool {
	return r.IsDirectory != 0
}

// String returns a human-readable representation of the NT create response.
func (r *NTCreateResponse) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("NTCreateResponse{FID:%d CreateAction:0x%08X ", r.FID, r.CreateAction))
	sb.WriteString(fmt.Sprintf("Size:%d Attrs:0x%08X", r.EndOfFile, r.FileAttributes))
	if r.IsDir() {
		sb.WriteString(" (DIR)")
	}
	sb.WriteString("}")
	return sb.String()
}
