package smb1

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/macourteau/smb1client/internal/utf16le"
)

// TreeConnectRequest represents an SMB_COM_TREE_CONNECT_ANDX request.
// This command connects to a share on the server.
//
// Request format (AndX command, WordCount = 4):
//
//	Parameters (8 bytes = 4 words):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-6:   Flags (uint16)
//	  6-8:   PasswordLength (uint16)
//	Data:
//	  Password (PasswordLength bytes, usually empty with extended security)
//	  Path (null-terminated string, UNC format: \\server\share)
//	  Service (null-terminated ASCII string, e.g., "?????", "A:", "IPC")
type TreeConnectRequest struct {
	AndXCommand    uint8  // Chained command (usually SMB_COM_NO_ANDX_COMMAND)
	AndXReserved   uint8  // Reserved (must be 0)
	AndXOffset     uint16 // Offset to next command
	Flags          uint16 // Connection flags
	PasswordLength uint16 // Length of password (usually 0 with extended security)
	Password       []byte // Share password (usually empty)
	Path           string // UNC path (e.g., \\server\share)
	Service        string // Service type (e.g., "?????", "A:", "IPC")
	UseUnicode     bool   // Whether to use Unicode strings
}

// TreeConnectResponse represents an SMB_COM_TREE_CONNECT_ANDX response.
//
// Response format (AndX command, WordCount = 3):
//
//	Parameters (6 bytes = 3 words):
//	  0-1:   AndXCommand
//	  1-2:   AndXReserved
//	  2-4:   AndXOffset
//	  4-6:   OptionalSupport (uint16)
//	Data:
//	  Service (null-terminated ASCII string, e.g., "A:", "IPC", "LPT1:")
//	  NativeFileSystem (null-terminated string, e.g., "NTFS", "FAT")
type TreeConnectResponse struct {
	AndXCommand      uint8  // Chained command
	AndXReserved     uint8  // Reserved
	AndXOffset       uint16 // Offset to next command
	OptionalSupport  uint16 // Optional support flags
	Service          string // Service type
	NativeFileSystem string // File system type
}

// TreeDisconnectRequest represents an SMB_COM_TREE_DISCONNECT request.
// This command disconnects from a share. It has no parameters.
type TreeDisconnectRequest struct {
	// No fields - this is an empty request
}

// TreeDisconnectResponse represents an SMB_COM_TREE_DISCONNECT response.
// This response is also empty.
type TreeDisconnectResponse struct {
	// No fields - this is an empty response
}

// TreeConnect flags
const (
	TREE_CONNECT_ANDX_DISCONNECT_TID      uint16 = 0x0001 // Disconnect previous TID
	TREE_CONNECT_ANDX_EXTENDED_SIGNATURES uint16 = 0x0004 // Extended signatures
	TREE_CONNECT_ANDX_EXTENDED_RESPONSE   uint16 = 0x0008 // Extended response
)

// OptionalSupport flags for TreeConnectResponse
const (
	SMB_SUPPORT_SEARCH_BITS uint16 = 0x0001 // Exclusive search bits supported
	SMB_SHARE_IS_IN_DFS     uint16 = 0x0002 // Share is in DFS
	SMB_CSC_MASK            uint16 = 0x000C // Client-side caching mask
	SMB_UNIQUE_FILE_NAME    uint16 = 0x0010 // Server uses unique file names
	SMB_EXTENDED_SIGNATURES uint16 = 0x0020 // Extended signatures supported
)

// Service type strings for TreeConnect
const (
	SERVICE_DISK_SHARE  = "A:"    // Disk share
	SERVICE_PRINT_QUEUE = "LPT1:" // Print queue
	SERVICE_IPC         = "IPC"   // Named pipe
	SERVICE_COMM_DEVICE = "COMM"  // Communications device
	SERVICE_ANY         = "?????" // Wildcard (match any service type)
)

// EncodeTreeConnectRequest encodes an SMB_COM_TREE_CONNECT_ANDX request.
// Returns parameters and data sections.
func EncodeTreeConnectRequest(req *TreeConnectRequest) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: tree connect request is nil")
	}

	if req.Path == "" {
		return nil, nil, fmt.Errorf("smb1: tree connect path is empty")
	}

	// Parameters: 4 words = 8 bytes
	params := make([]byte, 8)

	// AndX header (4 bytes)
	params[0] = req.AndXCommand
	params[1] = req.AndXReserved
	binary.LittleEndian.PutUint16(params[2:4], req.AndXOffset)

	// Tree connect parameters
	binary.LittleEndian.PutUint16(params[4:6], req.Flags)
	binary.LittleEndian.PutUint16(params[6:8], req.PasswordLength)

	// Data section
	var data []byte

	// Password (usually empty with extended security)
	if len(req.Password) > 0 {
		data = append(data, req.Password...)
	}

	// Path (UNC format, e.g., \\server\share)
	if req.UseUnicode {
		// Per impacket: Unicode path starts immediately after password, no padding before
		pathBytes := utf16le.EncodeStringToBytes(req.Path)
		data = append(data, pathBytes...)
		data = append(data, 0, 0) // UTF-16LE null terminator

		// Per impacket's 'u' format: Add padding AFTER null terminators if path length is odd
		// This ensures the service field (which is always ASCII) starts at the correct position
		if len(pathBytes)%2 != 0 {
			data = append(data, 0)
		}
	} else {
		data = append(data, []byte(req.Path)...)
		data = append(data, 0) // ASCII null terminator
	}

	// Service (always ASCII, e.g., "?????", "A:", "IPC")
	data = append(data, []byte(req.Service)...)
	data = append(data, 0) // ASCII null terminator

	return params, data, nil
}

// DecodeTreeConnectResponse decodes an SMB_COM_TREE_CONNECT_ANDX response.
func DecodeTreeConnectResponse(params, data []byte, useUnicode bool) (*TreeConnectResponse, error) {
	// Validate parameters size (should be at least 6 bytes = 3 words)
	if len(params) < 6 {
		return nil, fmt.Errorf("smb1: tree connect response parameters too short: got %d bytes, need at least 6", len(params))
	}

	resp := &TreeConnectResponse{}

	// Parse AndX header
	resp.AndXCommand = params[0]
	resp.AndXReserved = params[1]
	resp.AndXOffset = binary.LittleEndian.Uint16(params[2:4])

	// Parse tree connect response parameters
	resp.OptionalSupport = binary.LittleEndian.Uint16(params[4:6])

	// Parse data section
	offset := 0

	// Service (always ASCII, null-terminated)
	if offset < len(data) {
		serviceEnd := offset
		for serviceEnd < len(data) && data[serviceEnd] != 0 {
			serviceEnd++
		}
		resp.Service = string(data[offset:serviceEnd])
		offset = serviceEnd + 1 // skip null terminator
	}

	// Native file system (may be Unicode or ASCII)
	if useUnicode {
		// Align to word boundary
		if offset < len(data) && offset%2 != 0 {
			offset++
		}

		// UTF-16LE string
		if offset < len(data) {
			fsEnd := offset
			for fsEnd+1 < len(data) {
				if data[fsEnd] == 0 && data[fsEnd+1] == 0 {
					break
				}
				fsEnd += 2
			}
			if fsEnd > offset {
				resp.NativeFileSystem = utf16le.DecodeToString(data[offset:fsEnd])
			}
		}
	} else {
		// ASCII string
		if offset < len(data) {
			fsEnd := offset
			for fsEnd < len(data) && data[fsEnd] != 0 {
				fsEnd++
			}
			resp.NativeFileSystem = string(data[offset:fsEnd])
		}
	}

	return resp, nil
}

// EncodeTreeDisconnectRequest encodes an SMB_COM_TREE_DISCONNECT request.
// This command has no parameters or data.
func EncodeTreeDisconnectRequest() ([]byte, []byte, error) {
	// Empty parameters and data
	return []byte{}, []byte{}, nil
}

// DecodeTreeDisconnectResponse decodes an SMB_COM_TREE_DISCONNECT response.
// This response is empty (WordCount = 0, ByteCount = 0).
func DecodeTreeDisconnectResponse(params, data []byte) (*TreeDisconnectResponse, error) {
	// Validate empty response
	if len(params) != 0 {
		return nil, fmt.Errorf("smb1: tree disconnect response should have no parameters, got %d bytes", len(params))
	}
	if len(data) != 0 {
		return nil, fmt.Errorf("smb1: tree disconnect response should have no data, got %d bytes", len(data))
	}

	return &TreeDisconnectResponse{}, nil
}

// HasChaining returns true if this response chains to another command.
func (r *TreeConnectResponse) HasChaining() bool {
	return r.AndXCommand != SMB_COM_NO_ANDX_COMMAND
}

// IsInDFS returns true if the share is in a DFS namespace.
func (r *TreeConnectResponse) IsInDFS() bool {
	return (r.OptionalSupport & SMB_SHARE_IS_IN_DFS) != 0
}

// SupportsSearchBits returns true if the server supports exclusive search bits.
func (r *TreeConnectResponse) SupportsSearchBits() bool {
	return (r.OptionalSupport & SMB_SUPPORT_SEARCH_BITS) != 0
}

// String returns a human-readable representation of the tree connect response.
func (r *TreeConnectResponse) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("TreeConnectResponse{OptionalSupport:0x%04X ", r.OptionalSupport))
	sb.WriteString(fmt.Sprintf("Service:%q FileSystem:%q", r.Service, r.NativeFileSystem))
	if r.IsInDFS() {
		sb.WriteString(" (DFS)")
	}
	sb.WriteString("}")
	return sb.String()
}
