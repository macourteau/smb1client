package smb1

import (
	"encoding/binary"
	"fmt"

	"github.com/macourteau/smb1client/internal/utf16le"
)

// RenameRequest represents an SMB_COM_RENAME request.
// This command renames or moves a file or directory.
//
// Request format (WordCount = 1):
//
//	Parameters (2 bytes = 1 word):
//	  0-2:  SearchAttributes (uint16)
//	Data:
//	  BufferFormat1 (uint8 = 0x04)
//	  OldFileName (null-terminated string)
//	  BufferFormat2 (uint8 = 0x04)
//	  NewFileName (null-terminated string)
type RenameRequest struct {
	SearchAttributes uint16 // Search attributes for files to rename
	OldFileName      string // Old file name or pattern
	NewFileName      string // New file name
	UseUnicode       bool   // Whether to use Unicode strings
}

// RenameResponse represents an SMB_COM_RENAME response.
// This response is empty (WordCount = 0, ByteCount = 0).
type RenameResponse struct {
	// No fields - this is an empty response
}

// EncodeRenameRequest encodes an SMB_COM_RENAME request.
func EncodeRenameRequest(req *RenameRequest) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: rename request is nil")
	}

	if req.OldFileName == "" {
		return nil, nil, fmt.Errorf("smb1: old file name is empty")
	}

	if req.NewFileName == "" {
		return nil, nil, fmt.Errorf("smb1: new file name is empty")
	}

	// Ensure filenames start with backslash (required by SMB protocol)
	oldFileName := req.OldFileName
	if oldFileName[0] != '\\' {
		oldFileName = "\\" + oldFileName
	}
	newFileName := req.NewFileName
	if newFileName[0] != '\\' {
		newFileName = "\\" + newFileName
	}

	// Parameters: 1 word = 2 bytes
	params := make([]byte, 2)
	binary.LittleEndian.PutUint16(params[0:2], req.SearchAttributes)

	// Data section: BufferFormat1 + OldFileName + BufferFormat2 + NewFileName
	var data []byte

	// Buffer format indicator for old filename (0x04 = ASCII string)
	data = append(data, 0x04)

	if req.UseUnicode {
		// No padding needed - OldFileName is already aligned at even offset
		oldBytes := utf16le.EncodeStringToBytes(oldFileName)
		data = append(data, oldBytes...)
		data = append(data, 0, 0) // Null terminator (2 bytes for Unicode)
	} else {
		data = append(data, []byte(oldFileName)...)
		data = append(data, 0) // Null terminator
	}

	// Buffer format indicator for new filename (0x04 = ASCII string)
	data = append(data, 0x04)

	if req.UseUnicode {
		// Always add padding byte to align NewFileName to word boundary
		data = append(data, 0)
		newBytes := utf16le.EncodeStringToBytes(newFileName)
		data = append(data, newBytes...)
		data = append(data, 0, 0) // Null terminator (2 bytes for Unicode)
	} else {
		data = append(data, []byte(newFileName)...)
		data = append(data, 0) // Null terminator
	}

	return params, data, nil
}

// DecodeRenameResponse decodes an SMB_COM_RENAME response.
// This response is empty (WordCount = 0, ByteCount = 0).
func DecodeRenameResponse(params, data []byte) (*RenameResponse, error) {
	// Validate empty response
	if len(params) != 0 {
		return nil, fmt.Errorf("smb1: rename response should have no parameters, got %d bytes", len(params))
	}

	return &RenameResponse{}, nil
}
