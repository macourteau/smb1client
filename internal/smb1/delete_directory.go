package smb1

import (
	"fmt"

	"github.com/macourteau/smb1client/internal/utf16le"
)

// DeleteDirectoryRequest represents an SMB_COM_DELETE_DIRECTORY request
// ([MS-CIFS] 2.2.4.2.1). The server removes the directory only if it is
// empty and fails with STATUS_DIRECTORY_NOT_EMPTY otherwise.
//
// Request format (WordCount = 0):
//
//	Data:
//	  BufferFormat (uint8 = 0x04)
//	  DirectoryName (null-terminated string)
type DeleteDirectoryRequest struct {
	DirectoryName string // Path of the directory to remove
	UseUnicode    bool   // Whether to use Unicode strings
}

// EncodeDeleteDirectoryRequest encodes an SMB_COM_DELETE_DIRECTORY request.
func EncodeDeleteDirectoryRequest(req *DeleteDirectoryRequest) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: delete directory request is nil")
	}

	if req.DirectoryName == "" {
		return nil, nil, fmt.Errorf("smb1: directory name is empty")
	}

	// Ensure the name starts with a backslash (required by SMB protocol)
	dirName := req.DirectoryName
	if dirName[0] != '\\' {
		dirName = "\\" + dirName
	}

	// Buffer format indicator (0x04 = null-terminated string)
	data := []byte{0x04}

	if req.UseUnicode {
		// No padding needed - the data block starts at an odd offset from
		// the SMB header (32 header + 1 word count + 2 byte count = 35), so
		// the string following the BufferFormat byte is already aligned at
		// an even offset.
		data = append(data, utf16le.EncodeStringToBytes(dirName)...)
		data = append(data, 0, 0) // Null terminator (2 bytes for Unicode)
	} else {
		data = append(data, []byte(dirName)...)
		data = append(data, 0) // Null terminator
	}

	return []byte{}, data, nil
}

// DecodeDeleteDirectoryResponse decodes an SMB_COM_DELETE_DIRECTORY response.
// This response is empty (WordCount = 0, ByteCount = 0).
func DecodeDeleteDirectoryResponse(params, data []byte) error {
	if len(params) != 0 {
		return fmt.Errorf("smb1: delete directory response should have no parameters, got %d bytes", len(params))
	}
	return nil
}
