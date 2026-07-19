package smb1

import (
	"encoding/binary"
	"fmt"

	"github.com/macourteau/smb1client/internal/utf16le"
)

// SetInformationRequest represents a core-protocol SMB_COM_SET_INFORMATION
// request ([MS-CIFS] 2.2.4.6.1). This command sets DOS file attributes and
// optionally the last-write time by path. It predates the TRANS2
// information levels and is the set-attributes path legacy servers accept
// when they reject TRANS2 SET_PATH/FILE_INFORMATION with
// STATUS_NOT_SUPPORTED.
//
// Request format (WordCount = 8):
//
//	Parameters (16 bytes = 8 words):
//	  0-2:   FileAttributes (uint16, DOS attribute bits)
//	  2-6:   LastWriteTime (UTIME: seconds since 1970, server-local; 0 = don't change)
//	  6-16:  Reserved (5 words, must be 0)
//	Data:
//	  BufferFormat (uint8 = 0x04)
//	  FileName (null-terminated string)
//	  BufferFormat2 (uint8 = 0x04)
//	  Reserved (empty ASCII string: single null byte)
//
// The trailing empty buffer comes from the X/Open core protocol definition;
// [MS-CIFS] omits it, but Samba's client has always sent it and servers of
// either persuasion accept it.
type SetInformationRequest struct {
	FileAttributes uint16 // DOS attributes to set (absolute; 0x0000 = normal file)
	LastWriteTime  uint32 // UTIME last-write time; 0 leaves it unchanged
	FileName       string // Path of the file to modify
	UseUnicode     bool   // Whether to use Unicode strings
}

// EncodeSetInformationRequest encodes an SMB_COM_SET_INFORMATION request.
func EncodeSetInformationRequest(req *SetInformationRequest) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: set information request is nil")
	}

	if req.FileName == "" {
		return nil, nil, fmt.Errorf("smb1: file name is empty")
	}

	// Ensure the filename starts with a backslash (required by SMB protocol)
	fileName := req.FileName
	if fileName[0] != '\\' {
		fileName = "\\" + fileName
	}

	// Parameters: 8 words = 16 bytes (FileAttributes + LastWriteTime + 5 reserved words)
	params := make([]byte, 16)
	binary.LittleEndian.PutUint16(params[0:2], req.FileAttributes)
	binary.LittleEndian.PutUint32(params[2:6], req.LastWriteTime)

	// Data section: BufferFormat + FileName
	var data []byte

	// Buffer format indicator (0x04 = null-terminated string)
	data = append(data, 0x04)

	if req.UseUnicode {
		// No padding needed - the data block starts at an odd offset from
		// the SMB header (32 header + 1 word count + 16 params + 2 byte
		// count = 51), so the string following the BufferFormat byte is
		// already aligned at an even offset.
		data = append(data, utf16le.EncodeStringToBytes(fileName)...)
		data = append(data, 0, 0) // Null terminator (2 bytes for Unicode)
	} else {
		data = append(data, []byte(fileName)...)
		data = append(data, 0) // Null terminator
	}

	// Trailing second buffer: BufferFormat 0x04 + empty ASCII string. The
	// X/Open core protocol defines it and Samba's client always sends it;
	// [MS-CIFS] omits it, but legacy servers may require it.
	data = append(data, 0x04, 0x00)

	return params, data, nil
}

// DecodeSetInformationResponse decodes an SMB_COM_SET_INFORMATION response.
// This response is empty (WordCount = 0, ByteCount = 0).
func DecodeSetInformationResponse(params, data []byte) error {
	if len(params) != 0 {
		return fmt.Errorf("smb1: set information response should have no parameters, got %d bytes", len(params))
	}
	return nil
}
