package smb1

import (
	"encoding/binary"
	"fmt"

	"github.com/macourteau/smb1client/internal/utf16le"
)

// Trans2Request represents a TRANS2 request structure.
// TRANS2 provides extended file system operations like directory listing,
// querying file metadata, and setting file attributes.
//
// Request format (WordCount = 15):
//
//	Parameters (30 bytes = 15 words):
//	  0-2:   TotalParameterCount (uint16)
//	  2-4:   TotalDataCount (uint16)
//	  4-6:   MaxParameterCount (uint16)
//	  6-8:   MaxDataCount (uint16)
//	  8-9:   MaxSetupCount (uint8)
//	  9-10:  Reserved1 (uint8)
//	  10-12: Flags (uint16)
//	  12-16: Timeout (uint32)
//	  16-18: Reserved2 (uint16)
//	  18-20: ParameterCount (uint16)
//	  20-22: ParameterOffset (uint16)
//	  22-24: DataCount (uint16)
//	  24-26: DataOffset (uint16)
//	  26-27: SetupCount (uint8)
//	  27-28: Reserved3 (uint8)
//	  28-30+: Setup (SetupCount * 2 bytes, typically 1-3 words)
//	Data:
//	  ByteCount (uint16)
//	  Name (variable, can be empty)
//	  Pad1 (alignment to word boundary)
//	  Parameters (ParameterCount bytes)
//	  Pad2 (alignment to word boundary)
//	  Data (DataCount bytes)
type Trans2Request struct {
	TotalParameterCount uint16
	TotalDataCount      uint16
	MaxParameterCount   uint16
	MaxDataCount        uint16
	MaxSetupCount       uint8
	Reserved1           uint8
	Flags               uint16
	Timeout             uint32
	Reserved2           uint16
	ParameterCount      uint16
	ParameterOffset     uint16
	DataCount           uint16
	DataOffset          uint16
	SetupCount          uint8
	Reserved3           uint8
	Setup               []uint16
	ByteCount           uint16
	Name                string
	Pad1                []byte
	Parameters          []byte
	Pad2                []byte
	Data                []byte
}

// Trans2Response represents a TRANS2 response structure.
//
// Response format (WordCount = 10):
//
//	Parameters (20 bytes = 10 words):
//	  0-2:   TotalParameterCount (uint16)
//	  2-4:   TotalDataCount (uint16)
//	  4-6:   Reserved (uint16)
//	  6-8:   ParameterCount (uint16)
//	  8-10:  ParameterOffset (uint16)
//	  10-12: ParameterDisplacement (uint16)
//	  12-14: DataCount (uint16)
//	  14-16: DataOffset (uint16)
//	  16-18: DataDisplacement (uint16)
//	  18-19: SetupCount (uint8)
//	  19-20: Reserved2 (uint8)
//	  20+:   Setup (SetupCount * 2 bytes)
//	Data:
//	  ByteCount (uint16)
//	  Pad1 (alignment)
//	  Parameters (ParameterCount bytes)
//	  Pad2 (alignment)
//	  Data (DataCount bytes)
type Trans2Response struct {
	Status                uint32 // NT status code from the SMB header (e.g., STATUS_NO_MORE_FILES)
	TotalParameterCount   uint16
	TotalDataCount        uint16
	Reserved              uint16
	ParameterCount        uint16
	ParameterOffset       uint16
	ParameterDisplacement uint16
	DataCount             uint16
	DataOffset            uint16
	DataDisplacement      uint16
	SetupCount            uint8
	Reserved2             uint8
	Setup                 []uint16
	ByteCount             uint16
	Pad1                  []byte
	Parameters            []byte
	Pad2                  []byte
	Data                  []byte
}

// FindFirst2Request represents a TRANS2_FIND_FIRST2 request.
// This command starts a directory search operation.
type FindFirst2Request struct {
	SearchAttributes  uint16 // Search attributes (hidden, system, etc.)
	SearchCount       uint16 // Maximum entries to return
	Flags             uint16 // Search flags
	InformationLevel  uint16 // Information level to return
	SearchStorageType uint32 // Search storage type (usually 0)
	FileName          string // Search pattern (e.g., "*")
	UseUnicode        bool   // Whether to use Unicode strings
}

// FindFirst2Response represents a TRANS2_FIND_FIRST2 response.
type FindFirst2Response struct {
	SID            uint16                  // Search handle for FIND_NEXT2
	SearchCount    uint16                  // Number of entries returned
	EndOfSearch    uint16                  // 1 if no more entries
	EaErrorOffset  uint16                  // EA error offset
	LastNameOffset uint16                  // Offset of last name in data
	Files          []FileBothDirectoryInfo // File information
}

// FindNext2Request represents a TRANS2_FIND_NEXT2 request.
// This command continues a directory search operation.
type FindNext2Request struct {
	SID              uint16 // Search handle from FIND_FIRST2
	SearchCount      uint16 // Maximum entries to return
	InformationLevel uint16 // Information level to return
	ResumeKey        uint32 // Resume key from previous search
	Flags            uint16 // Search flags
	FileName         string // Search pattern
	UseUnicode       bool   // Whether to use Unicode strings
}

// FindNext2Response represents a TRANS2_FIND_NEXT2 response.
type FindNext2Response struct {
	SearchCount    uint16                  // Number of entries returned
	EndOfSearch    uint16                  // 1 if no more entries
	EaErrorOffset  uint16                  // EA error offset
	LastNameOffset uint16                  // Offset of last name in data
	Files          []FileBothDirectoryInfo // File information
}

// FindClose2Request represents a TRANS2_FIND_CLOSE2 request.
// This command closes a search handle.
type FindClose2Request struct {
	SID uint16 // Search handle to close
}

// QueryPathInfoRequest represents a TRANS2_QUERY_PATH_INFORMATION request.
type QueryPathInfoRequest struct {
	InformationLevel uint16 // Information level to query
	Reserved         uint32 // Reserved (must be 0)
	FileName         string // File path to query
}

// QueryPathInfoResponse represents a TRANS2_QUERY_PATH_INFORMATION response.
type QueryPathInfoResponse struct {
	Data []byte // Information data (format depends on InformationLevel)
}

// QueryFileInfoRequest represents a TRANS2_QUERY_FILE_INFORMATION request.
type QueryFileInfoRequest struct {
	FID              uint16 // File ID to query
	InformationLevel uint16 // Information level to query
}

// QueryFileInfoResponse represents a TRANS2_QUERY_FILE_INFORMATION response.
type QueryFileInfoResponse struct {
	Data []byte // Information data (format depends on InformationLevel)
}

// SetPathInfoRequest represents a TRANS2_SET_PATH_INFORMATION request.
type SetPathInfoRequest struct {
	InformationLevel uint16 // Information level to set
	Reserved         uint32 // Reserved (must be 0)
	FileName         string // File path to modify
	Data             []byte // Information data
}

// SetFileInfoRequest represents a TRANS2_SET_FILE_INFORMATION request.
type SetFileInfoRequest struct {
	FID              uint16 // File ID to modify
	InformationLevel uint16 // Information level to set
	Reserved         uint16 // Reserved (must be 0)
	Data             []byte // Information data
}

// FileBasicInfo represents SMB_QUERY_FILE_BASIC_INFO information.
// This structure contains file timestamps and attributes.
type FileBasicInfo struct {
	CreationTime   uint64 // FILETIME format
	LastAccessTime uint64 // FILETIME format
	LastWriteTime  uint64 // FILETIME format
	ChangeTime     uint64 // FILETIME format
	Attributes     uint32 // File attributes
	Reserved       uint32 // Reserved (must be 0)
}

// FileStandardInfo represents SMB_QUERY_FILE_STANDARD_INFO information.
// This structure contains file size and deletion information.
type FileStandardInfo struct {
	AllocationSize uint64 // Allocated size on disk
	EndOfFile      uint64 // Logical end of file
	NumberOfLinks  uint32 // Number of hard links
	DeletePending  uint8  // 1 if deletion pending
	Directory      uint8  // 1 if directory
	Reserved       uint16 // Reserved (must be 0)
}

// FileBothDirectoryInfo represents file information for FIND_FIRST2/FIND_NEXT2.
// This is the most commonly used information level (SMB_FIND_FILE_BOTH_DIRECTORY_INFO).
type FileBothDirectoryInfo struct {
	NextEntryOffset uint32   // Offset to next entry (0 if last)
	FileIndex       uint32   // File index
	CreationTime    uint64   // FILETIME format
	LastAccessTime  uint64   // FILETIME format
	LastWriteTime   uint64   // FILETIME format
	ChangeTime      uint64   // FILETIME format
	EndOfFile       uint64   // Logical end of file
	AllocationSize  uint64   // Allocated size on disk
	FileAttributes  uint32   // File attributes
	FileNameLength  uint32   // Length of file name in bytes
	EaSize          uint32   // Size of extended attributes
	ShortNameLength uint8    // Length of short name (8.3)
	Reserved        uint8    // Reserved (must be 0)
	ShortName       [24]byte // 8.3 short name (Unicode)
	FileName        string   // Long file name
}

// EncodeTrans2Request encodes a TRANS2 request structure.
// The setup array contains the subcommand code and optional FID.
// The params and data are the subcommand-specific parameters and data.
// The name is typically empty for most TRANS2 commands.
func EncodeTrans2Request(setup []uint16, params, data []byte, name string) ([]byte, []byte, error) {
	if len(setup) == 0 {
		return nil, nil, fmt.Errorf("smb1: setup array cannot be empty")
	}
	if len(setup) > 14 {
		return nil, nil, fmt.Errorf("smb1: setup array too large: %d words (max 14)", len(setup))
	}

	// Calculate sizes
	setupCount := uint8(len(setup))
	paramCount := uint16(len(params))
	dataCount := uint16(len(data))

	// Name is typically empty for TRANS2
	nameBytes := []byte(name)

	// Calculate offsets (relative to start of SMB header, per MS-CIFS spec)
	// Offsets must point to absolute positions from start of SMB header (\xFFSMB)
	// Structure: SMBHeader(32) + WordCount(1) + FixedParams(28) + SetupWords(setupCount*2) + ByteCount(2) + Name + Padding
	headerAndParamsSize := HeaderSize + 1 + 28 + int(setupCount)*2 + 2 + len(nameBytes)

	// Align to word boundary for parameters
	pad1Size := 0
	if headerAndParamsSize%2 != 0 {
		pad1Size = 1
	}

	paramOffset := uint16(headerAndParamsSize + pad1Size)

	// Data starts after parameters with padding
	pad2Size := 0
	if (paramOffset+paramCount)%2 != 0 {
		pad2Size = 1
	}

	dataOffset := paramOffset + paramCount + uint16(pad2Size)

	// Encode fixed parameters (15 words = 30 bytes, but excludes setup)
	fixedParams := make([]byte, 28)
	binary.LittleEndian.PutUint16(fixedParams[0:2], paramCount)    // TotalParameterCount
	binary.LittleEndian.PutUint16(fixedParams[2:4], dataCount)     // TotalDataCount
	binary.LittleEndian.PutUint16(fixedParams[4:6], 1024)          // MaxParameterCount
	binary.LittleEndian.PutUint16(fixedParams[6:8], 65535)         // MaxDataCount
	fixedParams[8] = 0                                             // MaxSetupCount
	fixedParams[9] = 0                                             // Reserved1
	binary.LittleEndian.PutUint16(fixedParams[10:12], 0)           // Flags
	binary.LittleEndian.PutUint32(fixedParams[12:16], 0)           // Timeout
	binary.LittleEndian.PutUint16(fixedParams[16:18], 0)           // Reserved2
	binary.LittleEndian.PutUint16(fixedParams[18:20], paramCount)  // ParameterCount
	binary.LittleEndian.PutUint16(fixedParams[20:22], paramOffset) // ParameterOffset
	binary.LittleEndian.PutUint16(fixedParams[22:24], dataCount)   // DataCount
	binary.LittleEndian.PutUint16(fixedParams[24:26], dataOffset)  // DataOffset
	fixedParams[26] = setupCount                                   // SetupCount
	fixedParams[27] = 0                                            // Reserved3

	// Encode setup words
	setupBytes := make([]byte, len(setup)*2)
	for i, word := range setup {
		binary.LittleEndian.PutUint16(setupBytes[i*2:(i+1)*2], word)
	}

	// Combine fixed params and setup into parameters section
	allParams := append(fixedParams, setupBytes...)

	// Build data section: Name + Pad1 + Parameters + Pad2 + Data
	dataSection := make([]byte, 0, len(nameBytes)+pad1Size+len(params)+pad2Size+len(data))
	dataSection = append(dataSection, nameBytes...)
	for i := 0; i < pad1Size; i++ {
		dataSection = append(dataSection, 0)
	}
	dataSection = append(dataSection, params...)
	for i := 0; i < pad2Size; i++ {
		dataSection = append(dataSection, 0)
	}
	dataSection = append(dataSection, data...)

	return allParams, dataSection, nil
}

// DecodeTrans2Response decodes a TRANS2 response.
func DecodeTrans2Response(paramsBytes, dataBytes []byte) (*Trans2Response, error) {
	resp := &Trans2Response{}

	// Handle empty response (e.g., when WordCount = 0 for STATUS_NO_MORE_FILES)
	if len(paramsBytes) == 0 {
		return resp, nil
	}

	// Validate minimum parameters size (10 words = 20 bytes, excluding setup)
	if len(paramsBytes) < 20 {
		return nil, fmt.Errorf("smb1: trans2 response parameters too short: got %d bytes, need at least 20", len(paramsBytes))
	}

	// Parse fixed parameters (10 words = 20 bytes)
	resp.TotalParameterCount = binary.LittleEndian.Uint16(paramsBytes[0:2])
	resp.TotalDataCount = binary.LittleEndian.Uint16(paramsBytes[2:4])
	resp.Reserved = binary.LittleEndian.Uint16(paramsBytes[4:6])
	resp.ParameterCount = binary.LittleEndian.Uint16(paramsBytes[6:8])
	resp.ParameterOffset = binary.LittleEndian.Uint16(paramsBytes[8:10])
	resp.ParameterDisplacement = binary.LittleEndian.Uint16(paramsBytes[10:12])
	resp.DataCount = binary.LittleEndian.Uint16(paramsBytes[12:14])
	resp.DataOffset = binary.LittleEndian.Uint16(paramsBytes[14:16])
	resp.DataDisplacement = binary.LittleEndian.Uint16(paramsBytes[16:18])
	resp.SetupCount = paramsBytes[18]
	resp.Reserved2 = paramsBytes[19]

	// Parse setup words if present
	if resp.SetupCount > 0 {
		setupSize := int(resp.SetupCount) * 2
		if len(paramsBytes) < 20+setupSize {
			return nil, fmt.Errorf("smb1: trans2 response parameters too short for setup: got %d bytes, need %d",
				len(paramsBytes), 20+setupSize)
		}
		resp.Setup = make([]uint16, resp.SetupCount)
		for i := uint8(0); i < resp.SetupCount; i++ {
			offset := 20 + int(i)*2
			resp.Setup[i] = binary.LittleEndian.Uint16(paramsBytes[offset : offset+2])
		}
	}

	// Parse data section: extract parameters and data
	// The dataBytes does NOT contain the ByteCount field - it's the data after ByteCount
	// ParameterOffset and DataOffset in the TRANS2 response header are absolute offsets
	// from the start of the SMB header. We need to convert them to relative offsets
	// within dataBytes.

	// dataBytes[0] corresponds to absolute offset: HeaderSize + 1 + len(paramsBytes) + 2
	// where +1 is WordCount byte and +2 is ByteCount field
	dataStart := HeaderSize + 1 + len(paramsBytes) + 2

	// Extract parameters using absolute offset
	if resp.ParameterCount > 0 && resp.ParameterOffset > 0 {
		// Convert absolute offset to relative offset within dataBytes
		// dataBytes[0] is at absolute offset dataStart
		// So to access absolute offset X, we use dataBytes[X - dataStart]
		relativeParamOffset := int(resp.ParameterOffset) - dataStart

		if relativeParamOffset >= 0 && relativeParamOffset+int(resp.ParameterCount) <= len(dataBytes) {
			resp.Parameters = make([]byte, resp.ParameterCount)
			copy(resp.Parameters, dataBytes[relativeParamOffset:relativeParamOffset+int(resp.ParameterCount)])
		}
	}

	// Extract data using absolute offset
	if resp.DataCount > 0 && resp.DataOffset > 0 {
		// Convert absolute offset to relative offset within dataBytes
		relativeDataOffset := int(resp.DataOffset) - dataStart

		if relativeDataOffset >= 0 && relativeDataOffset+int(resp.DataCount) <= len(dataBytes) {
			resp.Data = make([]byte, resp.DataCount)
			copy(resp.Data, dataBytes[relativeDataOffset:relativeDataOffset+int(resp.DataCount)])
		}
	}

	return resp, nil
}

// EncodeFindFirst2 encodes a TRANS2_FIND_FIRST2 request parameters.
func EncodeFindFirst2(req *FindFirst2Request) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("smb1: find first2 request is nil")
	}
	if req.FileName == "" {
		return nil, fmt.Errorf("smb1: find first2 filename is empty")
	}

	// Encode filename as Unicode or ASCII with null terminator (SMB_STRING format)
	var nameBytes []byte
	if req.UseUnicode {
		// Unicode: encode as UTF-16LE with Unicode null terminator (0x0000)
		nameBytes = utf16le.EncodeStringToBytes(req.FileName)
		nameBytes = append(nameBytes, 0, 0) // Add Unicode null terminator
	} else {
		// ASCII: null-terminated string
		nameBytes = []byte(req.FileName + "\x00")
	}

	// Parameters: SearchAttributes(2) + SearchCount(2) + Flags(2) + InformationLevel(2) + SearchStorageType(4) + FileName
	params := make([]byte, 12+len(nameBytes))

	binary.LittleEndian.PutUint16(params[0:2], req.SearchAttributes)
	binary.LittleEndian.PutUint16(params[2:4], req.SearchCount)
	binary.LittleEndian.PutUint16(params[4:6], req.Flags)
	binary.LittleEndian.PutUint16(params[6:8], req.InformationLevel)
	binary.LittleEndian.PutUint32(params[8:12], req.SearchStorageType)
	copy(params[12:], nameBytes)

	return params, nil
}

// DecodeFindFirst2Response decodes a TRANS2_FIND_FIRST2 response.
func DecodeFindFirst2Response(params, data []byte, infoLevel uint16) (*FindFirst2Response, error) {
	// Validate parameters size (should be at least 10 bytes)
	if len(params) < 10 {
		return nil, fmt.Errorf("smb1: find first2 response parameters too short: got %d bytes, need at least 10", len(params))
	}

	resp := &FindFirst2Response{}
	resp.SID = binary.LittleEndian.Uint16(params[0:2])
	resp.SearchCount = binary.LittleEndian.Uint16(params[2:4])
	resp.EndOfSearch = binary.LittleEndian.Uint16(params[4:6])
	resp.EaErrorOffset = binary.LittleEndian.Uint16(params[6:8])
	resp.LastNameOffset = binary.LittleEndian.Uint16(params[8:10])

	// Parse file entries based on information level
	if infoLevel == SMB_FIND_FILE_BOTH_DIRECTORY_INFO && len(data) > 0 {
		result, err := ParseFileBothDirectoryInfo(data)
		if err != nil {
			return nil, fmt.Errorf("smb1: failed to parse file entries: %w", err)
		}
		resp.Files = result.Files

		// A truncated parse means the reply's own bytes ended mid-entry. The
		// transport reassembles replies the server splits across messages, so
		// reaching here means the data is malformed. Returning the short list
		// would drop directory entries with nothing to tell the caller apart
		// from a genuinely small directory.
		if result.Truncated {
			return nil, fmt.Errorf("smb1: find first2 response truncated after %d entries", len(result.Files))
		}
	}

	return resp, nil
}

// EncodeFindNext2 encodes a TRANS2_FIND_NEXT2 request parameters.
func EncodeFindNext2(req *FindNext2Request) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("smb1: find next2 request is nil")
	}

	// Encode filename as Unicode or ASCII with null terminator (SMB_STRING format)
	var nameBytes []byte
	if req.UseUnicode {
		// Unicode: encode as UTF-16LE with Unicode null terminator (0x0000)
		nameBytes = utf16le.EncodeStringToBytes(req.FileName)
		nameBytes = append(nameBytes, 0, 0) // Add Unicode null terminator
	} else {
		// ASCII: null-terminated string
		nameBytes = []byte(req.FileName + "\x00")
	}

	// Parameters: SID(2) + SearchCount(2) + InformationLevel(2) + ResumeKey(4) + Flags(2) + FileName
	params := make([]byte, 12+len(nameBytes))

	binary.LittleEndian.PutUint16(params[0:2], req.SID)
	binary.LittleEndian.PutUint16(params[2:4], req.SearchCount)
	binary.LittleEndian.PutUint16(params[4:6], req.InformationLevel)
	binary.LittleEndian.PutUint32(params[6:10], req.ResumeKey)
	binary.LittleEndian.PutUint16(params[10:12], req.Flags)
	copy(params[12:], nameBytes)

	return params, nil
}

// DecodeFindNext2Response decodes a TRANS2_FIND_NEXT2 response.
func DecodeFindNext2Response(params, data []byte, infoLevel uint16) (*FindNext2Response, error) {
	resp := &FindNext2Response{}

	// Handle empty response (e.g., when STATUS_NO_MORE_FILES and no data to return)
	if len(params) == 0 {
		resp.EndOfSearch = 1 // Mark as end of search
		return resp, nil
	}

	// Validate parameters size (should be at least 8 bytes)
	if len(params) < 8 {
		return nil, fmt.Errorf("smb1: find next2 response parameters too short: got %d bytes, need at least 8", len(params))
	}

	resp.SearchCount = binary.LittleEndian.Uint16(params[0:2])
	resp.EndOfSearch = binary.LittleEndian.Uint16(params[2:4])
	resp.EaErrorOffset = binary.LittleEndian.Uint16(params[4:6])
	resp.LastNameOffset = binary.LittleEndian.Uint16(params[6:8])

	// Parse file entries based on information level
	if infoLevel == SMB_FIND_FILE_BOTH_DIRECTORY_INFO && len(data) > 0 {
		result, err := ParseFileBothDirectoryInfo(data)
		if err != nil {
			return nil, fmt.Errorf("smb1: failed to parse file entries: %w", err)
		}
		resp.Files = result.Files

		// See DecodeFindFirst2Response: a truncated parse is malformed data,
		// not a size limit, and must not be reported as a short listing.
		if result.Truncated {
			return nil, fmt.Errorf("smb1: find next2 response truncated after %d entries", len(result.Files))
		}
	}

	return resp, nil
}

// EncodeFindClose2 encodes TRANS2_FIND_CLOSE2 request parameters.
func EncodeFindClose2(sid uint16) ([]byte, error) {
	params := make([]byte, 2)
	binary.LittleEndian.PutUint16(params[0:2], sid)
	return params, nil
}

// EncodeQueryPathInfo encodes TRANS2_QUERY_PATH_INFORMATION request parameters.
func EncodeQueryPathInfo(fileName string, infoLevel uint16, useUnicode bool) ([]byte, error) {
	if fileName == "" {
		return nil, fmt.Errorf("smb1: query path info filename is empty")
	}

	// Encode filename as Unicode or ASCII with null terminator
	var nameBytes []byte
	if useUnicode {
		// Unicode: encode as UTF-16LE with Unicode null terminator (0x0000)
		nameBytes = utf16le.EncodeStringToBytes(fileName)
		nameBytes = append(nameBytes, 0, 0) // Add Unicode null terminator
	} else {
		// ASCII: null-terminated string
		nameBytes = []byte(fileName + "\x00")
	}

	// Parameters: InformationLevel(2) + Reserved(4) + FileName
	params := make([]byte, 6+len(nameBytes))

	binary.LittleEndian.PutUint16(params[0:2], infoLevel)
	// Reserved bytes 2-6 are already zero
	copy(params[6:], nameBytes)

	return params, nil
}

// DecodeQueryPathInfoResponse decodes TRANS2_QUERY_PATH_INFORMATION response data.
func DecodeQueryPathInfoResponse(data []byte, infoLevel uint16) (interface{}, error) {
	switch infoLevel {
	case SMB_QUERY_FILE_BASIC_INFO:
		return DecodeFileBasicInfo(data)
	case SMB_QUERY_FILE_STANDARD_INFO:
		return DecodeFileStandardInfo(data)
	default:
		// For unsupported info levels, return raw data
		return data, nil
	}
}

// EncodeQueryFileInfo encodes TRANS2_QUERY_FILE_INFORMATION request parameters.
func EncodeQueryFileInfo(fid uint16, infoLevel uint16) ([]byte, error) {
	// Parameters: FID(2) + InformationLevel(2)
	params := make([]byte, 4)
	binary.LittleEndian.PutUint16(params[0:2], fid)
	binary.LittleEndian.PutUint16(params[2:4], infoLevel)
	return params, nil
}

// DecodeQueryFileInfoResponse decodes TRANS2_QUERY_FILE_INFORMATION response data.
func DecodeQueryFileInfoResponse(data []byte, infoLevel uint16) (interface{}, error) {
	// Same decoding as QueryPathInfo
	return DecodeQueryPathInfoResponse(data, infoLevel)
}

// EncodeSetPathInfo encodes TRANS2_SET_PATH_INFORMATION request.
func EncodeSetPathInfo(fileName string, infoLevel uint16, data []byte, useUnicode bool) ([]byte, []byte, error) {
	if fileName == "" {
		return nil, nil, fmt.Errorf("smb1: set path info filename is empty")
	}

	// Encode filename as Unicode or ASCII with null terminator, matching the
	// session's negotiated capability the same way EncodeQueryPathInfo does —
	// a Unicode server reads an ASCII-encoded name as garbage UTF-16.
	var nameBytes []byte
	if useUnicode {
		nameBytes = utf16le.EncodeStringToBytes(fileName)
		nameBytes = append(nameBytes, 0, 0) // Add Unicode null terminator
	} else {
		nameBytes = []byte(fileName + "\x00")
	}

	// Parameters: InformationLevel(2) + Reserved(4) + FileName
	params := make([]byte, 6+len(nameBytes))

	binary.LittleEndian.PutUint16(params[0:2], infoLevel)
	// Reserved bytes 2-6 are already zero
	copy(params[6:], nameBytes)

	return params, data, nil
}

// EncodeSetFileInfo encodes TRANS2_SET_FILE_INFORMATION request.
func EncodeSetFileInfo(fid uint16, infoLevel uint16, data []byte) ([]byte, []byte, error) {
	// Parameters: FID(2) + InformationLevel(2) + Reserved(2)
	params := make([]byte, 6)
	binary.LittleEndian.PutUint16(params[0:2], fid)
	binary.LittleEndian.PutUint16(params[2:4], infoLevel)
	// Reserved bytes 4-6 are already zero

	return params, data, nil
}

// ParseFileBothDirectoryInfoResult contains the result of parsing directory information.
type ParseFileBothDirectoryInfoResult struct {
	Files     []FileBothDirectoryInfo // Successfully parsed files
	Truncated bool                    // True if parsing stopped due to truncated data
}

// ParseFileBothDirectoryInfo parses a sequence of FileBothDirectoryInfo structures.
// These structures are chained using NextEntryOffset.
// Returns a result containing the parsed files and a truncation flag.
func ParseFileBothDirectoryInfo(data []byte) (*ParseFileBothDirectoryInfoResult, error) {
	result := &ParseFileBothDirectoryInfoResult{
		Files:     make([]FileBothDirectoryInfo, 0),
		Truncated: false,
	}
	offset := 0

	for offset < len(data) {
		// Need at least 94 bytes for the fixed part of the structure. Fewer
		// than that left means the previous entry chained to an entry the
		// reply does not actually carry, so the data is short.
		if len(data)-offset < 94 {
			result.Truncated = true
			break
		}

		var file FileBothDirectoryInfo

		file.NextEntryOffset = binary.LittleEndian.Uint32(data[offset : offset+4])
		file.FileIndex = binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		file.CreationTime = binary.LittleEndian.Uint64(data[offset+8 : offset+16])
		file.LastAccessTime = binary.LittleEndian.Uint64(data[offset+16 : offset+24])
		file.LastWriteTime = binary.LittleEndian.Uint64(data[offset+24 : offset+32])
		file.ChangeTime = binary.LittleEndian.Uint64(data[offset+32 : offset+40])
		file.EndOfFile = binary.LittleEndian.Uint64(data[offset+40 : offset+48])
		file.AllocationSize = binary.LittleEndian.Uint64(data[offset+48 : offset+56])
		file.FileAttributes = binary.LittleEndian.Uint32(data[offset+56 : offset+60])
		file.FileNameLength = binary.LittleEndian.Uint32(data[offset+60 : offset+64])
		file.EaSize = binary.LittleEndian.Uint32(data[offset+64 : offset+68])
		file.ShortNameLength = data[offset+68]
		file.Reserved = data[offset+69]
		copy(file.ShortName[:], data[offset+70:offset+94])

		// Parse file name (Unicode)
		nameStart := offset + 94
		nameEnd := nameStart + int(file.FileNameLength)
		if nameEnd > len(data) {
			// Filename extends beyond available data - this means the response was truncated.
			// This can happen when the server reaches the maximum data count.
			// Mark as truncated and stop parsing here - the caller will use FIND_NEXT2 to get the rest.
			result.Truncated = true
			break
		}

		if file.FileNameLength > 0 {
			file.FileName = utf16le.DecodeToString(data[nameStart:nameEnd])
		}

		result.Files = append(result.Files, file)

		// Move to next entry
		if file.NextEntryOffset == 0 {
			break // Last entry
		}
		offset += int(file.NextEntryOffset)
	}

	return result, nil
}

// EncodeFileBasicInfo encodes FileBasicInfo structure.
func EncodeFileBasicInfo(info *FileBasicInfo) []byte {
	data := make([]byte, 40)
	binary.LittleEndian.PutUint64(data[0:8], info.CreationTime)
	binary.LittleEndian.PutUint64(data[8:16], info.LastAccessTime)
	binary.LittleEndian.PutUint64(data[16:24], info.LastWriteTime)
	binary.LittleEndian.PutUint64(data[24:32], info.ChangeTime)
	binary.LittleEndian.PutUint32(data[32:36], info.Attributes)
	binary.LittleEndian.PutUint32(data[36:40], info.Reserved)
	return data
}

// DecodeFileBasicInfo decodes FileBasicInfo structure.
func DecodeFileBasicInfo(data []byte) (*FileBasicInfo, error) {
	// FILE_BASIC_INFO is typically 40 bytes, but some servers omit the 4-byte Reserved field
	if len(data) < 36 {
		return nil, fmt.Errorf("smb1: file basic info data too short: got %d bytes, need at least 36", len(data))
	}

	info := &FileBasicInfo{
		CreationTime:   binary.LittleEndian.Uint64(data[0:8]),
		LastAccessTime: binary.LittleEndian.Uint64(data[8:16]),
		LastWriteTime:  binary.LittleEndian.Uint64(data[16:24]),
		ChangeTime:     binary.LittleEndian.Uint64(data[24:32]),
		Attributes:     binary.LittleEndian.Uint32(data[32:36]),
	}

	// Reserved field is optional - some servers omit it
	if len(data) >= 40 {
		info.Reserved = binary.LittleEndian.Uint32(data[36:40])
	}

	return info, nil
}

// EncodeFileStandardInfo encodes FileStandardInfo structure.
func EncodeFileStandardInfo(info *FileStandardInfo) []byte {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint64(data[0:8], info.AllocationSize)
	binary.LittleEndian.PutUint64(data[8:16], info.EndOfFile)
	binary.LittleEndian.PutUint32(data[16:20], info.NumberOfLinks)
	data[20] = info.DeletePending
	data[21] = info.Directory
	binary.LittleEndian.PutUint16(data[22:24], info.Reserved)
	return data
}

// DecodeFileStandardInfo decodes FileStandardInfo structure.
func DecodeFileStandardInfo(data []byte) (*FileStandardInfo, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("smb1: file standard info data too short: got %d bytes, need 24", len(data))
	}

	info := &FileStandardInfo{
		AllocationSize: binary.LittleEndian.Uint64(data[0:8]),
		EndOfFile:      binary.LittleEndian.Uint64(data[8:16]),
		NumberOfLinks:  binary.LittleEndian.Uint32(data[16:20]),
		DeletePending:  data[20],
		Directory:      data[21],
		Reserved:       binary.LittleEndian.Uint16(data[22:24]),
	}

	return info, nil
}

// FsSizeInfo represents SMB_QUERY_FS_SIZE_INFO information.
// Allocation-unit counts are 64-bit, so this level describes volumes of any
// practical size.
type FsSizeInfo struct {
	TotalAllocationUnits     uint64 // Total allocation units on the volume
	TotalFreeAllocationUnits uint64 // Allocation units still free
	SectorsPerAllocationUnit uint32 // Sectors making up one allocation unit
	BytesPerSector           uint32 // Bytes per sector
}

// FsAllocationInfo represents SMB_INFO_ALLOCATION information — the legacy
// counterpart of FsSizeInfo. Its counts are 32-bit and therefore saturate on
// large volumes, but old and embedded servers may support only this level.
type FsAllocationInfo struct {
	FileSystemID             uint32 // File system identifier (often 0; not meaningful)
	SectorsPerAllocationUnit uint32 // Sectors making up one allocation unit
	TotalAllocationUnits     uint32 // Total allocation units on the volume
	FreeAllocationUnits      uint32 // Allocation units still free
	BytesPerSector           uint16 // Bytes per sector
}

// FsVolumeInfo represents SMB_QUERY_FS_VOLUME_INFO information.
// The serial number identifies the mounted volume without writing to it.
type FsVolumeInfo struct {
	VolumeCreationTime uint64 // FILETIME format
	SerialNumber       uint32 // Volume serial number
	Label              string // Volume label
}

// EncodeQueryFSInfo encodes the parameters for a TRANS2_QUERY_FS_INFORMATION
// request. The query is scoped to the tree the request is sent on — unlike the
// file and path levels, it takes no FID and no path.
func EncodeQueryFSInfo(infoLevel uint16) ([]byte, error) {
	// Parameters: InformationLevel(2)
	params := make([]byte, 2)
	binary.LittleEndian.PutUint16(params[0:2], infoLevel)
	return params, nil
}

// DecodeFsSizeInfo decodes an SMB_QUERY_FS_SIZE_INFO response.
func DecodeFsSizeInfo(data []byte) (*FsSizeInfo, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("smb1: fs size info data too short: got %d bytes, need 24", len(data))
	}

	return &FsSizeInfo{
		TotalAllocationUnits:     binary.LittleEndian.Uint64(data[0:8]),
		TotalFreeAllocationUnits: binary.LittleEndian.Uint64(data[8:16]),
		SectorsPerAllocationUnit: binary.LittleEndian.Uint32(data[16:20]),
		BytesPerSector:           binary.LittleEndian.Uint32(data[20:24]),
	}, nil
}

// DecodeFsAllocationInfo decodes an SMB_INFO_ALLOCATION response.
func DecodeFsAllocationInfo(data []byte) (*FsAllocationInfo, error) {
	if len(data) < 18 {
		return nil, fmt.Errorf("smb1: fs allocation info data too short: got %d bytes, need 18", len(data))
	}

	return &FsAllocationInfo{
		FileSystemID:             binary.LittleEndian.Uint32(data[0:4]),
		SectorsPerAllocationUnit: binary.LittleEndian.Uint32(data[4:8]),
		TotalAllocationUnits:     binary.LittleEndian.Uint32(data[8:12]),
		FreeAllocationUnits:      binary.LittleEndian.Uint32(data[12:16]),
		BytesPerSector:           binary.LittleEndian.Uint16(data[16:18]),
	}, nil
}

// DecodeFsVolumeInfo decodes an SMB_QUERY_FS_VOLUME_INFO response.
// A label that is absent or truncated by the server is not an error: the
// serial number is the useful field and is fully present without it.
func DecodeFsVolumeInfo(data []byte) (*FsVolumeInfo, error) {
	// VolumeCreationTime(8) + SerialNumber(4) + LabelLength(4) + Reserved(2)
	const headerLen = 18
	if len(data) < headerLen {
		return nil, fmt.Errorf("smb1: fs volume info data too short: got %d bytes, need %d", len(data), headerLen)
	}

	info := &FsVolumeInfo{
		VolumeCreationTime: binary.LittleEndian.Uint64(data[0:8]),
		SerialNumber:       binary.LittleEndian.Uint32(data[8:12]),
	}

	// The label length is server-supplied and counts bytes, not characters.
	// Clamp it to what actually arrived rather than trusting it to index.
	labelLen := int(binary.LittleEndian.Uint32(data[12:16]))
	available := len(data) - headerLen
	if labelLen > available {
		labelLen = available
	}
	if labelLen > 0 {
		info.Label = utf16le.DecodeToString(data[headerLen : headerLen+labelLen])
	}

	return info, nil
}

// IsDirectory returns true if the file is a directory.
func (f *FileBothDirectoryInfo) IsDirectory() bool {
	return (f.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
}

// IsHidden returns true if the file is hidden.
func (f *FileBothDirectoryInfo) IsHidden() bool {
	return (f.FileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0
}

// IsSystem returns true if the file is a system file.
func (f *FileBothDirectoryInfo) IsSystem() bool {
	return (f.FileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0
}
