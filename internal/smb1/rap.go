package smb1

import (
	"encoding/binary"
	"fmt"
)

// RAP (Remote Administration Protocol) constants and structures.
// RAP is a legacy protocol used for administrative operations like
// enumerating shares, users, and sessions on SMB1 servers.
//
// RAP uses the \PIPE\LANMAN named pipe and the SMB_COM_TRANSACTION command.
// It predates MS-RPC/SRVSVC and is more compatible with older SMB1 servers.

// RAP function codes
const (
	RAP_NetShareEnum uint16 = 0x0000 // Enumerate shares
)

// RAP parameter descriptor strings
// These strings describe the format of parameters sent and received.
// Format: SendFormat[RecvFormat]
// W = Word (16-bit)
// r = Receive buffer length (16-bit)
// L = Dword (32-bit)
// e = Entry count (16-bit)
// h = More data available (16-bit)
const (
	// WrLeh: Send W (Level), r (receive buffer length) / Receive L (converter), e (count), h (available)
	ParamDescriptorNetShareEnum = "WrLeh"
	// B13BWz: Data format for NetShareEnum level 1
	// B13 = 13 bytes for share name
	// B = byte (padding/reserved)
	// W = word (share type)
	// z = null-terminated string (comment)
	DataDescriptorNetShareEnumLevel1 = "B13BWz"
)

// NetShareEnumRequest represents a RAP NetShareEnum request.
// This is used to enumerate shares on an SMB1 server.
type NetShareEnumRequest struct {
	InfoLevel  uint16 // Information level (0, 1, or 2)
	ReceiveBuf uint16 // Maximum receive buffer size
}

// NetShareEnumResponse represents a RAP NetShareEnum response.
type NetShareEnumResponse struct {
	Converter  uint16       // Converter for pointer offsets
	EntryCount uint16       // Number of entries returned
	Available  uint16       // Total available entries
	Shares     []ShareInfo1 // Share information (level 1)
}

// ShareInfo1 represents share information at level 1 (most common).
// This provides the share name, type, and comment.
type ShareInfo1 struct {
	Name    string // Share name (max 13 chars for RAP)
	Type    uint16 // Share type
	Comment string // Share comment
}

// Share type constants
const (
	ShareTypeDisk      uint16 = 0x0000 // Disk share
	ShareTypePrintQ    uint16 = 0x0001 // Print queue
	ShareTypeDevice    uint16 = 0x0002 // Communication device
	ShareTypeIPC       uint16 = 0x0003 // IPC share
	ShareTypeTemporary uint16 = 0x4000 // Temporary share (OR'ed with type)
	ShareTypeHidden    uint16 = 0x8000 // Hidden share (OR'ed with type)
)

// EncodeRAPRequest encodes a RAP request into transaction parameters and data.
// The RAP request format is:
//
//	Parameters:
//	  FunctionCode (uint16)
//	  ParamDescriptor (null-terminated string)
//	  DataDescriptor (null-terminated string)
//	  [Function-specific parameters]
//	Data:
//	  [Function-specific data]
func EncodeRAPRequest(functionCode uint16, paramDesc, dataDesc string, params, data []byte) ([]byte, []byte, error) {
	// Calculate sizes
	paramDescBytes := []byte(paramDesc + "\x00")
	dataDescBytes := []byte(dataDesc + "\x00")

	// Build parameters section
	allParams := make([]byte, 0, 2+len(paramDescBytes)+len(dataDescBytes)+len(params))

	// Function code (2 bytes)
	funcCodeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(funcCodeBytes, functionCode)
	allParams = append(allParams, funcCodeBytes...)

	// Parameter descriptor string (null-terminated)
	allParams = append(allParams, paramDescBytes...)

	// Data descriptor string (null-terminated)
	allParams = append(allParams, dataDescBytes...)

	// Function-specific parameters
	allParams = append(allParams, params...)

	return allParams, data, nil
}

// EncodeNetShareEnumRequest encodes a NetShareEnum RAP request.
func EncodeNetShareEnumRequest(req *NetShareEnumRequest) ([]byte, []byte, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("smb1: NetShareEnum request is nil")
	}

	// Build function-specific parameters
	params := make([]byte, 4)
	binary.LittleEndian.PutUint16(params[0:2], req.InfoLevel)
	binary.LittleEndian.PutUint16(params[2:4], req.ReceiveBuf)

	// Select data descriptor based on info level
	var dataDesc string
	switch req.InfoLevel {
	case 1:
		dataDesc = DataDescriptorNetShareEnumLevel1
	default:
		return nil, nil, fmt.Errorf("smb1: unsupported NetShareEnum info level: %d", req.InfoLevel)
	}

	// Encode RAP request
	return EncodeRAPRequest(RAP_NetShareEnum, ParamDescriptorNetShareEnum, dataDesc, params, nil)
}

// DecodeRAPResponse decodes the common RAP response parameters.
// Returns the status code and remaining parameter/data bytes.
func DecodeRAPResponse(params, data []byte) (uint16, []byte, []byte, error) {
	// RAP response format:
	//   Status (uint16) - 0 = success
	//   Converter (uint16) - for pointer offsets
	//   [Function-specific parameters and data]

	if len(params) < 4 {
		return 0, nil, nil, fmt.Errorf("smb1: RAP response too short: got %d bytes, need at least 4", len(params))
	}

	status := binary.LittleEndian.Uint16(params[0:2])
	// Converter at offset 2, but we return remaining params starting from offset 2
	// so the caller can parse it

	return status, params[2:], data, nil
}

// DecodeNetShareEnumResponse decodes a NetShareEnum RAP response.
func DecodeNetShareEnumResponse(params, data []byte, infoLevel uint16) (*NetShareEnumResponse, error) {
	// Response format:
	//   Status (uint16)
	//   Converter (uint16)
	//   EntryCount (uint16)
	//   Available (uint16)
	//   Data (variable) - share entries

	if len(params) < 8 {
		return nil, fmt.Errorf("smb1: NetShareEnum response too short: got %d bytes, need at least 8", len(params))
	}

	// Check status
	status := binary.LittleEndian.Uint16(params[0:2])
	if status != 0 {
		return nil, fmt.Errorf("smb1: NetShareEnum failed with status: %d", status)
	}

	resp := &NetShareEnumResponse{
		Converter:  binary.LittleEndian.Uint16(params[2:4]),
		EntryCount: binary.LittleEndian.Uint16(params[4:6]),
		Available:  binary.LittleEndian.Uint16(params[6:8]),
	}

	// Parse data based on info level
	switch infoLevel {
	case 1:
		shares, err := parseShareInfo1(data, resp.EntryCount, resp.Converter)
		if err != nil {
			return nil, fmt.Errorf("smb1: failed to parse share info: %w", err)
		}
		resp.Shares = shares
	default:
		return nil, fmt.Errorf("smb1: unsupported NetShareEnum info level: %d", infoLevel)
	}

	return resp, nil
}

// parseShareInfo1 parses share information at level 1.
// Level 1 format (per entry):
//
//	ShareName (13 bytes) - fixed-size field, null-padded
//	Padding (1 byte) - alignment
//	Type (uint16) - share type
//	CommentOffset (uint32) - pointer to comment string (needs converter adjustment)
func parseShareInfo1(data []byte, count uint16, converter uint16) ([]ShareInfo1, error) {
	shares := make([]ShareInfo1, 0, count)

	// Each entry is 20 bytes: 13 (name) + 1 (pad) + 2 (type) + 4 (comment offset)
	const entrySize = 20
	offset := 0

	for i := uint16(0); i < count; i++ {
		if offset+entrySize > len(data) {
			return nil, fmt.Errorf("smb1: insufficient data for share entry %d: need %d bytes, got %d", i, offset+entrySize, len(data))
		}

		share := ShareInfo1{}

		// Parse share name (13 bytes, null-padded)
		nameBytes := data[offset : offset+13]
		share.Name = parseNullPaddedString(nameBytes)

		// Skip padding byte at offset+13

		// Parse share type (2 bytes at offset+14)
		share.Type = binary.LittleEndian.Uint16(data[offset+14 : offset+16])

		// Parse comment offset (4 bytes at offset+16)
		// RAP uses 32-bit pointers, but we need to convert them to offsets
		commentPtr := binary.LittleEndian.Uint32(data[offset+16 : offset+20])

		// If comment pointer is non-zero, parse the comment
		if commentPtr != 0 {
			// Convert pointer to data offset
			// The converter value is subtracted from pointers to get actual offsets
			commentOffset := int(commentPtr) - int(converter)

			if commentOffset >= 0 && commentOffset < len(data) {
				// Read null-terminated string at comment offset
				comment, err := parseNullTerminatedString(data[commentOffset:])
				if err == nil {
					share.Comment = comment
				}
			}
		}

		shares = append(shares, share)
		offset += entrySize
	}

	return shares, nil
}

// parseNullPaddedString extracts a string from a null-padded fixed-size field.
func parseNullPaddedString(data []byte) string {
	// Find first null byte
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// parseNullTerminatedString extracts a null-terminated string.
func parseNullTerminatedString(data []byte) (string, error) {
	for i, b := range data {
		if b == 0 {
			return string(data[:i]), nil
		}
	}
	return "", fmt.Errorf("smb1: no null terminator found in string")
}

// EncodeTransactionRequest encodes a TRANSACTION request (not TRANS2).
// This is used for RAP requests via \PIPE\LANMAN.
//
// The transaction request format is similar to TRANS2 but uses a different
// command (SMB_COM_TRANSACTION) and has a Name field for the pipe name.
func EncodeTransactionRequest(name string, params, data []byte) ([]byte, []byte, error) {
	// Calculate sizes
	paramCount := uint16(len(params))
	dataCount := uint16(len(data))

	// Name should be null-terminated ASCII string for pipe name
	nameBytes := []byte(name + "\x00")

	// Calculate offsets (similar to TRANS2)
	// Structure: SMBHeader(32) + WordCount(1) + FixedParams(28) + SetupWords(4) + ByteCount(2) + Name + Padding
	headerAndParamsSize := HeaderSize + 1 + 28 + 4 + 2 + len(nameBytes)

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

	// Encode fixed parameters (14 words = 28 bytes, plus 2 setup words)
	fixedParams := make([]byte, 28)
	binary.LittleEndian.PutUint16(fixedParams[0:2], paramCount)    // TotalParameterCount
	binary.LittleEndian.PutUint16(fixedParams[2:4], dataCount)     // TotalDataCount
	binary.LittleEndian.PutUint16(fixedParams[4:6], 1024)          // MaxParameterCount
	binary.LittleEndian.PutUint16(fixedParams[6:8], 65535)         // MaxDataCount
	fixedParams[8] = 0                                             // MaxSetupCount
	fixedParams[9] = 0                                             // Reserved1
	binary.LittleEndian.PutUint16(fixedParams[10:12], 0)           // Flags
	binary.LittleEndian.PutUint32(fixedParams[12:16], 0)           // Timeout (0 = wait indefinitely)
	binary.LittleEndian.PutUint16(fixedParams[16:18], 0)           // Reserved2
	binary.LittleEndian.PutUint16(fixedParams[18:20], paramCount)  // ParameterCount
	binary.LittleEndian.PutUint16(fixedParams[20:22], paramOffset) // ParameterOffset
	binary.LittleEndian.PutUint16(fixedParams[22:24], dataCount)   // DataCount
	binary.LittleEndian.PutUint16(fixedParams[24:26], dataOffset)  // DataOffset
	fixedParams[26] = 2                                            // SetupCount (2 words for TRANSACTION)
	fixedParams[27] = 0                                            // Reserved3

	// Setup words for TRANSACTION (2 words = 4 bytes)
	// For RAP/LANMAN pipes, setup is typically zero
	setupBytes := make([]byte, 4)
	// Setup[0] = 0 (function code for named pipe transaction)
	// Setup[1] = 0 (priority)

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

// EncodeTransactNamedPipeRequest encodes a TRANSACTION request for TransactNamedPipe (0x0026).
// This is used for RPC operations over named pipes.
// Unlike EncodeTransactionRequest which uses pipe names for RAP, this uses a FID.
func EncodeTransactNamedPipeRequest(fid uint16, data []byte) ([]byte, []byte, error) {
	// Calculate sizes
	paramCount := uint16(0) // No parameters for TransactNamedPipe
	dataCount := uint16(len(data))

	// Calculate offsets (similar to TRANS2)
	// Structure: SMBHeader(32) + WordCount(1) + FixedParams(28) + SetupWords(4) + ByteCount(2) + Data
	// For TransactNamedPipe, there's no name field and no parameters
	baseSize := HeaderSize + 1 + 28 + 4 + 2

	// Data offset is right after the header/params
	// Since there are no parameters, paramOffset is 0 and dataOffset points to start of data
	paramOffset := uint16(0) // No parameters
	dataOffset := uint16(baseSize)

	// Encode fixed parameters (14 words = 28 bytes, plus 2 setup words)
	fixedParams := make([]byte, 28)
	binary.LittleEndian.PutUint16(fixedParams[0:2], paramCount)    // TotalParameterCount
	binary.LittleEndian.PutUint16(fixedParams[2:4], dataCount)     // TotalDataCount
	binary.LittleEndian.PutUint16(fixedParams[4:6], 0)             // MaxParameterCount
	binary.LittleEndian.PutUint16(fixedParams[6:8], 65535)         // MaxDataCount
	fixedParams[8] = 0                                             // MaxSetupCount
	fixedParams[9] = 0                                             // Reserved1
	binary.LittleEndian.PutUint16(fixedParams[10:12], 0)           // Flags
	binary.LittleEndian.PutUint32(fixedParams[12:16], 0)           // Timeout (0 = wait indefinitely)
	binary.LittleEndian.PutUint16(fixedParams[16:18], 0)           // Reserved2
	binary.LittleEndian.PutUint16(fixedParams[18:20], paramCount)  // ParameterCount
	binary.LittleEndian.PutUint16(fixedParams[20:22], paramOffset) // ParameterOffset
	binary.LittleEndian.PutUint16(fixedParams[22:24], dataCount)   // DataCount
	binary.LittleEndian.PutUint16(fixedParams[24:26], dataOffset)  // DataOffset
	fixedParams[26] = 2                                            // SetupCount (2 words for TRANSACTION)
	fixedParams[27] = 0                                            // Reserved3

	// Setup words for TRANSACTION (2 words = 4 bytes)
	// For TransactNamedPipe:
	//   Setup[0] = 0x0026 (TransactNamedPipe function code)
	//   Setup[1] = FID (file ID of the named pipe)
	setupBytes := make([]byte, 4)
	binary.LittleEndian.PutUint16(setupBytes[0:2], 0x0026) // TransactNamedPipe function
	binary.LittleEndian.PutUint16(setupBytes[2:4], fid)    // FID

	// Combine fixed params and setup into parameters section
	allParams := append(fixedParams, setupBytes...)

	// Data section: just the transaction data (no name field for TransactNamedPipe)
	dataSection := data

	return allParams, dataSection, nil
}

// DecodeTransactionResponse decodes a TRANSACTION response (similar to TRANS2).
func DecodeTransactionResponse(paramsBytes, dataBytes []byte) (*Trans2Response, error) {
	// TRANSACTION response has the same structure as TRANS2 response
	// We can reuse the Trans2Response structure and decoder
	return DecodeTrans2Response(paramsBytes, dataBytes)
}
