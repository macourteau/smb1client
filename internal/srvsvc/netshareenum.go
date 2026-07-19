package srvsvc

import (
	"fmt"

	"github.com/macourteau/smb1client/internal/dcerpc"
)

// EncodeNetShareEnumAllRequest encodes a NetShareEnumAll RPC request.
// This function creates the NDR-encoded request body for the NetShareEnumAll operation.
//
// The NetShareEnumAll request structure (MS-SRVS 3.1.4.8):
//  1. ServerName: pointer to UNC server name (e.g., "\\198.51.100.2")
//  2. Level: info level (1 for SHARE_INFO_1)
//  3. InfoStruct: SHARE_ENUM_STRUCT containing:
//     - Level: same as above
//     - ShareInfo union (switched on Level):
//     - ShareInfo1: SHARE_INFO_1_CONTAINER
//     - EntriesRead: 0 (input value)
//     - Buffer: null pointer
//  4. PrefMaxLen: preferred maximum length (0xFFFFFFFF = unlimited)
//  5. ResumeHandle: pointer to resume handle (0 for first call)
//
// Parameters:
//   - serverName: Server name or IP address (will be converted to UNC format)
//
// Returns the NDR-encoded request body (stub data).
func EncodeNetShareEnumAllRequest(serverName string) []byte {
	buf := make([]byte, 0, 256)

	// Convert server name to UNC format
	uncName := serverName
	if len(serverName) > 0 && serverName[0] != '\\' {
		uncName = "\\\\" + serverName
	} else if len(serverName) > 1 && serverName[0] == '\\' && serverName[1] != '\\' {
		uncName = "\\" + serverName
	}

	// Prepare server name string data (for deferred section)
	serverNameString := dcerpc.MarshalConformantVaryingString(uncName)

	// 1. Server name pointer (referent ID: 0x00020000)
	buf = append(buf, dcerpc.MarshalUint32(0x00020000)...)

	// CRITICAL: In NDR, top-level [in] pointer parameters must have their deferred
	// data appear immediately after the referent ID, before other parameters.
	// This is different from pointers embedded in structures.
	//
	// Server name string (pointed to by referent ID 0x00020000)
	buf = append(buf, serverNameString...)

	// Align to 4-byte boundary after the string
	// Conformant varying strings include: MaxCount(4) + Offset(4) + ActualCount(4) + chars
	// The character data may not end on a 4-byte boundary, so we need padding
	buf = dcerpc.Pad(buf, dcerpc.Align4)

	// 2. Level (uint32): 1 for SHARE_INFO_1
	buf = append(buf, dcerpc.MarshalUint32(1)...)

	// 3. InfoStruct: SHARE_ENUM_STRUCT
	//    - Level (uint32): 1
	buf = append(buf, dcerpc.MarshalUint32(1)...)

	//    - ShareInfo union (switched on Level)
	//      For Level 1, this is a SHARE_INFO_1_CONTAINER
	//      - Container pointer (referent ID: 0x00020004)
	buf = append(buf, dcerpc.MarshalUint32(0x00020004)...)

	//      - Container data (deferred):
	//        - EntriesRead (uint32): 0
	buf = append(buf, dcerpc.MarshalUint32(0)...)

	//        - Buffer pointer: null (0x00000000)
	buf = append(buf, dcerpc.MarshalUint32(0)...)

	// 4. PrefMaxLen (uint32): 0xFFFFFFFF (unlimited)
	buf = append(buf, dcerpc.MarshalUint32(0xFFFFFFFF)...)

	// 5. ResumeHandle pointer (referent ID: 0x00020008)
	buf = append(buf, dcerpc.MarshalUint32(0x00020008)...)

	// DEFERRED DATA SECTION (for embedded pointers)
	// ResumeHandle value (pointed to by referent ID 0x00020008): 0
	buf = append(buf, dcerpc.MarshalUint32(0)...)

	return buf
}

// DecodeNetShareEnumAllResponse decodes a NetShareEnumAll RPC response.
// This function parses the NDR-encoded response body from the NetShareEnumAll operation.
//
// The NetShareEnumAll response structure (MS-SRVS 3.1.4.8):
//  1. Level: info level (should match request)
//  2. InfoStruct: SHARE_ENUM_STRUCT containing:
//     - Level: same as above
//     - ShareInfo union (switched on Level):
//     - ShareInfo1: SHARE_INFO_1_CONTAINER
//     - EntriesRead: number of shares returned
//     - Buffer: pointer to array of SHARE_INFO_1
//  3. TotalEntries: total number of shares available
//  4. ResumeHandle: pointer to resume handle (for continuation)
//  5. Return code: Windows error code (0 = success)
//
// Parameters:
//   - data: NDR-encoded response body
//
// Returns the list of shares and any error encountered.
func DecodeNetShareEnumAllResponse(data []byte) ([]ShareInfo1, error) {
	offset := 0

	// 1. Level (uint32)
	if len(data) < offset+4 {
		return nil, fmt.Errorf("srvsvc: response too short for level field")
	}
	level := dcerpc.UnmarshalUint32(data[offset : offset+4])
	offset += 4

	if level != 1 {
		return nil, fmt.Errorf("srvsvc: unsupported info level: %d", level)
	}

	// 2. InfoStruct: SHARE_ENUM_STRUCT
	//    - Level (uint32) - should match above
	if len(data) < offset+4 {
		return nil, fmt.Errorf("srvsvc: response too short for infostruct level")
	}
	infoLevel := dcerpc.UnmarshalUint32(data[offset : offset+4])
	offset += 4

	if infoLevel != level {
		return nil, fmt.Errorf("srvsvc: level mismatch: top=%d, infostruct=%d", level, infoLevel)
	}

	//    - ShareInfo union switch (based on level)
	//      For level 1: SHARE_INFO_1_CONTAINER pointer
	containerPtr, err := dcerpc.UnmarshalPointer(data, &offset)
	if err != nil {
		return nil, fmt.Errorf("srvsvc: failed to read container pointer: %w", err)
	}

	var shares []ShareInfo1
	var entriesRead uint32

	if containerPtr != 0 {
		//      - Container data (pointed to):
		//        - EntriesRead (uint32)
		if len(data) < offset+4 {
			return nil, fmt.Errorf("srvsvc: response too short for entries read")
		}
		entriesRead = dcerpc.UnmarshalUint32(data[offset : offset+4])
		offset += 4

		//        - Buffer pointer (to array of SHARE_INFO_1)
		bufferPtr, err := dcerpc.UnmarshalPointer(data, &offset)
		if err != nil {
			return nil, fmt.Errorf("srvsvc: failed to read buffer pointer: %w", err)
		}

		if bufferPtr != 0 && entriesRead > 0 {
			// Parse array of SHARE_INFO_1 structures
			shares, err = DecodeShareInfo1Array(data, &offset, entriesRead)
			if err != nil {
				return nil, fmt.Errorf("srvsvc: failed to decode share array: %w", err)
			}
		} else {
			shares = []ShareInfo1{}
		}
	} else {
		// Null container pointer means no shares
		shares = []ShareInfo1{}
		entriesRead = 0
	}

	// 3. TotalEntries (uint32)
	if len(data) < offset+4 {
		return nil, fmt.Errorf("srvsvc: response too short for total entries")
	}
	totalEntries := dcerpc.UnmarshalUint32(data[offset : offset+4])
	offset += 4

	// Validate that totalEntries makes sense
	if totalEntries < entriesRead {
		return nil, fmt.Errorf("srvsvc: invalid response: totalEntries=%d < entriesRead=%d", totalEntries, entriesRead)
	}

	// 4. ResumeHandle pointer (optional)
	resumeHandlePtr, err := dcerpc.UnmarshalPointer(data, &offset)
	if err != nil {
		return nil, fmt.Errorf("srvsvc: failed to read resume handle pointer: %w", err)
	}

	if resumeHandlePtr != 0 {
		// Read resume handle value (we don't use it currently)
		if len(data) < offset+4 {
			return nil, fmt.Errorf("srvsvc: response too short for resume handle")
		}
		// resumeHandle := dcerpc.UnmarshalUint32(data[offset : offset+4])
		offset += 4
	}

	// 5. Return code (uint32)
	if len(data) < offset+4 {
		return nil, fmt.Errorf("srvsvc: response too short for return code")
	}
	returnCode := dcerpc.UnmarshalUint32(data[offset : offset+4])
	// offset += 4 // Not needed as this is the last field

	// Check return code
	if returnCode != 0 {
		return nil, fmt.Errorf("srvsvc: NetShareEnumAll failed with error code: 0x%08x", returnCode)
	}

	return shares, nil
}
