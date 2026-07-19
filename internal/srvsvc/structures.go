package srvsvc

import (
	"fmt"
	"strings"

	"github.com/macourteau/smb1client/internal/dcerpc"
)

// Share type constants define the various types of network shares.
// These constants follow the MS-SRVS specification.
const (
	// ShareTypeDisk indicates a disk share (directory).
	ShareTypeDisk = 0x00000000

	// ShareTypePrintQ indicates a print queue share.
	ShareTypePrintQ = 0x00000001

	// ShareTypeDevice indicates a communication device share.
	ShareTypeDevice = 0x00000002

	// ShareTypeIPC indicates an IPC (Inter-Process Communication) share.
	// These are typically named pipes like IPC$.
	ShareTypeIPC = 0x00000003

	// ShareTypeSpecial is a flag indicating a special share (e.g., IPC$, ADMIN$, C$).
	// This flag is OR'ed with the base type.
	ShareTypeSpecial = 0x80000000

	// ShareTypeTemporary is a flag indicating a temporary share.
	// This flag is OR'ed with the base type.
	ShareTypeTemporary = 0x40000000
)

// EncodeServerName encodes a UNC server name as an NDR conformant varying string pointer.
// The server name should be provided in one of these formats:
//   - IP address: "192.168.1.1"
//   - Hostname: "SERVER"
//   - UNC name: "\\SERVER" or "\\\\192.168.1.1"
//
// The function automatically converts to UNC format (\\SERVER) if needed.
// Returns the encoded pointer with referent ID followed by the string data.
func EncodeServerName(name string) []byte {
	// Convert to UNC format if not already
	uncName := name
	if !strings.HasPrefix(name, "\\\\") {
		if !strings.HasPrefix(name, "\\") {
			uncName = "\\\\" + name
		} else {
			uncName = "\\" + name
		}
	}

	// Encode the string using NDR conformant varying string format
	stringData := dcerpc.MarshalConformantVaryingString(uncName)

	// Wrap in a pointer with referent ID 0x00020000
	return dcerpc.MarshalPointer(0x00020000, stringData)
}

// DecodeShareInfo1Array parses an array of SHARE_INFO_1 structures from NDR-encoded data.
// This function handles the complex pointer structure used in NDR:
//  1. Array conformance (max count)
//  2. Array of structure elements (with embedded pointers)
//  3. Deferred pointers (string data appears after all structures)
//
// The offset pointer is updated to point past all decoded data.
func DecodeShareInfo1Array(data []byte, offset *int, count uint32) ([]ShareInfo1, error) {
	if count == 0 {
		return []ShareInfo1{}, nil
	}

	// Align to 4-byte boundary
	*offset = dcerpc.AlignOffset(*offset, dcerpc.Align4)

	// Read array conformance (max count)
	if len(data) < *offset+4 {
		return nil, fmt.Errorf("srvsvc: buffer too short for array conformance")
	}
	maxCount := dcerpc.UnmarshalUint32(data[*offset : *offset+4])
	*offset += 4

	// Validate count
	if count > maxCount {
		return nil, fmt.Errorf("srvsvc: invalid array: count=%d > maxCount=%d", count, maxCount)
	}

	// Parse array elements
	// Each SHARE_INFO_1 structure consists of:
	//   - Name pointer (4 bytes referent ID)
	//   - Type (4 bytes)
	//   - Comment pointer (4 bytes referent ID)
	shares := make([]ShareInfo1, count)
	namePointers := make([]uint32, count)
	commentPointers := make([]uint32, count)

	for i := uint32(0); i < count; i++ {
		// Align to 4-byte boundary for structure
		*offset = dcerpc.AlignOffset(*offset, dcerpc.Align4)

		// Name pointer (referent ID)
		if len(data) < *offset+4 {
			return nil, fmt.Errorf("srvsvc: buffer too short for share %d name pointer", i)
		}
		namePointers[i] = dcerpc.UnmarshalUint32(data[*offset : *offset+4])
		*offset += 4

		// Type
		if len(data) < *offset+4 {
			return nil, fmt.Errorf("srvsvc: buffer too short for share %d type", i)
		}
		shares[i].Type = dcerpc.UnmarshalUint32(data[*offset : *offset+4])
		*offset += 4

		// Comment pointer (referent ID)
		if len(data) < *offset+4 {
			return nil, fmt.Errorf("srvsvc: buffer too short for share %d comment pointer", i)
		}
		commentPointers[i] = dcerpc.UnmarshalUint32(data[*offset : *offset+4])
		*offset += 4
	}

	// Parse deferred pointers (strings)
	// NDR places all pointed-to data after the structures in the order they appeared
	for i := uint32(0); i < count; i++ {
		// Parse name string if pointer is non-null
		if namePointers[i] != 0 {
			name, err := dcerpc.UnmarshalConformantVaryingString(data, offset)
			if err != nil {
				return nil, fmt.Errorf("srvsvc: failed to decode share %d name: %w", i, err)
			}
			shares[i].Name = name
		}

		// Parse comment string if pointer is non-null
		if commentPointers[i] != 0 {
			comment, err := dcerpc.UnmarshalConformantVaryingString(data, offset)
			if err != nil {
				return nil, fmt.Errorf("srvsvc: failed to decode share %d comment: %w", i, err)
			}
			shares[i].Comment = comment
		}
	}

	return shares, nil
}

// ShareTypeName returns a human-readable string for a share type.
// This is useful for debugging and logging.
func ShareTypeName(shareType uint32) string {
	// Extract base type (remove flags)
	baseType := shareType & 0x0000FFFF
	flags := shareType & 0xFFFF0000

	var typeName string
	switch baseType {
	case ShareTypeDisk:
		typeName = "Disk"
	case ShareTypePrintQ:
		typeName = "PrintQueue"
	case ShareTypeDevice:
		typeName = "Device"
	case ShareTypeIPC:
		typeName = "IPC"
	default:
		typeName = fmt.Sprintf("Unknown(0x%08x)", baseType)
	}

	// Add flags
	var flagNames []string
	if flags&ShareTypeSpecial != 0 {
		flagNames = append(flagNames, "Special")
	}
	if flags&ShareTypeTemporary != 0 {
		flagNames = append(flagNames, "Temporary")
	}

	if len(flagNames) > 0 {
		return fmt.Sprintf("%s|%s", typeName, strings.Join(flagNames, "|"))
	}
	return typeName
}
