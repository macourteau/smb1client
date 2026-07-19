package srvsvc

// SRVSVC (Server Service) is a DCE/RPC interface for administrative operations
// on Windows servers. It provides functions like NetShareEnum for enumerating
// network shares.
//
// This package implements the SRVSVC interface according to [MS-SRVS]:
// Server Service (SRVSVC) Remote Protocol
//
// Interface UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188
// Version: 3.0

// InterfaceUUID is the UUID for the SRVSVC interface.
// UUID string: 4b324fc8-1670-01d3-1278-5a47bf6ee188
// In DCE/RPC little-endian format:
var InterfaceUUID = [16]byte{
	0xc8, 0x4f, 0x32, 0x4b, // time_low (little-endian)
	0x70, 0x16, // time_mid (little-endian)
	0xd3, 0x01, // time_hi_and_version (little-endian)
	0x12, 0x78, // clock_seq
	0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88, // node
}

// InterfaceVersion is the version of the SRVSVC interface (3.0).
// Encoded as uint32 with major version in low 16 bits, minor version in high 16 bits
const InterfaceVersion = 0x00000003

// SRVSVC operation numbers
const (
	// OpNetShareEnumAll is the operation number for NetShareEnumAll.
	// This operation enumerates all network shares on the server.
	OpNetShareEnumAll = 15
)

// ShareInfo1 represents share information at level 1.
// This structure corresponds to SHARE_INFO_1 in the MS-SRVS specification.
type ShareInfo1 struct {
	Name    string // Share name
	Type    uint32 // Share type (see ShareType constants)
	Comment string // Share comment/description
}

// NetShareCtr1 is the container for an array of SHARE_INFO_1 structures.
// This corresponds to SHARE_INFO_1_CONTAINER in the MS-SRVS specification.
type NetShareCtr1 struct {
	Count  uint32       // Number of shares in the array
	Shares []ShareInfo1 // Array of share information structures
}

// NetShareInfoCtr is a union that contains share information at a specific level.
// This corresponds to SHARE_ENUM_STRUCT in the MS-SRVS specification.
type NetShareInfoCtr struct {
	Level uint32        // Information level (1 for SHARE_INFO_1)
	Ctr1  *NetShareCtr1 // Level 1 container (non-nil when Level=1)
}
