// Package smb1 implements the SMB1/CIFS protocol layer.
// This package provides core protocol structures, constants, and encoding/decoding
// functionality for the SMB1/CIFS protocol as defined in [MS-CIFS] and [MS-SMB].
package smb1

import (
	"github.com/macourteau/smb1client/internal/erref"
)

// Protocol signature for SMB1/CIFS (0xFF 'S' 'M' 'B')
const ProtocolSMB1 = "\xFFSMB"

// SMB1 Command codes
const (
	// Core protocol commands
	SMB_COM_CREATE_DIRECTORY       uint8 = 0x00
	SMB_COM_DELETE_DIRECTORY       uint8 = 0x01
	SMB_COM_OPEN                   uint8 = 0x02
	SMB_COM_CREATE                 uint8 = 0x03
	SMB_COM_CLOSE                  uint8 = 0x04
	SMB_COM_FLUSH                  uint8 = 0x05
	SMB_COM_DELETE                 uint8 = 0x06
	SMB_COM_RENAME                 uint8 = 0x07
	SMB_COM_QUERY_INFORMATION      uint8 = 0x08
	SMB_COM_SET_INFORMATION        uint8 = 0x09
	SMB_COM_READ                   uint8 = 0x0A
	SMB_COM_WRITE                  uint8 = 0x0B
	SMB_COM_LOCK_BYTE_RANGE        uint8 = 0x0C
	SMB_COM_UNLOCK_BYTE_RANGE      uint8 = 0x0D
	SMB_COM_CREATE_TEMPORARY       uint8 = 0x0E
	SMB_COM_CREATE_NEW             uint8 = 0x0F
	SMB_COM_CHECK_DIRECTORY        uint8 = 0x10
	SMB_COM_PROCESS_EXIT           uint8 = 0x11
	SMB_COM_SEEK                   uint8 = 0x12
	SMB_COM_LOCK_AND_READ          uint8 = 0x13
	SMB_COM_WRITE_AND_UNLOCK       uint8 = 0x14
	SMB_COM_READ_RAW               uint8 = 0x1A
	SMB_COM_READ_MPX               uint8 = 0x1B
	SMB_COM_READ_MPX_SECONDARY     uint8 = 0x1C
	SMB_COM_WRITE_RAW              uint8 = 0x1D
	SMB_COM_WRITE_MPX              uint8 = 0x1E
	SMB_COM_WRITE_MPX_SECONDARY    uint8 = 0x1F
	SMB_COM_WRITE_COMPLETE         uint8 = 0x20
	SMB_COM_QUERY_SERVER           uint8 = 0x21
	SMB_COM_SET_INFORMATION2       uint8 = 0x22
	SMB_COM_QUERY_INFORMATION2     uint8 = 0x23
	SMB_COM_LOCKING_ANDX           uint8 = 0x24
	SMB_COM_TRANSACTION            uint8 = 0x25
	SMB_COM_TRANSACTION_SECONDARY  uint8 = 0x26
	SMB_COM_IOCTL                  uint8 = 0x27
	SMB_COM_IOCTL_SECONDARY        uint8 = 0x28
	SMB_COM_COPY                   uint8 = 0x29
	SMB_COM_MOVE                   uint8 = 0x2A
	SMB_COM_ECHO                   uint8 = 0x2B
	SMB_COM_WRITE_AND_CLOSE        uint8 = 0x2C
	SMB_COM_OPEN_ANDX              uint8 = 0x2D
	SMB_COM_READ_ANDX              uint8 = 0x2E
	SMB_COM_WRITE_ANDX             uint8 = 0x2F
	SMB_COM_NEW_FILE_SIZE          uint8 = 0x30
	SMB_COM_CLOSE_AND_TREE_DISC    uint8 = 0x31
	SMB_COM_TRANSACTION2           uint8 = 0x32
	SMB_COM_TRANSACTION2_SECONDARY uint8 = 0x33
	SMB_COM_FIND_CLOSE2            uint8 = 0x34
	SMB_COM_FIND_NOTIFY_CLOSE      uint8 = 0x35

	// Session commands
	SMB_COM_TREE_CONNECT          uint8 = 0x70
	SMB_COM_TREE_DISCONNECT       uint8 = 0x71
	SMB_COM_NEGOTIATE             uint8 = 0x72
	SMB_COM_SESSION_SETUP_ANDX    uint8 = 0x73
	SMB_COM_LOGOFF_ANDX           uint8 = 0x74
	SMB_COM_TREE_CONNECT_ANDX     uint8 = 0x75
	SMB_COM_SECURITY_PACKAGE_ANDX uint8 = 0x7E

	// NT commands
	SMB_COM_QUERY_INFORMATION_DISK uint8 = 0x80
	SMB_COM_SEARCH                 uint8 = 0x81
	SMB_COM_FIND                   uint8 = 0x82
	SMB_COM_FIND_UNIQUE            uint8 = 0x83
	SMB_COM_FIND_CLOSE             uint8 = 0x84
	SMB_COM_NT_TRANSACT            uint8 = 0xA0
	SMB_COM_NT_TRANSACT_SECONDARY  uint8 = 0xA1
	SMB_COM_NT_CREATE_ANDX         uint8 = 0xA2
	SMB_COM_NT_CANCEL              uint8 = 0xA4
	SMB_COM_NT_RENAME              uint8 = 0xA5

	// Special commands
	SMB_COM_OPEN_PRINT_FILE  uint8 = 0xC0
	SMB_COM_WRITE_PRINT_FILE uint8 = 0xC1
	SMB_COM_CLOSE_PRINT_FILE uint8 = 0xC2
	SMB_COM_GET_PRINT_QUEUE  uint8 = 0xC3
	SMB_COM_READ_BULK        uint8 = 0xD8
	SMB_COM_WRITE_BULK       uint8 = 0xD9
	SMB_COM_WRITE_BULK_DATA  uint8 = 0xDA
	SMB_COM_INVALID          uint8 = 0xFE
	SMB_COM_NO_ANDX_COMMAND  uint8 = 0xFF
)

// Status codes (NT_STATUS format)
const (
	STATUS_SUCCESS                  uint32 = 0x00000000
	STATUS_MORE_PROCESSING_REQUIRED uint32 = 0xC0000016
	STATUS_INVALID_PARAMETER        uint32 = 0xC000000D
	STATUS_LOGON_FAILURE            uint32 = 0xC000006D
	STATUS_USER_SESSION_DELETED     uint32 = 0xC0000203
	STATUS_ACCESS_DENIED            uint32 = 0xC0000022
	STATUS_OBJECT_NAME_NOT_FOUND    uint32 = 0xC0000034
	STATUS_OBJECT_PATH_NOT_FOUND    uint32 = 0xC000003A
	STATUS_SHARING_VIOLATION        uint32 = 0xC0000043
	STATUS_END_OF_FILE              uint32 = 0xC0000011
	STATUS_NOT_SUPPORTED            uint32 = 0xC00000BB
	STATUS_NOT_IMPLEMENTED          uint32 = 0xC0000002
	STATUS_INVALID_INFO_CLASS       uint32 = 0xC0000003
	STATUS_INVALID_LEVEL            uint32 = 0xC0000148
	STATUS_INVALID_SMB              uint32 = 0x00010002
	STATUS_BAD_TID                  uint32 = 0x00050002
	STATUS_BAD_UID                  uint32 = 0x005B0002
)

// Flags field values
const (
	SMB_FLAGS_LOCK_AND_READ_OK    uint8 = 0x01 // Server supports LockAndRead
	SMB_FLAGS_BUF_AVAIL           uint8 = 0x02 // Obsolete
	SMB_FLAGS_RESERVED            uint8 = 0x04 // Reserved (must be zero)
	SMB_FLAGS_CASE_INSENSITIVE    uint8 = 0x08 // Path names are case insensitive
	SMB_FLAGS_CANONICALIZED_PATHS uint8 = 0x10 // Pathnames are canonicalized
	SMB_FLAGS_OPLOCK              uint8 = 0x20 // OpLock requested/granted
	SMB_FLAGS_OPBATCH             uint8 = 0x40 // Batch OpLock requested/granted
	SMB_FLAGS_REPLY               uint8 = 0x80 // Message is a response (server->client)
)

// Flags2 field values
const (
	SMB_FLAGS2_LONG_NAMES                  uint16 = 0x0001 // Support long file names
	SMB_FLAGS2_EAS                         uint16 = 0x0002 // Support Extended Attributes
	SMB_FLAGS2_SMB_SECURITY_SIGNATURE      uint16 = 0x0004 // Security signature required/supported
	SMB_FLAGS2_COMPRESSED                  uint16 = 0x0008 // Compression supported
	SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED uint16 = 0x0010 // Security signature required
	SMB_FLAGS2_RESERVED                    uint16 = 0x0020 // Reserved (must be zero)
	SMB_FLAGS2_IS_LONG_NAME                uint16 = 0x0040 // Pathnames are long format
	SMB_FLAGS2_REPARSE_PATH                uint16 = 0x0400 // Request is for reparse point
	SMB_FLAGS2_EXTENDED_SECURITY           uint16 = 0x0800 // Extended security negotiation
	SMB_FLAGS2_DFS                         uint16 = 0x1000 // Path is in DFS format
	SMB_FLAGS2_PAGING_IO                   uint16 = 0x2000 // Read if execute permission
	SMB_FLAGS2_NT_STATUS                   uint16 = 0x4000 // Use NT status codes (32-bit)
	SMB_FLAGS2_UNICODE                     uint16 = 0x8000 // Strings are Unicode
)

// Capabilities flags (for Negotiate protocol)
const (
	CAP_RAW_MODE           uint32 = 0x00000001 // Raw read/write mode supported
	CAP_MPX_MODE           uint32 = 0x00000002 // Multiplexed mode supported
	CAP_UNICODE            uint32 = 0x00000004 // Unicode strings supported
	CAP_LARGE_FILES        uint32 = 0x00000008 // 64-bit file offsets supported
	CAP_NT_SMBS            uint32 = 0x00000010 // NT SMB commands supported
	CAP_RPC_REMOTE_APIS    uint32 = 0x00000020 // RPC remote APIs supported
	CAP_STATUS32           uint32 = 0x00000040 // 32-bit NT status codes supported
	CAP_LEVEL_II_OPLOCKS   uint32 = 0x00000080 // Level II OpLocks supported
	CAP_LOCK_AND_READ      uint32 = 0x00000100 // LockAndRead supported
	CAP_NT_FIND            uint32 = 0x00000200 // NT Find supported
	CAP_DFS                uint32 = 0x00001000 // DFS supported
	CAP_INFOLEVEL_PASSTHRU uint32 = 0x00002000 // NT information level requests
	CAP_LARGE_READX        uint32 = 0x00004000 // Large read operations supported
	CAP_LARGE_WRITEX       uint32 = 0x00008000 // Large write operations supported
	CAP_LWIO               uint32 = 0x00010000 // Reserved
	CAP_UNIX               uint32 = 0x00800000 // UNIX extensions supported
	CAP_COMPRESSED_DATA    uint32 = 0x02000000 // Compression supported
	CAP_DYNAMIC_REAUTH     uint32 = 0x20000000 // Dynamic re-authentication
	CAP_PERSISTENT_HANDLES uint32 = 0x40000000 // Persistent handles
	CAP_EXTENDED_SECURITY  uint32 = 0x80000000 // Extended security exchanges
)

// Dialect strings for Negotiate protocol (NT LM 0.12 is primary for SMB1)
var Dialects = []string{
	"PC NETWORK PROGRAM 1.0",
	"LANMAN1.0",
	"Windows for Workgroups 3.1a",
	"LM1.2X002",
	"LANMAN2.1",
	"NT LM 0.12",
}

// DialectNTLM012 is the standard NT LAN Manager 0.12 dialect
const DialectNTLM012 = "NT LM 0.12"

// Access mask constants (for file open operations)
const (
	FILE_READ_DATA         uint32 = 0x00000001
	FILE_WRITE_DATA        uint32 = 0x00000002
	FILE_APPEND_DATA       uint32 = 0x00000004
	FILE_READ_EA           uint32 = 0x00000008
	FILE_WRITE_EA          uint32 = 0x00000010
	FILE_EXECUTE           uint32 = 0x00000020
	FILE_READ_ATTRIBUTES   uint32 = 0x00000080
	FILE_WRITE_ATTRIBUTES  uint32 = 0x00000100
	DELETE                 uint32 = 0x00010000
	READ_CONTROL           uint32 = 0x00020000
	WRITE_DAC              uint32 = 0x00040000
	WRITE_OWNER            uint32 = 0x00080000
	SYNCHRONIZE            uint32 = 0x00100000
	ACCESS_SYSTEM_SECURITY uint32 = 0x01000000
	MAXIMUM_ALLOWED        uint32 = 0x02000000
	GENERIC_ALL            uint32 = 0x10000000
	GENERIC_EXECUTE        uint32 = 0x20000000
	GENERIC_WRITE          uint32 = 0x40000000
	GENERIC_READ           uint32 = 0x80000000
)

// Share access flags (for file open operations)
const (
	FILE_SHARE_NONE   uint32 = 0x00000000
	FILE_SHARE_READ   uint32 = 0x00000001
	FILE_SHARE_WRITE  uint32 = 0x00000002
	FILE_SHARE_DELETE uint32 = 0x00000004
)

// File attributes
const (
	FILE_ATTRIBUTE_READONLY            uint32 = 0x00000001
	FILE_ATTRIBUTE_HIDDEN              uint32 = 0x00000002
	FILE_ATTRIBUTE_SYSTEM              uint32 = 0x00000004
	FILE_ATTRIBUTE_DIRECTORY           uint32 = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE             uint32 = 0x00000020
	FILE_ATTRIBUTE_DEVICE              uint32 = 0x00000040
	FILE_ATTRIBUTE_NORMAL              uint32 = 0x00000080
	FILE_ATTRIBUTE_TEMPORARY           uint32 = 0x00000100
	FILE_ATTRIBUTE_SPARSE_FILE         uint32 = 0x00000200
	FILE_ATTRIBUTE_REPARSE_POINT       uint32 = 0x00000400
	FILE_ATTRIBUTE_COMPRESSED          uint32 = 0x00000800
	FILE_ATTRIBUTE_OFFLINE             uint32 = 0x00001000
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED uint32 = 0x00002000
	FILE_ATTRIBUTE_ENCRYPTED           uint32 = 0x00004000
)

// Create disposition constants
const (
	FILE_SUPERSEDE    uint32 = 0x00000000 // Replace if exists
	FILE_OPEN         uint32 = 0x00000001 // Open if exists, fail otherwise
	FILE_CREATE       uint32 = 0x00000002 // Create if not exists, fail otherwise
	FILE_OPEN_IF      uint32 = 0x00000003 // Open if exists, create otherwise
	FILE_OVERWRITE    uint32 = 0x00000004 // Overwrite if exists, fail otherwise
	FILE_OVERWRITE_IF uint32 = 0x00000005 // Overwrite if exists, create otherwise
)

// Create options flags
const (
	FILE_DIRECTORY_FILE            uint32 = 0x00000001
	FILE_WRITE_THROUGH             uint32 = 0x00000002
	FILE_SEQUENTIAL_ONLY           uint32 = 0x00000004
	FILE_NO_INTERMEDIATE_BUFFERING uint32 = 0x00000008
	FILE_SYNCHRONOUS_IO_ALERT      uint32 = 0x00000010
	FILE_SYNCHRONOUS_IO_NONALERT   uint32 = 0x00000020
	FILE_NON_DIRECTORY_FILE        uint32 = 0x00000040
	FILE_CREATE_TREE_CONNECTION    uint32 = 0x00000080
	FILE_COMPLETE_IF_OPLOCKED      uint32 = 0x00000100
	FILE_NO_EA_KNOWLEDGE           uint32 = 0x00000200
	FILE_OPEN_FOR_RECOVERY         uint32 = 0x00000400
	FILE_RANDOM_ACCESS             uint32 = 0x00000800
	FILE_DELETE_ON_CLOSE           uint32 = 0x00001000
	FILE_OPEN_BY_FILE_ID           uint32 = 0x00002000
	FILE_OPEN_FOR_BACKUP_INTENT    uint32 = 0x00004000
	FILE_NO_COMPRESSION            uint32 = 0x00008000
	FILE_RESERVE_OPFILTER          uint32 = 0x00100000
	FILE_OPEN_REPARSE_POINT        uint32 = 0x00200000
	FILE_OPEN_NO_RECALL            uint32 = 0x00400000
	FILE_OPEN_FOR_FREE_SPACE_QUERY uint32 = 0x00800000
)

// Transaction2 subcommands
const (
	TRANS2_OPEN2                    uint16 = 0x0000
	TRANS2_FIND_FIRST2              uint16 = 0x0001
	TRANS2_FIND_NEXT2               uint16 = 0x0002
	TRANS2_QUERY_FS_INFORMATION     uint16 = 0x0003
	TRANS2_SET_FS_INFORMATION       uint16 = 0x0004
	TRANS2_QUERY_PATH_INFORMATION   uint16 = 0x0005
	TRANS2_SET_PATH_INFORMATION     uint16 = 0x0006
	TRANS2_QUERY_FILE_INFORMATION   uint16 = 0x0007
	TRANS2_SET_FILE_INFORMATION     uint16 = 0x0008
	TRANS2_FSCTL                    uint16 = 0x0009
	TRANS2_IOCTL2                   uint16 = 0x000A
	TRANS2_FIND_NOTIFY_FIRST        uint16 = 0x000B
	TRANS2_FIND_NOTIFY_NEXT         uint16 = 0x000C
	TRANS2_CREATE_DIRECTORY         uint16 = 0x000D
	TRANS2_SESSION_SETUP            uint16 = 0x000E
	TRANS2_GET_DFS_REFERRAL         uint16 = 0x0010
	TRANS2_REPORT_DFS_INCONSISTENCY uint16 = 0x0011
)

// Information level constants for TRANS2 queries
const (
	// Standard information levels (0x0001-0x0004)
	SMB_INFO_STANDARD            uint16 = 0x0001
	SMB_INFO_QUERY_EA_SIZE       uint16 = 0x0002
	SMB_INFO_QUERY_EAS_FROM_LIST uint16 = 0x0003
	SMB_INFO_QUERY_ALL_EAS       uint16 = 0x0004

	// File information levels (0x0101-0x0109)
	SMB_QUERY_FILE_BASIC_INFO    uint16 = 0x0101
	SMB_QUERY_FILE_STANDARD_INFO uint16 = 0x0102
	SMB_QUERY_FILE_EA_INFO       uint16 = 0x0103
	SMB_QUERY_FILE_NAME_INFO     uint16 = 0x0104
	SMB_QUERY_FILE_ALL_INFO      uint16 = 0x0107
	SMB_QUERY_FILE_STREAM_INFO   uint16 = 0x0109

	// Find file information levels (0x0101-0x0104)
	SMB_FIND_FILE_DIRECTORY_INFO      uint16 = 0x0101
	SMB_FIND_FILE_FULL_DIRECTORY_INFO uint16 = 0x0102
	SMB_FIND_FILE_NAMES_INFO          uint16 = 0x0103
	SMB_FIND_FILE_BOTH_DIRECTORY_INFO uint16 = 0x0104

	// Set file information levels
	SMB_SET_FILE_BASIC_INFO      uint16 = 0x0101
	FILE_END_OF_FILE_INFORMATION uint16 = 0x0104
)

// Filesystem information levels for TRANS2_QUERY_FS_INFORMATION.
//
// These reuse the numeric values of the file information levels above — both
// spaces begin at 0x0001 and 0x0101. A level is only meaningful next to its
// TRANS2 subcommand, so the two sets are named separately rather than shared.
const (
	// Legacy levels, understood by effectively every SMB1 server including old
	// and embedded ones. Their allocation-unit counts are 32-bit, so they
	// cannot describe very large volumes — hence the 0x0100 levels below.
	SMB_INFO_ALLOCATION uint16 = 0x0001
	SMB_INFO_VOLUME     uint16 = 0x0002

	// Modern levels. SMB_QUERY_FS_SIZE_INFO carries 64-bit unit counts.
	SMB_QUERY_FS_LABEL_INFO     uint16 = 0x0101
	SMB_QUERY_FS_VOLUME_INFO    uint16 = 0x0102
	SMB_QUERY_FS_SIZE_INFO      uint16 = 0x0103
	SMB_QUERY_FS_DEVICE_INFO    uint16 = 0x0104
	SMB_QUERY_FS_ATTRIBUTE_INFO uint16 = 0x0105
)

// FIND_FIRST2/FIND_NEXT2 flags
const (
	SMB_FIND_CLOSE_AFTER_REQUEST uint16 = 0x0001 // Close search after this request
	SMB_FIND_CLOSE_AT_EOS        uint16 = 0x0002 // Close search at end of search
	SMB_FIND_RETURN_RESUME_KEYS  uint16 = 0x0004 // Return resume keys
	SMB_FIND_CONTINUE_FROM_LAST  uint16 = 0x0008 // Continue from last entry
	SMB_FIND_WITH_BACKUP_INTENT  uint16 = 0x0010 // Find with backup intent
)

// Search attributes for FIND_FIRST2/FIND_NEXT2
const (
	SMB_SEARCH_ATTRIBUTE_READONLY  uint16 = 0x0001
	SMB_SEARCH_ATTRIBUTE_HIDDEN    uint16 = 0x0002
	SMB_SEARCH_ATTRIBUTE_SYSTEM    uint16 = 0x0004
	SMB_SEARCH_ATTRIBUTE_VOLUME    uint16 = 0x0008
	SMB_SEARCH_ATTRIBUTE_DIRECTORY uint16 = 0x0010
	SMB_SEARCH_ATTRIBUTE_ARCHIVE   uint16 = 0x0020
)

// StatusToError converts an NT_STATUS code to a Go error.
// It uses the erref package which contains comprehensive NT status code mappings.
func StatusToError(status uint32) error {
	if status == STATUS_SUCCESS {
		return nil
	}
	return erref.NtStatus(status)
}
