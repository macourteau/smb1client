package smb1

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/macourteau/smb1client/internal/utf16le"
)

// TestEncodeTrans2Request tests TRANS2 request encoding.
func TestEncodeTrans2Request(t *testing.T) {
	tests := []struct {
		name    string
		setup   []uint16
		params  []byte
		data    []byte
		reqName string
		wantErr bool
		check   func(*testing.T, []byte, []byte)
	}{
		{
			name:    "basic trans2 request",
			setup:   []uint16{TRANS2_FIND_FIRST2},
			params:  []byte{0x01, 0x02, 0x03, 0x04},
			data:    []byte{0x05, 0x06},
			reqName: "",
			wantErr: false,
			check: func(t *testing.T, params, data []byte) {
				// Verify parameters size: 28 (fixed) + 2 (setup)
				if len(params) != 30 {
					t.Errorf("params length = %d, want 30", len(params))
				}
				// Verify setup count
				if params[26] != 1 {
					t.Errorf("SetupCount = %d, want 1", params[26])
				}
				// Verify subcommand
				subCmd := binary.LittleEndian.Uint16(params[28:30])
				if subCmd != TRANS2_FIND_FIRST2 {
					t.Errorf("Setup[0] = 0x%04x, want 0x%04x", subCmd, TRANS2_FIND_FIRST2)
				}
			},
		},
		{
			name:    "trans2 with multiple setup words",
			setup:   []uint16{TRANS2_QUERY_FILE_INFORMATION, 1234},
			params:  []byte{0x11, 0x22},
			data:    []byte{},
			reqName: "",
			wantErr: false,
			check: func(t *testing.T, params, data []byte) {
				// Verify setup count
				if params[26] != 2 {
					t.Errorf("SetupCount = %d, want 2", params[26])
				}
			},
		},
		{
			name:    "empty setup array",
			setup:   []uint16{},
			params:  []byte{},
			data:    []byte{},
			reqName: "",
			wantErr: true,
		},
		{
			name:    "setup array too large",
			setup:   make([]uint16, 15),
			params:  []byte{},
			data:    []byte{},
			reqName: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeTrans2Request(tt.setup, tt.params, tt.data, tt.reqName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeTrans2Request() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if tt.check != nil {
				tt.check(t, params, data)
			}
		})
	}
}

// TestDecodeTrans2Response tests TRANS2 response decoding.
func TestDecodeTrans2Response(t *testing.T) {
	tests := []struct {
		name      string
		params    []byte
		data      []byte
		wantErr   bool
		checkResp func(*testing.T, *Trans2Response)
	}{
		{
			name: "valid trans2 response",
			params: func() []byte {
				p := make([]byte, 20)
				binary.LittleEndian.PutUint16(p[0:2], 10)   // TotalParameterCount
				binary.LittleEndian.PutUint16(p[2:4], 20)   // TotalDataCount
				binary.LittleEndian.PutUint16(p[4:6], 0)    // Reserved
				binary.LittleEndian.PutUint16(p[6:8], 10)   // ParameterCount
				binary.LittleEndian.PutUint16(p[8:10], 50)  // ParameterOffset
				binary.LittleEndian.PutUint16(p[10:12], 0)  // ParameterDisplacement
				binary.LittleEndian.PutUint16(p[12:14], 20) // DataCount
				binary.LittleEndian.PutUint16(p[14:16], 60) // DataOffset
				binary.LittleEndian.PutUint16(p[16:18], 0)  // DataDisplacement
				p[18] = 0                                   // SetupCount
				p[19] = 0                                   // Reserved2
				return p
			}(),
			data: func() []byte {
				d := make([]byte, 2+30)
				binary.LittleEndian.PutUint16(d[0:2], 30) // ByteCount
				// Add some parameter data
				for i := 0; i < 10; i++ {
					d[2+i] = byte(i)
				}
				// Add some data
				for i := 0; i < 20; i++ {
					d[12+i] = byte(i + 10)
				}
				return d
			}(),
			wantErr: false,
			checkResp: func(t *testing.T, resp *Trans2Response) {
				if resp.TotalParameterCount != 10 {
					t.Errorf("TotalParameterCount = %d, want 10", resp.TotalParameterCount)
				}
				if resp.TotalDataCount != 20 {
					t.Errorf("TotalDataCount = %d, want 20", resp.TotalDataCount)
				}
				if resp.ParameterCount != 10 {
					t.Errorf("ParameterCount = %d, want 10", resp.ParameterCount)
				}
				if resp.DataCount != 20 {
					t.Errorf("DataCount = %d, want 20", resp.DataCount)
				}
			},
		},
		{
			name: "trans2 response with setup words",
			params: func() []byte {
				p := make([]byte, 24)
				binary.LittleEndian.PutUint16(p[0:2], 0)   // TotalParameterCount
				binary.LittleEndian.PutUint16(p[2:4], 0)   // TotalDataCount
				binary.LittleEndian.PutUint16(p[4:6], 0)   // Reserved
				binary.LittleEndian.PutUint16(p[6:8], 0)   // ParameterCount
				binary.LittleEndian.PutUint16(p[8:10], 0)  // ParameterOffset
				binary.LittleEndian.PutUint16(p[10:12], 0) // ParameterDisplacement
				binary.LittleEndian.PutUint16(p[12:14], 0) // DataCount
				binary.LittleEndian.PutUint16(p[14:16], 0) // DataOffset
				binary.LittleEndian.PutUint16(p[16:18], 0) // DataDisplacement
				p[18] = 2                                  // SetupCount
				p[19] = 0                                  // Reserved2
				binary.LittleEndian.PutUint16(p[20:22], 0x1234)
				binary.LittleEndian.PutUint16(p[22:24], 0x5678)
				return p
			}(),
			data:    []byte{0x00, 0x00},
			wantErr: false,
			checkResp: func(t *testing.T, resp *Trans2Response) {
				if resp.SetupCount != 2 {
					t.Errorf("SetupCount = %d, want 2", resp.SetupCount)
				}
				if len(resp.Setup) != 2 {
					t.Errorf("len(Setup) = %d, want 2", len(resp.Setup))
				}
				if resp.Setup[0] != 0x1234 {
					t.Errorf("Setup[0] = 0x%04x, want 0x1234", resp.Setup[0])
				}
				if resp.Setup[1] != 0x5678 {
					t.Errorf("Setup[1] = 0x%04x, want 0x5678", resp.Setup[1])
				}
			},
		},
		{
			name:    "parameters too short",
			params:  make([]byte, 10),
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := DecodeTrans2Response(tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeTrans2Response() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if tt.checkResp != nil {
				tt.checkResp(t, resp)
			}
		})
	}
}

// TestEncodeFindFirst2 tests FIND_FIRST2 request encoding.
func TestEncodeFindFirst2(t *testing.T) {
	tests := []struct {
		name    string
		req     *FindFirst2Request
		wantErr bool
		check   func(*testing.T, []byte)
	}{
		{
			name: "basic find first2",
			req: &FindFirst2Request{
				SearchAttributes:  SMB_SEARCH_ATTRIBUTE_DIRECTORY | SMB_SEARCH_ATTRIBUTE_ARCHIVE,
				SearchCount:       100,
				Flags:             SMB_FIND_CLOSE_AT_EOS,
				InformationLevel:  SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
				SearchStorageType: 0,
				FileName:          "*",
				UseUnicode:        false,
			},
			wantErr: false,
			check: func(t *testing.T, params []byte) {
				if len(params) < 12 {
					t.Errorf("params length = %d, want >= 12", len(params))
				}
				searchCount := binary.LittleEndian.Uint16(params[2:4])
				if searchCount != 100 {
					t.Errorf("SearchCount = %d, want 100", searchCount)
				}
				infoLevel := binary.LittleEndian.Uint16(params[6:8])
				if infoLevel != SMB_FIND_FILE_BOTH_DIRECTORY_INFO {
					t.Errorf("InformationLevel = 0x%04x, want 0x%04x", infoLevel, SMB_FIND_FILE_BOTH_DIRECTORY_INFO)
				}
			},
		},
		{
			name: "find with pattern",
			req: &FindFirst2Request{
				SearchAttributes:  SMB_SEARCH_ATTRIBUTE_ARCHIVE,
				SearchCount:       10,
				Flags:             0,
				InformationLevel:  SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
				SearchStorageType: 0,
				FileName:          "*.txt",
				UseUnicode:        false,
			},
			wantErr: false,
			check: func(t *testing.T, params []byte) {
				// Check that filename is present and null-terminated
				filename := string(params[12 : len(params)-1])
				if filename != "*.txt" {
					t.Errorf("FileName = %s, want *.txt", filename)
				}
			},
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "empty filename",
			req: &FindFirst2Request{
				SearchCount:      10,
				InformationLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
				FileName:         "",
				UseUnicode:       false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := EncodeFindFirst2(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeFindFirst2() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if tt.check != nil {
				tt.check(t, params)
			}
		})
	}
}

// TestDecodeFindFirst2Response tests FIND_FIRST2 response decoding.
func TestDecodeFindFirst2Response(t *testing.T) {
	tests := []struct {
		name      string
		params    []byte
		data      []byte
		infoLevel uint16
		wantErr   bool
		checkResp func(*testing.T, *FindFirst2Response)
	}{
		{
			name: "valid find first2 response",
			params: func() []byte {
				p := make([]byte, 10)
				binary.LittleEndian.PutUint16(p[0:2], 1234) // SID
				binary.LittleEndian.PutUint16(p[2:4], 2)    // SearchCount
				binary.LittleEndian.PutUint16(p[4:6], 0)    // EndOfSearch
				binary.LittleEndian.PutUint16(p[6:8], 0)    // EaErrorOffset
				binary.LittleEndian.PutUint16(p[8:10], 0)   // LastNameOffset
				return p
			}(),
			data:      []byte{},
			infoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
			wantErr:   false,
			checkResp: func(t *testing.T, resp *FindFirst2Response) {
				if resp.SID != 1234 {
					t.Errorf("SID = %d, want 1234", resp.SID)
				}
				if resp.SearchCount != 2 {
					t.Errorf("SearchCount = %d, want 2", resp.SearchCount)
				}
				if resp.EndOfSearch != 0 {
					t.Errorf("EndOfSearch = %d, want 0", resp.EndOfSearch)
				}
			},
		},
		{
			name:      "parameters too short",
			params:    make([]byte, 5),
			data:      []byte{},
			infoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := DecodeFindFirst2Response(tt.params, tt.data, tt.infoLevel)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeFindFirst2Response() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if tt.checkResp != nil {
				tt.checkResp(t, resp)
			}
		})
	}
}

// TestEncodeFindNext2 tests FIND_NEXT2 request encoding.
func TestEncodeFindNext2(t *testing.T) {
	tests := []struct {
		name    string
		req     *FindNext2Request
		wantErr bool
		check   func(*testing.T, []byte)
	}{
		{
			name: "basic find next2",
			req: &FindNext2Request{
				SID:              1234,
				SearchCount:      50,
				InformationLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
				ResumeKey:        0,
				Flags:            SMB_FIND_CONTINUE_FROM_LAST,
				FileName:         "*",
				UseUnicode:       false,
			},
			wantErr: false,
			check: func(t *testing.T, params []byte) {
				if len(params) < 12 {
					t.Errorf("params length = %d, want >= 12", len(params))
				}
				sid := binary.LittleEndian.Uint16(params[0:2])
				if sid != 1234 {
					t.Errorf("SID = %d, want 1234", sid)
				}
				searchCount := binary.LittleEndian.Uint16(params[2:4])
				if searchCount != 50 {
					t.Errorf("SearchCount = %d, want 50", searchCount)
				}
			},
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := EncodeFindNext2(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeFindNext2() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if tt.check != nil {
				tt.check(t, params)
			}
		})
	}
}

// TestDecodeFindNext2Response tests FIND_NEXT2 response decoding.
func TestDecodeFindNext2Response(t *testing.T) {
	tests := []struct {
		name      string
		params    []byte
		data      []byte
		infoLevel uint16
		wantErr   bool
		checkResp func(*testing.T, *FindNext2Response)
	}{
		{
			name: "valid find next2 response",
			params: func() []byte {
				p := make([]byte, 8)
				binary.LittleEndian.PutUint16(p[0:2], 1) // SearchCount
				binary.LittleEndian.PutUint16(p[2:4], 1) // EndOfSearch
				binary.LittleEndian.PutUint16(p[4:6], 0) // EaErrorOffset
				binary.LittleEndian.PutUint16(p[6:8], 0) // LastNameOffset
				return p
			}(),
			data:      []byte{},
			infoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
			wantErr:   false,
			checkResp: func(t *testing.T, resp *FindNext2Response) {
				if resp.SearchCount != 1 {
					t.Errorf("SearchCount = %d, want 1", resp.SearchCount)
				}
				if resp.EndOfSearch != 1 {
					t.Errorf("EndOfSearch = %d, want 1", resp.EndOfSearch)
				}
			},
		},
		{
			name:      "parameters too short",
			params:    make([]byte, 5),
			data:      []byte{},
			infoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := DecodeFindNext2Response(tt.params, tt.data, tt.infoLevel)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeFindNext2Response() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if tt.checkResp != nil {
				tt.checkResp(t, resp)
			}
		})
	}
}

// TestEncodeFindClose2 tests FIND_CLOSE2 request encoding.
func TestEncodeFindClose2(t *testing.T) {
	params, err := EncodeFindClose2(5678)
	if err != nil {
		t.Fatalf("EncodeFindClose2() error = %v", err)
	}

	if len(params) != 2 {
		t.Errorf("params length = %d, want 2", len(params))
	}

	sid := binary.LittleEndian.Uint16(params[0:2])
	if sid != 5678 {
		t.Errorf("SID = %d, want 5678", sid)
	}
}

// TestEncodeQueryPathInfo tests QUERY_PATH_INFO request encoding.
func TestEncodeQueryPathInfo(t *testing.T) {
	tests := []struct {
		name       string
		fileName   string
		infoLevel  uint16
		useUnicode bool
		wantErr    bool
		check      func(*testing.T, []byte)
	}{
		{
			name:       "basic query path info (ASCII)",
			fileName:   "test.txt",
			infoLevel:  SMB_QUERY_FILE_BASIC_INFO,
			useUnicode: false,
			wantErr:    false,
			check: func(t *testing.T, params []byte) {
				if len(params) < 6 {
					t.Errorf("params length = %d, want >= 6", len(params))
				}
				level := binary.LittleEndian.Uint16(params[0:2])
				if level != SMB_QUERY_FILE_BASIC_INFO {
					t.Errorf("InformationLevel = 0x%04x, want 0x%04x", level, SMB_QUERY_FILE_BASIC_INFO)
				}
			},
		},
		{
			name:       "basic query path info (Unicode)",
			fileName:   "test.txt",
			infoLevel:  SMB_QUERY_FILE_BASIC_INFO,
			useUnicode: true,
			wantErr:    false,
			check: func(t *testing.T, params []byte) {
				if len(params) < 6 {
					t.Errorf("params length = %d, want >= 6", len(params))
				}
				level := binary.LittleEndian.Uint16(params[0:2])
				if level != SMB_QUERY_FILE_BASIC_INFO {
					t.Errorf("InformationLevel = 0x%04x, want 0x%04x", level, SMB_QUERY_FILE_BASIC_INFO)
				}
			},
		},
		{
			name:       "empty filename",
			fileName:   "",
			infoLevel:  SMB_QUERY_FILE_BASIC_INFO,
			useUnicode: false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := EncodeQueryPathInfo(tt.fileName, tt.infoLevel, tt.useUnicode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeQueryPathInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if tt.check != nil {
				tt.check(t, params)
			}
		})
	}
}

// TestEncodeQueryFileInfo tests QUERY_FILE_INFO request encoding.
func TestEncodeQueryFileInfo(t *testing.T) {
	params, err := EncodeQueryFileInfo(1234, SMB_QUERY_FILE_STANDARD_INFO)
	if err != nil {
		t.Fatalf("EncodeQueryFileInfo() error = %v", err)
	}

	if len(params) != 4 {
		t.Errorf("params length = %d, want 4", len(params))
	}

	fid := binary.LittleEndian.Uint16(params[0:2])
	if fid != 1234 {
		t.Errorf("FID = %d, want 1234", fid)
	}

	level := binary.LittleEndian.Uint16(params[2:4])
	if level != SMB_QUERY_FILE_STANDARD_INFO {
		t.Errorf("InformationLevel = 0x%04x, want 0x%04x", level, SMB_QUERY_FILE_STANDARD_INFO)
	}
}

// TestEncodeSetPathInfo tests SET_PATH_INFO request encoding.
func TestEncodeSetPathInfo(t *testing.T) {
	tests := []struct {
		name       string
		fileName   string
		infoLevel  uint16
		data       []byte
		useUnicode bool
		wantName   []byte // expected filename bytes at params[6:], including terminator
		wantErr    bool
	}{
		{
			name:      "basic set path info",
			fileName:  "test.txt",
			infoLevel: SMB_SET_FILE_BASIC_INFO,
			data:      make([]byte, 40),
			wantName:  []byte("test.txt\x00"),
			wantErr:   false,
		},
		{
			// A Unicode session must carry the name as UTF-16LE with a
			// two-byte terminator, or the server decodes garbage.
			name:       "unicode set path info",
			fileName:   "ab",
			infoLevel:  SMB_SET_FILE_BASIC_INFO,
			data:       make([]byte, 40),
			useUnicode: true,
			wantName:   []byte{'a', 0, 'b', 0, 0, 0},
			wantErr:    false,
		},
		{
			name:      "empty filename",
			fileName:  "",
			infoLevel: SMB_SET_FILE_BASIC_INFO,
			data:      []byte{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeSetPathInfo(tt.fileName, tt.infoLevel, tt.data, tt.useUnicode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeSetPathInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if len(params) != 6+len(tt.wantName) {
				t.Fatalf("params length = %d, want %d", len(params), 6+len(tt.wantName))
			}
			if got := binary.LittleEndian.Uint16(params[0:2]); got != tt.infoLevel {
				t.Errorf("InformationLevel = 0x%04x, want 0x%04x", got, tt.infoLevel)
			}
			if !bytes.Equal(params[6:], tt.wantName) {
				t.Errorf("filename bytes = %v, want %v", params[6:], tt.wantName)
			}
			if !bytes.Equal(data, tt.data) {
				t.Errorf("data mismatch")
			}
		})
	}
}

// TestEncodeSetFileInfo tests SET_FILE_INFO request encoding.
func TestEncodeSetFileInfo(t *testing.T) {
	fid := uint16(5678)
	infoLevel := SMB_QUERY_FILE_BASIC_INFO
	data := make([]byte, 40)

	params, resultData, err := EncodeSetFileInfo(fid, infoLevel, data)
	if err != nil {
		t.Fatalf("EncodeSetFileInfo() error = %v", err)
	}

	if len(params) != 6 {
		t.Errorf("params length = %d, want 6", len(params))
	}

	decodedFid := binary.LittleEndian.Uint16(params[0:2])
	if decodedFid != fid {
		t.Errorf("FID = %d, want %d", decodedFid, fid)
	}

	level := binary.LittleEndian.Uint16(params[2:4])
	if level != infoLevel {
		t.Errorf("InformationLevel = 0x%04x, want 0x%04x", level, infoLevel)
	}

	if !bytes.Equal(resultData, data) {
		t.Errorf("data mismatch")
	}
}

// TestParseFileBothDirectoryInfo tests parsing of directory information.
func TestParseFileBothDirectoryInfo(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantFiles int
		wantErr   bool
		check     func(*testing.T, []FileBothDirectoryInfo)
	}{
		{
			name: "single file entry",
			data: func() []byte {
				d := make([]byte, 94+4)                       // Fixed part + 2-char Unicode name
				binary.LittleEndian.PutUint32(d[0:4], 0)      // NextEntryOffset (0 = last)
				binary.LittleEndian.PutUint32(d[4:8], 1)      // FileIndex
				binary.LittleEndian.PutUint64(d[40:48], 1024) // EndOfFile
				binary.LittleEndian.PutUint32(d[56:60], FILE_ATTRIBUTE_NORMAL)
				binary.LittleEndian.PutUint32(d[60:64], 4) // FileNameLength (2 bytes for "AB")
				binary.LittleEndian.PutUint32(d[64:68], 0) // EaSize
				d[68] = 0                                  // ShortNameLength
				// Add Unicode filename "AB"
				name := utf16le.EncodeStringToBytes("AB")
				copy(d[94:], name)
				return d
			}(),
			wantFiles: 1,
			wantErr:   false,
			check: func(t *testing.T, files []FileBothDirectoryInfo) {
				if files[0].EndOfFile != 1024 {
					t.Errorf("EndOfFile = %d, want 1024", files[0].EndOfFile)
				}
				if files[0].FileAttributes != FILE_ATTRIBUTE_NORMAL {
					t.Errorf("FileAttributes = 0x%08x, want 0x%08x", files[0].FileAttributes, FILE_ATTRIBUTE_NORMAL)
				}
				if files[0].FileName != "AB" {
					t.Errorf("FileName = %s, want AB", files[0].FileName)
				}
			},
		},
		{
			name: "multiple file entries",
			data: func() []byte {
				// Create two entries
				entry1 := make([]byte, 94+4)
				binary.LittleEndian.PutUint32(entry1[0:4], 98) // NextEntryOffset to entry2
				binary.LittleEndian.PutUint32(entry1[4:8], 1)  // FileIndex
				binary.LittleEndian.PutUint32(entry1[56:60], FILE_ATTRIBUTE_DIRECTORY)
				binary.LittleEndian.PutUint32(entry1[60:64], 4) // FileNameLength
				name1 := utf16le.EncodeStringToBytes("D1")
				copy(entry1[94:], name1)

				entry2 := make([]byte, 94+4)
				binary.LittleEndian.PutUint32(entry2[0:4], 0) // NextEntryOffset (last)
				binary.LittleEndian.PutUint32(entry2[4:8], 2) // FileIndex
				binary.LittleEndian.PutUint32(entry2[56:60], FILE_ATTRIBUTE_NORMAL)
				binary.LittleEndian.PutUint32(entry2[60:64], 4) // FileNameLength
				name2 := utf16le.EncodeStringToBytes("F2")
				copy(entry2[94:], name2)

				return append(entry1, entry2...)
			}(),
			wantFiles: 2,
			wantErr:   false,
			check: func(t *testing.T, files []FileBothDirectoryInfo) {
				if files[0].FileIndex != 1 {
					t.Errorf("files[0].FileIndex = %d, want 1", files[0].FileIndex)
				}
				if files[1].FileIndex != 2 {
					t.Errorf("files[1].FileIndex = %d, want 2", files[1].FileIndex)
				}
				if !files[0].IsDirectory() {
					t.Error("files[0] should be directory")
				}
				if files[1].IsDirectory() {
					t.Error("files[1] should not be directory")
				}
			},
		},
		{
			name:      "empty data",
			data:      []byte{},
			wantFiles: 0,
			wantErr:   false,
		},
		{
			name:      "truncated entry",
			data:      make([]byte, 50), // Less than minimum 94 bytes
			wantFiles: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseFileBothDirectoryInfo(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseFileBothDirectoryInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if len(result.Files) != tt.wantFiles {
				t.Errorf("got %d files, want %d", len(result.Files), tt.wantFiles)
			}

			if tt.check != nil && len(result.Files) > 0 {
				tt.check(t, result.Files)
			}
		})
	}
}

// TestFileBasicInfo tests FileBasicInfo encoding/decoding.
func TestFileBasicInfo(t *testing.T) {
	original := &FileBasicInfo{
		CreationTime:   0x01D7F1E8B3A00000,
		LastAccessTime: 0x01D7F1E8B3B00000,
		LastWriteTime:  0x01D7F1E8B3C00000,
		ChangeTime:     0x01D7F1E8B3D00000,
		Attributes:     FILE_ATTRIBUTE_NORMAL,
		Reserved:       0,
	}

	// Encode
	data := EncodeFileBasicInfo(original)
	if len(data) != 40 {
		t.Errorf("encoded data length = %d, want 40", len(data))
	}

	// Decode
	decoded, err := DecodeFileBasicInfo(data)
	if err != nil {
		t.Fatalf("DecodeFileBasicInfo() error = %v", err)
	}

	// Compare
	if decoded.CreationTime != original.CreationTime {
		t.Errorf("CreationTime = 0x%016x, want 0x%016x", decoded.CreationTime, original.CreationTime)
	}
	if decoded.LastAccessTime != original.LastAccessTime {
		t.Errorf("LastAccessTime = 0x%016x, want 0x%016x", decoded.LastAccessTime, original.LastAccessTime)
	}
	if decoded.LastWriteTime != original.LastWriteTime {
		t.Errorf("LastWriteTime = 0x%016x, want 0x%016x", decoded.LastWriteTime, original.LastWriteTime)
	}
	if decoded.ChangeTime != original.ChangeTime {
		t.Errorf("ChangeTime = 0x%016x, want 0x%016x", decoded.ChangeTime, original.ChangeTime)
	}
	if decoded.Attributes != original.Attributes {
		t.Errorf("Attributes = 0x%08x, want 0x%08x", decoded.Attributes, original.Attributes)
	}

	// Test error case
	_, err = DecodeFileBasicInfo(make([]byte, 20))
	if err == nil {
		t.Error("DecodeFileBasicInfo() with short data should return error")
	}
}

// TestFileStandardInfo tests FileStandardInfo encoding/decoding.
func TestFileStandardInfo(t *testing.T) {
	original := &FileStandardInfo{
		AllocationSize: 4096,
		EndOfFile:      2048,
		NumberOfLinks:  1,
		DeletePending:  0,
		Directory:      1,
		Reserved:       0,
	}

	// Encode
	data := EncodeFileStandardInfo(original)
	if len(data) != 24 {
		t.Errorf("encoded data length = %d, want 24", len(data))
	}

	// Decode
	decoded, err := DecodeFileStandardInfo(data)
	if err != nil {
		t.Fatalf("DecodeFileStandardInfo() error = %v", err)
	}

	// Compare
	if decoded.AllocationSize != original.AllocationSize {
		t.Errorf("AllocationSize = %d, want %d", decoded.AllocationSize, original.AllocationSize)
	}
	if decoded.EndOfFile != original.EndOfFile {
		t.Errorf("EndOfFile = %d, want %d", decoded.EndOfFile, original.EndOfFile)
	}
	if decoded.NumberOfLinks != original.NumberOfLinks {
		t.Errorf("NumberOfLinks = %d, want %d", decoded.NumberOfLinks, original.NumberOfLinks)
	}
	if decoded.DeletePending != original.DeletePending {
		t.Errorf("DeletePending = %d, want %d", decoded.DeletePending, original.DeletePending)
	}
	if decoded.Directory != original.Directory {
		t.Errorf("Directory = %d, want %d", decoded.Directory, original.Directory)
	}

	// Test error case
	_, err = DecodeFileStandardInfo(make([]byte, 10))
	if err == nil {
		t.Error("DecodeFileStandardInfo() with short data should return error")
	}
}

// TestDecodeQueryPathInfoResponse tests query path info response decoding.
func TestDecodeQueryPathInfoResponse(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		infoLevel uint16
		wantErr   bool
		checkType func(*testing.T, interface{})
	}{
		{
			name: "basic info level",
			data: func() []byte {
				info := &FileBasicInfo{
					CreationTime:   100,
					LastAccessTime: 200,
					LastWriteTime:  300,
					ChangeTime:     400,
					Attributes:     FILE_ATTRIBUTE_NORMAL,
				}
				return EncodeFileBasicInfo(info)
			}(),
			infoLevel: SMB_QUERY_FILE_BASIC_INFO,
			wantErr:   false,
			checkType: func(t *testing.T, result interface{}) {
				info, ok := result.(*FileBasicInfo)
				if !ok {
					t.Errorf("result type = %T, want *FileBasicInfo", result)
				}
				if info.CreationTime != 100 {
					t.Errorf("CreationTime = %d, want 100", info.CreationTime)
				}
			},
		},
		{
			name: "standard info level",
			data: func() []byte {
				info := &FileStandardInfo{
					AllocationSize: 8192,
					EndOfFile:      4096,
					NumberOfLinks:  1,
					Directory:      0,
				}
				return EncodeFileStandardInfo(info)
			}(),
			infoLevel: SMB_QUERY_FILE_STANDARD_INFO,
			wantErr:   false,
			checkType: func(t *testing.T, result interface{}) {
				info, ok := result.(*FileStandardInfo)
				if !ok {
					t.Errorf("result type = %T, want *FileStandardInfo", result)
				}
				if info.AllocationSize != 8192 {
					t.Errorf("AllocationSize = %d, want 8192", info.AllocationSize)
				}
			},
		},
		{
			name:      "unsupported info level returns raw data",
			data:      []byte{0x01, 0x02, 0x03, 0x04},
			infoLevel: 0xFFFF,
			wantErr:   false,
			checkType: func(t *testing.T, result interface{}) {
				data, ok := result.([]byte)
				if !ok {
					t.Errorf("result type = %T, want []byte", result)
				}
				if len(data) != 4 {
					t.Errorf("data length = %d, want 4", len(data))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeQueryPathInfoResponse(tt.data, tt.infoLevel)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeQueryPathInfoResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if tt.checkType != nil {
				tt.checkType(t, result)
			}
		})
	}
}

// TestFileBothDirectoryInfoHelpers tests helper methods on FileBothDirectoryInfo.
func TestFileBothDirectoryInfoHelpers(t *testing.T) {
	tests := []struct {
		name     string
		file     FileBothDirectoryInfo
		isDir    bool
		isHidden bool
		isSystem bool
	}{
		{
			name: "normal file",
			file: FileBothDirectoryInfo{
				FileAttributes: FILE_ATTRIBUTE_NORMAL,
			},
			isDir:    false,
			isHidden: false,
			isSystem: false,
		},
		{
			name: "directory",
			file: FileBothDirectoryInfo{
				FileAttributes: FILE_ATTRIBUTE_DIRECTORY,
			},
			isDir:    true,
			isHidden: false,
			isSystem: false,
		},
		{
			name: "hidden file",
			file: FileBothDirectoryInfo{
				FileAttributes: FILE_ATTRIBUTE_HIDDEN,
			},
			isDir:    false,
			isHidden: true,
			isSystem: false,
		},
		{
			name: "system file",
			file: FileBothDirectoryInfo{
				FileAttributes: FILE_ATTRIBUTE_SYSTEM,
			},
			isDir:    false,
			isHidden: false,
			isSystem: true,
		},
		{
			name: "hidden system directory",
			file: FileBothDirectoryInfo{
				FileAttributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
			},
			isDir:    true,
			isHidden: true,
			isSystem: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.file.IsDirectory() != tt.isDir {
				t.Errorf("IsDirectory() = %v, want %v", tt.file.IsDirectory(), tt.isDir)
			}
			if tt.file.IsHidden() != tt.isHidden {
				t.Errorf("IsHidden() = %v, want %v", tt.file.IsHidden(), tt.isHidden)
			}
			if tt.file.IsSystem() != tt.isSystem {
				t.Errorf("IsSystem() = %v, want %v", tt.file.IsSystem(), tt.isSystem)
			}
		})
	}
}

// TestDecodeQueryFileInfoResponse tests query file info response decoding.
func TestDecodeQueryFileInfoResponse(t *testing.T) {
	// This should behave identically to DecodeQueryPathInfoResponse
	data := EncodeFileBasicInfo(&FileBasicInfo{
		CreationTime: 12345,
		Attributes:   FILE_ATTRIBUTE_ARCHIVE,
	})

	result, err := DecodeQueryFileInfoResponse(data, SMB_QUERY_FILE_BASIC_INFO)
	if err != nil {
		t.Fatalf("DecodeQueryFileInfoResponse() error = %v", err)
	}

	info, ok := result.(*FileBasicInfo)
	if !ok {
		t.Fatalf("result type = %T, want *FileBasicInfo", result)
	}

	if info.CreationTime != 12345 {
		t.Errorf("CreationTime = %d, want 12345", info.CreationTime)
	}
	if info.Attributes != FILE_ATTRIBUTE_ARCHIVE {
		t.Errorf("Attributes = 0x%08x, want 0x%08x", info.Attributes, FILE_ATTRIBUTE_ARCHIVE)
	}
}

// TestLargeDirectoryListing tests parsing of large directory listings with many entries.
func TestLargeDirectoryListing(t *testing.T) {
	// Create data with 10 entries
	numEntries := 10
	var allData []byte

	for i := 0; i < numEntries; i++ {
		entry := make([]byte, 94+10) // Fixed part + 5-char Unicode name
		if i < numEntries-1 {
			binary.LittleEndian.PutUint32(entry[0:4], 104) // NextEntryOffset
		} else {
			binary.LittleEndian.PutUint32(entry[0:4], 0) // Last entry
		}
		binary.LittleEndian.PutUint32(entry[4:8], uint32(i))        // FileIndex
		binary.LittleEndian.PutUint64(entry[40:48], uint64(i*1000)) // EndOfFile
		binary.LittleEndian.PutUint32(entry[56:60], FILE_ATTRIBUTE_NORMAL)
		binary.LittleEndian.PutUint32(entry[60:64], 10) // FileNameLength

		// Create filename like "F00", "F01", etc.
		filename := []byte{byte('F'), byte('0' + i/10), byte('0' + i%10), 0, 0}
		name := utf16le.EncodeStringToBytes(string(filename[:3]))
		copy(entry[94:], name)

		allData = append(allData, entry...)
	}

	result, err := ParseFileBothDirectoryInfo(allData)
	if err != nil {
		t.Fatalf("ParseFileBothDirectoryInfo() error = %v", err)
	}

	if len(result.Files) != numEntries {
		t.Errorf("got %d files, want %d", len(result.Files), numEntries)
	}

	// Verify each entry
	for i, file := range result.Files {
		if file.FileIndex != uint32(i) {
			t.Errorf("files[%d].FileIndex = %d, want %d", i, file.FileIndex, i)
		}
		if file.EndOfFile != uint64(i*1000) {
			t.Errorf("files[%d].EndOfFile = %d, want %d", i, file.EndOfFile, i*1000)
		}
	}
}

// TestUnicodeFilenames tests handling of Unicode filenames in directory listings.
func TestUnicodeFilenames(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"ASCII filename", "test.txt"},
		{"Unicode Chinese", "测试文件.txt"},
		{"Unicode Japanese", "テスト.txt"},
		{"Unicode Emoji", "file😀.txt"},
		{"Long filename", "this_is_a_very_long_filename_that_exceeds_the_old_8_3_limit.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode filename
			nameBytes := utf16le.EncodeStringToBytes(tt.filename)

			// Create directory entry
			entry := make([]byte, 94+len(nameBytes))
			binary.LittleEndian.PutUint32(entry[0:4], 0) // NextEntryOffset (last)
			binary.LittleEndian.PutUint32(entry[4:8], 1) // FileIndex
			binary.LittleEndian.PutUint32(entry[56:60], FILE_ATTRIBUTE_NORMAL)
			binary.LittleEndian.PutUint32(entry[60:64], uint32(len(nameBytes))) // FileNameLength
			copy(entry[94:], nameBytes)

			// Parse
			result, err := ParseFileBothDirectoryInfo(entry)
			if err != nil {
				t.Fatalf("ParseFileBothDirectoryInfo() error = %v", err)
			}

			if len(result.Files) != 1 {
				t.Fatalf("got %d files, want 1", len(result.Files))
			}

			if result.Files[0].FileName != tt.filename {
				t.Errorf("FileName = %s, want %s", result.Files[0].FileName, tt.filename)
			}
		})
	}
}

// TestEmptyDirectory tests handling of empty directory listings.
func TestEmptyDirectory(t *testing.T) {
	// Test with completely empty data
	result, err := ParseFileBothDirectoryInfo([]byte{})
	if err != nil {
		t.Fatalf("ParseFileBothDirectoryInfo() error = %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("got %d files from empty data, want 0", len(result.Files))
	}

	// Test with data that's too short for even one entry
	result, err = ParseFileBothDirectoryInfo(make([]byte, 50))
	if err != nil {
		t.Fatalf("ParseFileBothDirectoryInfo() error = %v", err)
	}
	if len(result.Files) != 0 {
		t.Errorf("got %d files from truncated data, want 0", len(result.Files))
	}
}
