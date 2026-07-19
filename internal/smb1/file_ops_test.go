package smb1

import (
	"encoding/binary"
	"testing"
)

func TestEncodeNTCreateRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *NTCreateRequest
		wantErr bool
		check   func(*testing.T, []byte, []byte)
	}{
		{
			name: "basic file open with ASCII",
			req: &NTCreateRequest{
				AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
				NameLength:         9,
				Flags:              0,
				RootDirectoryFID:   0,
				DesiredAccess:      GENERIC_READ | GENERIC_WRITE,
				AllocationSize:     0,
				FileAttributes:     FILE_ATTRIBUTE_NORMAL,
				ShareAccess:        FILE_SHARE_READ | FILE_SHARE_WRITE,
				CreateDisposition:  FILE_OPEN_IF,
				CreateOptions:      0,
				ImpersonationLevel: SECURITY_IMPERSONATION,
				SecurityFlags:      0,
				FileName:           "test.txt",
				UseUnicode:         false,
			},
			wantErr: false,
			check: func(t *testing.T, params, data []byte) {
				if len(params) != 48 {
					t.Errorf("params length = %d, want 48", len(params))
				}
				desiredAccess := binary.LittleEndian.Uint32(params[15:19])
				if desiredAccess != GENERIC_READ|GENERIC_WRITE {
					t.Errorf("DesiredAccess = 0x%08x, want 0x%08x", desiredAccess, GENERIC_READ|GENERIC_WRITE)
				}
			},
		},
		{
			name: "basic file open with Unicode",
			req: &NTCreateRequest{
				AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
				DesiredAccess:      GENERIC_READ,
				FileAttributes:     FILE_ATTRIBUTE_NORMAL,
				ShareAccess:        FILE_SHARE_READ,
				CreateDisposition:  FILE_OPEN,
				CreateOptions:      0,
				ImpersonationLevel: SECURITY_IMPERSONATION,
				FileName:           "file.dat",
				UseUnicode:         true,
			},
			wantErr: false,
			check: func(t *testing.T, params, data []byte) {
				if len(params) != 48 {
					t.Errorf("params length = %d, want 48", len(params))
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
			req: &NTCreateRequest{
				FileName:   "",
				UseUnicode: false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeNTCreateRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeNTCreateRequest() error = %v, wantErr %v", err, tt.wantErr)
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

func TestDecodeNTCreateResponse(t *testing.T) {
	tests := []struct {
		name    string
		params  []byte
		data    []byte
		want    *NTCreateResponse
		wantErr bool
	}{
		{
			name: "valid file response",
			params: func() []byte {
				p := make([]byte, 68)
				p[0] = SMB_COM_NO_ANDX_COMMAND
				p[4] = OPLOCK_NONE
				binary.LittleEndian.PutUint16(p[5:7], 1234) // FID
				binary.LittleEndian.PutUint32(p[7:11], FILE_OPENED)
				binary.LittleEndian.PutUint64(p[11:19], 0) // CreationTime
				binary.LittleEndian.PutUint64(p[19:27], 0) // LastAccessTime
				binary.LittleEndian.PutUint64(p[27:35], 0) // LastWriteTime
				binary.LittleEndian.PutUint64(p[35:43], 0) // ChangeTime
				binary.LittleEndian.PutUint32(p[43:47], FILE_ATTRIBUTE_NORMAL)
				binary.LittleEndian.PutUint64(p[47:55], 4096) // AllocationSize
				binary.LittleEndian.PutUint64(p[55:63], 1024) // EndOfFile
				binary.LittleEndian.PutUint16(p[63:65], FILE_TYPE_DISK)
				binary.LittleEndian.PutUint16(p[65:67], 0) // IPCState
				p[67] = 0                                  // IsDirectory
				return p
			}(),
			data: []byte{},
			want: &NTCreateResponse{
				AndXCommand:    SMB_COM_NO_ANDX_COMMAND,
				OpLockLevel:    OPLOCK_NONE,
				FID:            1234,
				CreateAction:   FILE_OPENED,
				FileAttributes: FILE_ATTRIBUTE_NORMAL,
				AllocationSize: 4096,
				EndOfFile:      1024,
				FileType:       FILE_TYPE_DISK,
				IsDirectory:    0,
			},
			wantErr: false,
		},
		{
			name: "valid directory response",
			params: func() []byte {
				p := make([]byte, 68)
				p[0] = SMB_COM_NO_ANDX_COMMAND
				p[4] = OPLOCK_NONE
				binary.LittleEndian.PutUint16(p[5:7], 5678)
				binary.LittleEndian.PutUint32(p[7:11], FILE_CREATED)
				binary.LittleEndian.PutUint32(p[43:47], FILE_ATTRIBUTE_DIRECTORY)
				binary.LittleEndian.PutUint64(p[47:55], 0)
				binary.LittleEndian.PutUint64(p[55:63], 0)
				binary.LittleEndian.PutUint16(p[63:65], FILE_TYPE_DISK)
				p[67] = 1 // IsDirectory
				return p
			}(),
			data: []byte{},
			want: &NTCreateResponse{
				FID:            5678,
				CreateAction:   FILE_CREATED,
				FileAttributes: FILE_ATTRIBUTE_DIRECTORY,
				IsDirectory:    1,
			},
			wantErr: false,
		},
		{
			name:    "params too short",
			params:  make([]byte, 50),
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeNTCreateResponse(tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeNTCreateResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.FID != tt.want.FID {
				t.Errorf("FID = %d, want %d", got.FID, tt.want.FID)
			}
			if got.CreateAction != tt.want.CreateAction {
				t.Errorf("CreateAction = 0x%08x, want 0x%08x", got.CreateAction, tt.want.CreateAction)
			}
			if got.IsDirectory != tt.want.IsDirectory {
				t.Errorf("IsDirectory = %d, want %d", got.IsDirectory, tt.want.IsDirectory)
			}
		})
	}
}

func TestEncodeReadRequest(t *testing.T) {
	tests := []struct {
		name               string
		req                *ReadRequest
		supportsLargeFiles bool
		wantErr            bool
		checkParamsLen     int
	}{
		{
			name: "basic read without large files",
			req: &ReadRequest{
				AndXCommand:             SMB_COM_NO_ANDX_COMMAND,
				FID:                     1234,
				Offset:                  0,
				MaxCountOfBytesToReturn: 4096,
				MinCountOfBytesToReturn: 0,
				Timeout:                 0,
				Remaining:               0,
			},
			supportsLargeFiles: false,
			wantErr:            false,
			checkParamsLen:     20,
		},
		{
			name: "basic read with large files",
			req: &ReadRequest{
				AndXCommand:             SMB_COM_NO_ANDX_COMMAND,
				FID:                     5678,
				Offset:                  0x100000000, // 4GB
				MaxCountOfBytesToReturn: 8192,
				MinCountOfBytesToReturn: 0,
				Timeout:                 0,
				Remaining:               0,
			},
			supportsLargeFiles: true,
			wantErr:            false,
			checkParamsLen:     24,
		},
		{
			name:               "nil request",
			req:                nil,
			supportsLargeFiles: false,
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeReadRequest(tt.req, tt.supportsLargeFiles, false)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeReadRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if len(params) != tt.checkParamsLen {
				t.Errorf("params length = %d, want %d", len(params), tt.checkParamsLen)
			}

			if len(data) != 0 {
				t.Errorf("data length = %d, want 0", len(data))
			}
		})
	}
}

func TestDecodeReadResponse(t *testing.T) {
	tests := []struct {
		name    string
		params  []byte
		data    []byte
		want    *ReadResponse
		wantErr bool
	}{
		{
			name: "valid read response",
			params: func() []byte {
				p := make([]byte, 24)
				p[0] = SMB_COM_NO_ANDX_COMMAND
				binary.LittleEndian.PutUint16(p[4:6], 0)    // Remaining
				binary.LittleEndian.PutUint16(p[6:8], 0)    // DataCompactionMode
				binary.LittleEndian.PutUint16(p[8:10], 0)   // Reserved
				binary.LittleEndian.PutUint16(p[10:12], 10) // DataLength
				binary.LittleEndian.PutUint16(p[12:14], 0)  // DataOffset
				binary.LittleEndian.PutUint32(p[14:18], 0)  // DataLengthHigh
				return p
			}(),
			data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			want: &ReadResponse{
				AndXCommand: SMB_COM_NO_ANDX_COMMAND,
				DataLength:  10,
				Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			},
			wantErr: false,
		},
		{
			name:    "params too short",
			params:  make([]byte, 20),
			data:    []byte{},
			wantErr: true,
		},
		{
			name: "data too short",
			params: func() []byte {
				p := make([]byte, 24)
				binary.LittleEndian.PutUint16(p[10:12], 20) // DataLength = 20
				return p
			}(),
			data:    make([]byte, 10), // Only 10 bytes
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeReadResponse(tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeReadResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.DataLength != tt.want.DataLength {
				t.Errorf("DataLength = %d, want %d", got.DataLength, tt.want.DataLength)
			}
			if len(got.Data) != len(tt.want.Data) {
				t.Errorf("Data length = %d, want %d", len(got.Data), len(tt.want.Data))
			}
		})
	}
}

func TestEncodeWriteRequest(t *testing.T) {
	tests := []struct {
		name               string
		req                *WriteRequest
		supportsLargeFiles bool
		wantErr            bool
		checkParamsLen     int
	}{
		{
			name: "basic write without large files",
			req: &WriteRequest{
				AndXCommand: SMB_COM_NO_ANDX_COMMAND,
				FID:         1234,
				Offset:      0,
				Timeout:     0,
				WriteMode:   WRITE_THROUGH,
				Remaining:   0,
				DataLength:  5,
				Data:        []byte{1, 2, 3, 4, 5},
			},
			supportsLargeFiles: false,
			wantErr:            false,
			checkParamsLen:     24,
		},
		{
			name: "basic write with large files",
			req: &WriteRequest{
				AndXCommand: SMB_COM_NO_ANDX_COMMAND,
				FID:         5678,
				Offset:      0x200000000, // 8GB
				Timeout:     0,
				WriteMode:   0,
				Remaining:   0,
				DataLength:  10,
				Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			},
			supportsLargeFiles: true,
			wantErr:            false,
			checkParamsLen:     28,
		},
		{
			name:               "nil request",
			req:                nil,
			supportsLargeFiles: false,
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeWriteRequest(tt.req, tt.supportsLargeFiles)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeWriteRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if len(params) != tt.checkParamsLen {
				t.Errorf("params length = %d, want %d", len(params), tt.checkParamsLen)
			}

			if !tt.wantErr && len(data) != len(tt.req.Data) {
				t.Errorf("data length = %d, want %d", len(data), len(tt.req.Data))
			}
		})
	}
}

func TestDecodeWriteResponse(t *testing.T) {
	tests := []struct {
		name    string
		params  []byte
		data    []byte
		want    *WriteResponse
		wantErr bool
	}{
		{
			name: "valid write response",
			params: func() []byte {
				p := make([]byte, 12)
				p[0] = SMB_COM_NO_ANDX_COMMAND
				binary.LittleEndian.PutUint16(p[4:6], 100) // Count
				binary.LittleEndian.PutUint16(p[6:8], 0)   // Remaining
				binary.LittleEndian.PutUint32(p[8:12], 0)  // CountHigh
				return p
			}(),
			data: []byte{},
			want: &WriteResponse{
				AndXCommand: SMB_COM_NO_ANDX_COMMAND,
				Count:       100,
				Remaining:   0,
				CountHigh:   0,
			},
			wantErr: false,
		},
		{
			name:    "params too short",
			params:  make([]byte, 8),
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeWriteResponse(tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeWriteResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.Count != tt.want.Count {
				t.Errorf("Count = %d, want %d", got.Count, tt.want.Count)
			}
		})
	}
}

func TestEncodeCloseRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *CloseRequest
		wantErr bool
	}{
		{
			name: "basic close",
			req: &CloseRequest{
				FID:           1234,
				LastWriteTime: 0,
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, data, err := EncodeCloseRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeCloseRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if len(params) != 6 {
				t.Errorf("params length = %d, want 6", len(params))
			}

			if len(data) != 0 {
				t.Errorf("data length = %d, want 0", len(data))
			}
		})
	}
}

func TestDecodeCloseResponse(t *testing.T) {
	tests := []struct {
		name    string
		params  []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid empty response",
			params:  []byte{},
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "invalid response with params",
			params:  []byte{1, 2},
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "invalid response with data",
			params:  []byte{},
			data:    []byte{1, 2},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeCloseResponse(tt.params, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeCloseResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteResponse_GetBytesWritten(t *testing.T) {
	resp := &WriteResponse{
		Count:     0xFFFF,
		CountHigh: 0x0001,
	}

	got := resp.GetBytesWritten()
	want := uint64(0x0001FFFF)

	if got != want {
		t.Errorf("GetBytesWritten() = 0x%X, want 0x%X", got, want)
	}
}

func TestReadResponse_GetDataLength(t *testing.T) {
	resp := &ReadResponse{
		DataLength:     0xFFFF,
		DataLengthHigh: 0x0002,
	}

	got := resp.GetDataLength()
	want := uint64(0x0002FFFF)

	if got != want {
		t.Errorf("GetDataLength() = 0x%X, want 0x%X", got, want)
	}
}

func TestNTCreateResponse_IsDir(t *testing.T) {
	tests := []struct {
		name        string
		isDirectory uint8
		want        bool
	}{
		{
			name:        "is directory",
			isDirectory: 1,
			want:        true,
		},
		{
			name:        "is not directory",
			isDirectory: 0,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &NTCreateResponse{IsDirectory: tt.isDirectory}
			if got := r.IsDir(); got != tt.want {
				t.Errorf("IsDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNTCreateResponse_String(t *testing.T) {
	resp := &NTCreateResponse{
		FID:            1234,
		CreateAction:   FILE_OPENED,
		EndOfFile:      4096,
		FileAttributes: FILE_ATTRIBUTE_NORMAL,
		IsDirectory:    0,
	}

	str := resp.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	t.Logf("String() = %s", str)
}

func TestFileOpsRoundTrip(t *testing.T) {
	// Test NT Create round trip
	createReq := &NTCreateRequest{
		AndXCommand:        SMB_COM_NO_ANDX_COMMAND,
		DesiredAccess:      GENERIC_READ | GENERIC_WRITE,
		FileAttributes:     FILE_ATTRIBUTE_NORMAL,
		ShareAccess:        FILE_SHARE_READ,
		CreateDisposition:  FILE_OPEN_IF,
		CreateOptions:      0,
		ImpersonationLevel: SECURITY_IMPERSONATION,
		FileName:           "test.dat",
		UseUnicode:         false,
	}

	params, _, err := EncodeNTCreateRequest(createReq)
	if err != nil {
		t.Fatalf("EncodeNTCreateRequest() error = %v", err)
	}

	if len(params) != 48 {
		t.Errorf("params length = %d, want 48", len(params))
	}

	// Mock response
	respParams := make([]byte, 68)
	respParams[0] = SMB_COM_NO_ANDX_COMMAND
	respParams[4] = OPLOCK_NONE
	binary.LittleEndian.PutUint16(respParams[5:7], 1234)
	binary.LittleEndian.PutUint32(respParams[7:11], FILE_OPENED)
	binary.LittleEndian.PutUint32(respParams[43:47], FILE_ATTRIBUTE_NORMAL)
	binary.LittleEndian.PutUint64(respParams[55:63], 0)
	respParams[67] = 0

	createResp, err := DecodeNTCreateResponse(respParams, []byte{})
	if err != nil {
		t.Fatalf("DecodeNTCreateResponse() error = %v", err)
	}

	if createResp.FID != 1234 {
		t.Errorf("FID = %d, want 1234", createResp.FID)
	}

	// Test Read round trip
	readReq := &ReadRequest{
		AndXCommand:             SMB_COM_NO_ANDX_COMMAND,
		FID:                     createResp.FID,
		Offset:                  0,
		MaxCountOfBytesToReturn: 4096,
	}

	_, _, err = EncodeReadRequest(readReq, false, false)
	if err != nil {
		t.Fatalf("EncodeReadRequest() error = %v", err)
	}

	// Test Write round trip
	writeReq := &WriteRequest{
		AndXCommand: SMB_COM_NO_ANDX_COMMAND,
		FID:         createResp.FID,
		Offset:      0,
		WriteMode:   WRITE_THROUGH,
		DataLength:  10,
		Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}

	_, _, err = EncodeWriteRequest(writeReq, false)
	if err != nil {
		t.Fatalf("EncodeWriteRequest() error = %v", err)
	}

	// Test Close round trip
	closeReq := &CloseRequest{
		FID:           createResp.FID,
		LastWriteTime: 0,
	}

	_, _, err = EncodeCloseRequest(closeReq)
	if err != nil {
		t.Fatalf("EncodeCloseRequest() error = %v", err)
	}

	_, err = DecodeCloseResponse([]byte{}, []byte{})
	if err != nil {
		t.Fatalf("DecodeCloseResponse() error = %v", err)
	}
}

func TestLargeFileSupport(t *testing.T) {
	// Test read with large offset
	readReq := &ReadRequest{
		AndXCommand:             SMB_COM_NO_ANDX_COMMAND,
		FID:                     1234,
		Offset:                  0x123456789ABC, // Large 64-bit offset
		MaxCountOfBytesToReturn: 4096,
	}

	params, _, err := EncodeReadRequest(readReq, true, false)
	if err != nil {
		t.Fatalf("EncodeReadRequest() error = %v", err)
	}

	if len(params) != 24 {
		t.Errorf("params length = %d, want 24", len(params))
	}

	// Verify offset is correctly encoded
	offsetLow := binary.LittleEndian.Uint32(params[6:10])
	offsetHigh := binary.LittleEndian.Uint32(params[20:24])
	fullOffset := uint64(offsetLow) | (uint64(offsetHigh) << 32)

	if fullOffset != 0x123456789ABC {
		t.Errorf("encoded offset = 0x%X, want 0x%X", fullOffset, 0x123456789ABC)
	}

	// Test write with large offset
	writeReq := &WriteRequest{
		AndXCommand: SMB_COM_NO_ANDX_COMMAND,
		FID:         5678,
		Offset:      0xFEDCBA987654, // Large 64-bit offset
		WriteMode:   0,
		DataLength:  5,
		Data:        []byte{1, 2, 3, 4, 5},
	}

	params, _, err = EncodeWriteRequest(writeReq, true)
	if err != nil {
		t.Fatalf("EncodeWriteRequest() error = %v", err)
	}

	if len(params) != 28 {
		t.Errorf("params length = %d, want 28", len(params))
	}

	// Verify offset is correctly encoded
	offsetLow = binary.LittleEndian.Uint32(params[6:10])
	offsetHigh = binary.LittleEndian.Uint32(params[24:28])
	fullOffset = uint64(offsetLow) | (uint64(offsetHigh) << 32)

	if fullOffset != 0xFEDCBA987654 {
		t.Errorf("encoded offset = 0x%X, want 0x%X", fullOffset, 0xFEDCBA987654)
	}
}
