package smb1

import (
	"encoding/binary"
	"testing"
)

func TestEncodeQueryFSInfo(t *testing.T) {
	// The FS levels take only the information level — no FID, no path. A
	// longer parameter block would be a different request shape.
	params, err := EncodeQueryFSInfo(SMB_QUERY_FS_SIZE_INFO)
	if err != nil {
		t.Fatalf("EncodeQueryFSInfo: %v", err)
	}
	if len(params) != 2 {
		t.Fatalf("params length = %d, want 2", len(params))
	}
	if got := binary.LittleEndian.Uint16(params); got != SMB_QUERY_FS_SIZE_INFO {
		t.Errorf("encoded level = %#04x, want %#04x", got, SMB_QUERY_FS_SIZE_INFO)
	}
}

func TestDecodeFsSizeInfo(t *testing.T) {
	// A 32 GiB volume with 4 KiB clusters, ~20 GiB free — a small NAS-style
	// volume. 8 sectors/unit * 512 bytes/sector = 4096-byte clusters.
	data := make([]byte, 24)
	binary.LittleEndian.PutUint64(data[0:8], 8388608)  // total units: 32 GiB / 4 KiB
	binary.LittleEndian.PutUint64(data[8:16], 5242880) // free units:  20 GiB / 4 KiB
	binary.LittleEndian.PutUint32(data[16:20], 8)      // sectors per unit
	binary.LittleEndian.PutUint32(data[20:24], 512)    // bytes per sector

	info, err := DecodeFsSizeInfo(data)
	if err != nil {
		t.Fatalf("DecodeFsSizeInfo: %v", err)
	}
	if info.TotalAllocationUnits != 8388608 {
		t.Errorf("TotalAllocationUnits = %d, want 8388608", info.TotalAllocationUnits)
	}
	if info.TotalFreeAllocationUnits != 5242880 {
		t.Errorf("TotalFreeAllocationUnits = %d, want 5242880", info.TotalFreeAllocationUnits)
	}
	if info.SectorsPerAllocationUnit != 8 {
		t.Errorf("SectorsPerAllocationUnit = %d, want 8", info.SectorsPerAllocationUnit)
	}
	if info.BytesPerSector != 512 {
		t.Errorf("BytesPerSector = %d, want 512", info.BytesPerSector)
	}
}

// The 64-bit unit counts are the reason this level exists; a decoder that
// silently narrowed them would misreport large volumes.
func TestDecodeFsSizeInfoLargeVolume(t *testing.T) {
	data := make([]byte, 24)
	const huge = uint64(1) << 40 // beyond anything a uint32 could hold
	binary.LittleEndian.PutUint64(data[0:8], huge)
	binary.LittleEndian.PutUint64(data[8:16], huge/2)
	binary.LittleEndian.PutUint32(data[16:20], 1)
	binary.LittleEndian.PutUint32(data[20:24], 4096)

	info, err := DecodeFsSizeInfo(data)
	if err != nil {
		t.Fatalf("DecodeFsSizeInfo: %v", err)
	}
	if info.TotalAllocationUnits != huge {
		t.Errorf("TotalAllocationUnits = %d, want %d", info.TotalAllocationUnits, huge)
	}
	if info.TotalFreeAllocationUnits != huge/2 {
		t.Errorf("TotalFreeAllocationUnits = %d, want %d", info.TotalFreeAllocationUnits, huge/2)
	}
}

func TestDecodeFsSizeInfoShort(t *testing.T) {
	for _, n := range []int{0, 1, 23} {
		if _, err := DecodeFsSizeInfo(make([]byte, n)); err == nil {
			t.Errorf("DecodeFsSizeInfo(%d bytes) = nil error, want failure", n)
		}
	}
}

func TestDecodeFsAllocationInfo(t *testing.T) {
	data := make([]byte, 18)
	binary.LittleEndian.PutUint32(data[0:4], 0)        // file system id
	binary.LittleEndian.PutUint32(data[4:8], 8)        // sectors per unit
	binary.LittleEndian.PutUint32(data[8:12], 8388608) // total units
	binary.LittleEndian.PutUint32(data[12:16], 5242880)
	binary.LittleEndian.PutUint16(data[16:18], 512) // bytes per sector

	info, err := DecodeFsAllocationInfo(data)
	if err != nil {
		t.Fatalf("DecodeFsAllocationInfo: %v", err)
	}
	if info.SectorsPerAllocationUnit != 8 {
		t.Errorf("SectorsPerAllocationUnit = %d, want 8", info.SectorsPerAllocationUnit)
	}
	if info.TotalAllocationUnits != 8388608 {
		t.Errorf("TotalAllocationUnits = %d, want 8388608", info.TotalAllocationUnits)
	}
	if info.FreeAllocationUnits != 5242880 {
		t.Errorf("FreeAllocationUnits = %d, want 5242880", info.FreeAllocationUnits)
	}
	if info.BytesPerSector != 512 {
		t.Errorf("BytesPerSector = %d, want 512", info.BytesPerSector)
	}
}

func TestDecodeFsAllocationInfoShort(t *testing.T) {
	for _, n := range []int{0, 17} {
		if _, err := DecodeFsAllocationInfo(make([]byte, n)); err == nil {
			t.Errorf("DecodeFsAllocationInfo(%d bytes) = nil error, want failure", n)
		}
	}
}

func TestDecodeFsVolumeInfo(t *testing.T) {
	label := "TESTVOL"
	labelBytes := encodeUTF16LE(label)

	data := make([]byte, 18+len(labelBytes))
	binary.LittleEndian.PutUint64(data[0:8], 133000000000000000) // creation FILETIME
	binary.LittleEndian.PutUint32(data[8:12], 0xDEADBEEF)        // serial
	binary.LittleEndian.PutUint32(data[12:16], uint32(len(labelBytes)))
	binary.LittleEndian.PutUint16(data[16:18], 0) // reserved
	copy(data[18:], labelBytes)

	info, err := DecodeFsVolumeInfo(data)
	if err != nil {
		t.Fatalf("DecodeFsVolumeInfo: %v", err)
	}
	if info.SerialNumber != 0xDEADBEEF {
		t.Errorf("SerialNumber = %#x, want 0xDEADBEEF", info.SerialNumber)
	}
	if info.Label != label {
		t.Errorf("Label = %q, want %q", info.Label, label)
	}
	if info.VolumeCreationTime != 133000000000000000 {
		t.Errorf("VolumeCreationTime = %d, want 133000000000000000", info.VolumeCreationTime)
	}
}

// A server may report a label length longer than the bytes it actually sent.
// Trusting it would slice out of range; the serial number is still usable.
func TestDecodeFsVolumeInfoOverlongLabelLength(t *testing.T) {
	data := make([]byte, 18+4)
	binary.LittleEndian.PutUint32(data[8:12], 0x12345678)
	binary.LittleEndian.PutUint32(data[12:16], 9999) // lies: only 4 bytes follow
	copy(data[18:], encodeUTF16LE("ab"))

	info, err := DecodeFsVolumeInfo(data)
	if err != nil {
		t.Fatalf("DecodeFsVolumeInfo: %v", err)
	}
	if info.SerialNumber != 0x12345678 {
		t.Errorf("SerialNumber = %#x, want 0x12345678", info.SerialNumber)
	}
	if info.Label != "ab" {
		t.Errorf("Label = %q, want %q", info.Label, "ab")
	}
}

// A serial number with no label is a normal answer, not an error.
func TestDecodeFsVolumeInfoNoLabel(t *testing.T) {
	data := make([]byte, 18)
	binary.LittleEndian.PutUint32(data[8:12], 0xCAFEBABE)
	binary.LittleEndian.PutUint32(data[12:16], 0)

	info, err := DecodeFsVolumeInfo(data)
	if err != nil {
		t.Fatalf("DecodeFsVolumeInfo: %v", err)
	}
	if info.SerialNumber != 0xCAFEBABE {
		t.Errorf("SerialNumber = %#x, want 0xCAFEBABE", info.SerialNumber)
	}
	if info.Label != "" {
		t.Errorf("Label = %q, want empty", info.Label)
	}
}

func TestDecodeFsVolumeInfoShort(t *testing.T) {
	for _, n := range []int{0, 17} {
		if _, err := DecodeFsVolumeInfo(make([]byte, n)); err == nil {
			t.Errorf("DecodeFsVolumeInfo(%d bytes) = nil error, want failure", n)
		}
	}
}

func encodeUTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}
