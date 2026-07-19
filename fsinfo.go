package smb1

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/macourteau/smb1client/internal/client"
	"github.com/macourteau/smb1client/internal/erref"
	"github.com/macourteau/smb1client/internal/smb1"
)

// FileFsInfo describes the capacity of the filesystem backing a mounted
// share. The interface and its field mapping match go-smb2's FileFsInfo:
// BlockSize is the bytes per sector, FragmentSize is the sectors per
// allocation unit, and the three counts are in allocation units — so the
// volume's total capacity in bytes is
// TotalBlockCount() * FragmentSize() * BlockSize().
type FileFsInfo interface {
	BlockSize() uint64
	FragmentSize() uint64
	TotalBlockCount() uint64
	FreeBlockCount() uint64
	AvailableBlockCount() uint64
}

// fileFsSizeInfo backs FileFsInfo with the raw allocation-unit geometry the
// server reported, mirroring go-smb2's fileFsFullSizeInformation accessors.
//
// SMB1's size levels report a single free count — there is no per-caller
// quota figure distinct from the volume-wide one — so AvailableBlockCount
// and FreeBlockCount return the same number.
type fileFsSizeInfo struct {
	totalUnits     uint64
	freeUnits      uint64
	sectorsPerUnit uint64
	bytesPerSector uint64
}

func (fi *fileFsSizeInfo) BlockSize() uint64 {
	return fi.bytesPerSector
}

func (fi *fileFsSizeInfo) FragmentSize() uint64 {
	return fi.sectorsPerUnit
}

func (fi *fileFsSizeInfo) TotalBlockCount() uint64 {
	return fi.totalUnits
}

func (fi *fileFsSizeInfo) FreeBlockCount() uint64 {
	return fi.freeUnits
}

func (fi *fileFsSizeInfo) AvailableBlockCount() uint64 {
	return fi.freeUnits
}

// VolumeInfo identifies the volume backing a mounted share.
//
// SerialNumber is assigned when the volume is formatted, so it distinguishes
// one piece of removable media from another without writing anything to it.
// It is not a strong identifier: it is not unique across the world, and
// reformatting changes it.
type VolumeInfo struct {
	// SerialNumber is the volume serial number assigned at format time.
	SerialNumber uint32

	// Label is the volume label. It is frequently empty, and a server may
	// decline to report it while still reporting a serial number.
	Label string

	// CreationTime is when the volume was created. Servers whose filesystem
	// does not record this report a zero time.
	CreationTime time.Time
}

// Statfs returns the capacity of the filesystem backing the share.
// If there is an error, it will be of type *os.PathError.
//
// The name argument exists for go-smb2 signature parity and is validated and
// normalized like every other path argument (the empty string addresses the
// share root, as go-smb2 allows), but SMB1's TRANS2_QUERY_FS_INFORMATION is
// share-wide — the query is the same whichever path is named, so the name
// does not reach the wire.
//
// It prefers SMB_QUERY_FS_SIZE_INFO, whose unit counts are 64-bit, and falls
// back to the legacy SMB_INFO_ALLOCATION level when the server does not
// support it — the same accommodation ListSharenames makes for servers that
// lack RAP. The legacy level's counts are 32-bit and so cannot describe a
// volume beyond roughly 4 billion allocation units.
func (fs *Share) Statfs(name string) (FileFsInfo, error) {
	name = normalizePath(name)

	// The empty string is a valid Statfs argument — go-smb2 accepts it as the
	// share root — while validateFilePath rejects it for the operations that
	// must name a file.
	if name != "" {
		if err := validateFilePath(name); err != nil {
			return nil, &os.PathError{Op: "statfs", Path: name, Err: err}
		}
	}

	info, err := statfsTree(fs.tree, fs.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: name, Err: wrapError(err)}
	}
	return info, nil
}

// Statfs returns the capacity of the filesystem backing the file's share,
// queried over the tree the file was opened on.
// If there is an error, it will be of type *os.PathError.
func (f *File) Statfs() (FileFsInfo, error) {
	info, err := statfsTree(f.f.Tree(), f.ctx)
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: f.name, Err: wrapError(err)}
	}
	return info, nil
}

// statfsTree runs the capacity query against a tree, preferring the 64-bit
// level and falling back to the legacy one. It is shared by Share.Statfs and
// File.Statfs, whose only difference is which tree the query addresses.
func statfsTree(tree *client.Tree, ctx context.Context) (FileFsInfo, error) {
	logger := LoggerFromContext(ctx)

	info, err := statfsSizeInfo(tree, ctx)
	if err == nil {
		return info, nil
	}
	if !isUnsupportedLevelError(err) {
		return nil, err
	}

	logger.Debug("SMB_QUERY_FS_SIZE_INFO not supported, falling back to SMB_INFO_ALLOCATION")
	info, err = statfsAllocation(tree, ctx)
	if err != nil {
		return nil, fmt.Errorf("smb1: statfs failed (FS_SIZE_INFO unsupported, INFO_ALLOCATION failed): %w", err)
	}
	return info, nil
}

// statfsSizeInfo queries the 64-bit SMB_QUERY_FS_SIZE_INFO level.
func statfsSizeInfo(tree *client.Tree, ctx context.Context) (*fileFsSizeInfo, error) {
	params, err := smb1.EncodeQueryFSInfo(smb1.SMB_QUERY_FS_SIZE_INFO)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode fs size info request: %w", err)
	}

	resp, err := tree.SendTransact2(smb1.TRANS2_QUERY_FS_INFORMATION, params, nil, ctx)
	if err != nil {
		return nil, err
	}

	raw, err := smb1.DecodeFsSizeInfo(resp.Data)
	if err != nil {
		return nil, err
	}

	return newFileFsSizeInfo(raw.TotalAllocationUnits, raw.TotalFreeAllocationUnits,
		uint64(raw.SectorsPerAllocationUnit), uint64(raw.BytesPerSector))
}

// statfsAllocation queries the legacy 32-bit SMB_INFO_ALLOCATION level.
func statfsAllocation(tree *client.Tree, ctx context.Context) (*fileFsSizeInfo, error) {
	params, err := smb1.EncodeQueryFSInfo(smb1.SMB_INFO_ALLOCATION)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode fs allocation info request: %w", err)
	}

	resp, err := tree.SendTransact2(smb1.TRANS2_QUERY_FS_INFORMATION, params, nil, ctx)
	if err != nil {
		return nil, err
	}

	raw, err := smb1.DecodeFsAllocationInfo(resp.Data)
	if err != nil {
		return nil, err
	}

	return newFileFsSizeInfo(uint64(raw.TotalAllocationUnits), uint64(raw.FreeAllocationUnits),
		uint64(raw.SectorsPerAllocationUnit), uint64(raw.BytesPerSector))
}

// newFileFsSizeInfo wraps server-reported geometry, refusing a zero-byte
// allocation unit: every capacity computation a caller can make multiplies by
// it, and a zero there silently turns any volume into "empty". The counts
// themselves pass through unscaled, so they cannot overflow.
func newFileFsSizeInfo(totalUnits, freeUnits, sectorsPerUnit, bytesPerSector uint64) (*fileFsSizeInfo, error) {
	if sectorsPerUnit == 0 || bytesPerSector == 0 {
		return nil, fmt.Errorf("smb1: server reported a zero-byte allocation unit (%d sectors/unit, %d bytes/sector)",
			sectorsPerUnit, bytesPerSector)
	}

	return &fileFsSizeInfo{
		totalUnits:     totalUnits,
		freeUnits:      freeUnits,
		sectorsPerUnit: sectorsPerUnit,
		bytesPerSector: bytesPerSector,
	}, nil
}

// VolumeInfo returns the identity of the volume backing the share.
//
// The serial number answers "is this the same physical media I saw last time"
// without writing a marker file to the share — useful where the share is
// removable and deleting from the wrong one would be destructive.
func (fs *Share) VolumeInfo() (*VolumeInfo, error) {
	params, err := smb1.EncodeQueryFSInfo(smb1.SMB_QUERY_FS_VOLUME_INFO)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode fs volume info request: %w", err)
	}

	resp, err := fs.tree.SendTransact2(smb1.TRANS2_QUERY_FS_INFORMATION, params, nil, fs.ctx)
	if err != nil {
		return nil, err
	}

	raw, err := smb1.DecodeFsVolumeInfo(resp.Data)
	if err != nil {
		return nil, err
	}

	return &VolumeInfo{
		SerialNumber: raw.SerialNumber,
		Label:        raw.Label,
		CreationTime: convertFileTimeToTime(raw.VolumeCreationTime),
	}, nil
}

// isUnsupportedLevelError reports whether err is the server declining an
// information level, as opposed to a transport or permission failure.
//
// It inspects the NT_STATUS code rather than the message text: a server that
// does not implement a level answers with a status, and matching on the
// rendered string would break the moment a message is reworded.
func isUnsupportedLevelError(err error) bool {
	status, ok := ntStatusOf(err)
	if !ok {
		return false
	}

	switch status {
	case smb1.STATUS_INVALID_LEVEL,
		smb1.STATUS_INVALID_INFO_CLASS,
		smb1.STATUS_NOT_SUPPORTED,
		smb1.STATUS_NOT_IMPLEMENTED,
		smb1.STATUS_INVALID_PARAMETER:
		// Servers are not consistent about how they decline a level they do
		// not implement: INVALID_LEVEL and INVALID_INFO_CLASS say so directly,
		// while older ones reject it as unsupported, unimplemented, or merely
		// as a bad parameter. The request carries nothing except the level, so
		// there is little else any of them could be objecting to.
		//
		// A false positive here costs one extra round trip at the legacy
		// level, whose own failure still propagates; a false negative denies
		// the fallback to precisely the servers it exists for.
		return true
	}
	return false
}

// ntStatusOf extracts the NT_STATUS code from err, reporting whether one was
// found. It accepts every shape an NT status reaches callers in, at any depth
// of wrapping.
func ntStatusOf(err error) (uint32, bool) {
	if err == nil {
		return 0, false
	}

	// erref.NtStatus first: this is what StatusToError returns, so it is what
	// an error originating at the wire actually is. The two struct types below
	// are part of the public error vocabulary but are never produced by the
	// receive path, so checking only for them would classify nothing.
	var ntStatus erref.NtStatus
	if errors.As(err, &ntStatus) {
		return uint32(ntStatus), true
	}

	var respErr *ResponseError
	if errors.As(err, &respErr) {
		return respErr.Code, true
	}

	var smbErr *SMBError
	if errors.As(err, &smbErr) {
		return smbErr.Status, true
	}

	return 0, false
}
