package smb1

import (
	"errors"
	"os"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// Chtimes changes the access and modification times of the named file,
// mimicking os.Chtimes. If there is an error, it will be of type
// *os.PathError.
//
// It is implemented with TRANS2_SET_PATH_INFORMATION at the
// SMB_SET_FILE_BASIC_INFO level, so the file is not opened. A zero time
// value leaves the corresponding timestamp unchanged: SMB1 encodes it as
// FILETIME 0, which the protocol defines as "do not change".
//
// Servers are free to round the stored times to their filesystem's
// resolution, and some (Samba among them) do not persist access times at
// all; the modification time is the one callers can rely on reading back.
func (fs *Share) Chtimes(name string, atime time.Time, mtime time.Time) error {
	name = normalizePath(name)

	if err := validateFilePath(name); err != nil {
		return &os.PathError{Op: "chtimes", Path: name, Err: err}
	}

	basic := &smb1.FileBasicInfo{
		LastAccessTime: convertTimeToFileTime(atime),
		LastWriteTime:  convertTimeToFileTime(mtime),
	}
	if err := fs.setPathBasicInfo(name, basic); err != nil {
		return mapSMBErrorToOSError(err, "chtimes", name)
	}
	return nil
}

// Chmod changes the mode of the named file, mimicking os.Chmod within what
// SMB attributes can express: when the owner-write bit (0200) is absent the
// file becomes read-only, otherwise read-only is cleared. All other
// attributes are preserved via a read-modify-write of the current attribute
// set, matching go-smb2's behavior. If there is an error, it will be of type
// *os.PathError.
//
// The attribute set normally goes out as TRANS2_SET_PATH_INFORMATION at the
// SMB_SET_FILE_BASIC_INFO level; legacy servers that reject that with
// STATUS_NOT_SUPPORTED get the core-protocol SMB_COM_SET_INFORMATION
// command instead, with the same attribute semantics.
func (fs *Share) Chmod(name string, mode os.FileMode) error {
	name = normalizePath(name)

	if err := validateFilePath(name); err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}

	basic, err := fs.queryPathBasicInfo(name)
	if err != nil {
		return mapSMBErrorToOSError(err, "chmod", name)
	}

	if err := fs.tree.SetPathAttributes(name, chmodAttributes(basic.Attributes, mode), fs.ctx); err != nil {
		return mapSMBErrorToOSError(err, "chmod", name)
	}
	return nil
}

// Chmod changes the mode of the open file, with the same semantics as
// Share.Chmod. If there is an error, it will be of type *os.PathError.
//
// The attribute set normally goes out as TRANS2_SET_FILE_INFORMATION on the
// open handle; legacy servers that reject that with STATUS_NOT_SUPPORTED
// get the core-protocol SMB_COM_SET_INFORMATION command instead, which is
// path-based — it addresses the file by the path it was opened with rather
// than by handle — with the same attribute semantics.
func (f *File) Chmod(mode os.FileMode) error {
	basic, err := f.f.QueryBasicInfo(f.ctx)
	if err != nil {
		return &os.PathError{Op: "chmod", Path: f.name, Err: wrapError(err)}
	}

	if err := f.f.SetAttributes(chmodAttributes(basic.Attributes, mode), f.ctx); err != nil {
		return &os.PathError{Op: "chmod", Path: f.name, Err: wrapError(err)}
	}
	return nil
}

// chmodAttributes applies a Unix mode to an SMB attribute set the way
// go-smb2 does: the owner-write bit is the only expressible permission, and
// it maps to FILE_ATTRIBUTE_READONLY inverted; every other attribute passes
// through untouched.
//
// An attribute value of 0 means "leave unchanged" on the wire, so clearing
// read-only on a file whose only attribute was read-only must send
// FILE_ATTRIBUTE_NORMAL instead — sending 0 would silently keep the file
// read-only.
func chmodAttributes(attrs uint32, mode os.FileMode) uint32 {
	if mode&0200 != 0 {
		attrs &^= smb1.FILE_ATTRIBUTE_READONLY
	} else {
		attrs |= smb1.FILE_ATTRIBUTE_READONLY
	}
	if attrs == 0 {
		attrs = smb1.FILE_ATTRIBUTE_NORMAL
	}
	return attrs
}

// Symlink mimics os.Symlink's signature for go-smb2 parity, but SMB1 has no
// symbolic link operation — the reparse-point FSCTLs go-smb2 uses are SMB2
// constructs — so it always returns an *os.LinkError wrapping
// errors.ErrUnsupported.
func (fs *Share) Symlink(target, linkpath string) error {
	return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: errors.ErrUnsupported}
}

// Readlink mimics os.Readlink's signature for go-smb2 parity, but SMB1 has
// no symbolic link operation — see Symlink — so it always returns an
// *os.PathError wrapping errors.ErrUnsupported.
func (fs *Share) Readlink(name string) (string, error) {
	return "", &os.PathError{Op: "readlink", Path: name, Err: errors.ErrUnsupported}
}

// queryPathBasicInfo queries SMB_QUERY_FILE_BASIC_INFO by path, returning
// the attributes exactly as the server reports them — no directory-flag
// merging — so the result is safe to echo back in a read-modify-write.
func (fs *Share) queryPathBasicInfo(name string) (*smb1.FileBasicInfo, error) {
	useUnicode := (fs.tree.GetCapabilities() & smb1.CAP_UNICODE) != 0
	params, err := smb1.EncodeQueryPathInfo(name, smb1.SMB_QUERY_FILE_BASIC_INFO, useUnicode)
	if err != nil {
		return nil, err
	}

	resp, err := fs.tree.SendTransact2(smb1.TRANS2_QUERY_PATH_INFORMATION, params, nil, fs.ctx)
	if err != nil {
		return nil, err
	}

	return smb1.DecodeFileBasicInfo(resp.Data)
}

// setPathBasicInfo sets SMB_SET_FILE_BASIC_INFO by path. Zero-valued fields
// mean "leave unchanged" on the wire, so callers set only what they intend
// to change.
func (fs *Share) setPathBasicInfo(name string, info *smb1.FileBasicInfo) error {
	useUnicode := (fs.tree.GetCapabilities() & smb1.CAP_UNICODE) != 0
	params, data, err := smb1.EncodeSetPathInfo(name, smb1.SMB_SET_FILE_BASIC_INFO, smb1.EncodeFileBasicInfo(info), useUnicode)
	if err != nil {
		return err
	}

	_, err = fs.tree.SendTransact2(smb1.TRANS2_SET_PATH_INFORMATION, params, data, fs.ctx)
	return err
}
