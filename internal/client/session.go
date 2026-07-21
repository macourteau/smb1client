package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/macourteau/smb1client/internal/dcerpc"
	"github.com/macourteau/smb1client/internal/erref"
	"github.com/macourteau/smb1client/internal/logging"
	"github.com/macourteau/smb1client/internal/ntlm"
	"github.com/macourteau/smb1client/internal/smb1"
)

// Initiator is the interface for NTLM authentication.
// It's implemented by ntlm.Client in the internal package.
type Initiator interface {
	Negotiate() ([]byte, error)
	Authenticate(challengeMsg []byte) ([]byte, error)
	Session() *ntlm.Session
}

// Session represents an authenticated SMB1 session.
// A session is created after successful session setup (authentication).
// This type is exported for use by the public API layer.
type Session struct {
	conn      *Conn            // underlying connection
	uid       uint16           // user ID from session setup
	initiator Initiator        // NTLM authenticator
	mu        sync.Mutex       // protects trees map
	trees     map[uint16]*Tree // active tree connections by TID
}

// Tree represents a connection to a share (tree connect).
// Multiple trees can be active on a single session.
// This type is exported for use by the public API layer.
type Tree struct {
	Session          *Session // parent session
	TID              uint16   // tree ID
	Path             string   // UNC path (e.g., \\server\share)
	Service          string   // service type (e.g., "A:", "IPC")
	OptionalSupport  uint16   // optional support flags from server
	NativeFileSystem string   // native file system (e.g., "NTFS")
}

// NewSession creates a new SMB1 session by performing session setup.
// It uses the provided Initiator for NTLM authentication.
// The session setup process involves two round trips:
// 1. Send NTLM negotiate message (receive challenge)
// 2. Send NTLM authenticate message (receive session UID)
func NewSession(c *Conn, initiator Initiator, ctx context.Context) (*Session, error) {
	logger := logging.FromContext(ctx)
	logger.Debug("NewSession: starting session setup")

	// Create session struct
	s := &Session{
		conn:      c,
		initiator: initiator,
		trees:     make(map[uint16]*Tree),
	}

	// Round 1: Send NTLM negotiate
	logger.Debug("NewSession: sending NTLM negotiate")
	nmsg, err := initiator.Negotiate()
	if err != nil {
		return nil, fmt.Errorf("smb1: NTLM negotiate failed: %w", err)
	}

	// Create session setup request with negotiate message
	req := &smb1.SessionSetupRequest{
		AndXCommand:        smb1.SMB_COM_NO_ANDX_COMMAND,
		MaxBufferSize:      uint16(c.maxBufferSize),
		MaxMpxCount:        c.maxMpxCount,
		VcNumber:           0,
		SessionKey:         c.sessionKey,
		SecurityBlobLength: uint16(len(nmsg)),
		Capabilities:       c.capabilities,
		SecurityBlob:       nmsg,
		NativeOS:           "Unix",
		NativeLanMan:       "smb1client",
		UseUnicode:         (c.capabilities & smb1.CAP_UNICODE) != 0,
	}

	params, data, err := smb1.EncodeSessionSetupRequest(req)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode session setup request: %w", err)
	}

	header := smb1.NewHeader(smb1.SMB_COM_SESSION_SETUP_ANDX)
	resp, err := c.sendRecv(header, params, data, ctx)
	if err != nil {
		return nil, fmt.Errorf("smb1: session setup (negotiate) failed: %w", err)
	}

	// Check status - could be STATUS_MORE_PROCESSING_REQUIRED (2-round) or STATUS_SUCCESS (1-round, e.g., guest)
	if resp.header.Status == smb1.STATUS_SUCCESS {
		// Single-round authentication succeeded (e.g., guest account)
		logger.Debug("NewSession: single-round authentication succeeded (UID=%d)", resp.header.UID)
		_, err := smb1.DecodeSessionSetupResponse(resp.params, resp.data, req.UseUnicode)
		if err != nil {
			return nil, fmt.Errorf("smb1: failed to decode session setup response: %w", err)
		}

		return &Session{
			conn:  c,
			uid:   resp.header.UID,
			trees: make(map[uint16]*Tree),
		}, nil
	}

	if resp.header.Status != smb1.STATUS_MORE_PROCESSING_REQUIRED {
		if resp.err != nil {
			return nil, fmt.Errorf("smb1: session setup (negotiate) returned error: %w", resp.err)
		}
		return nil, fmt.Errorf("smb1: unexpected status in session setup (negotiate): 0x%08X", resp.header.Status)
	}

	// Decode session setup response
	setupResp, err := smb1.DecodeSessionSetupResponse(resp.params, resp.data, req.UseUnicode)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to decode session setup response: %w", err)
	}

	// Round 2: Send NTLM authenticate with challenge
	logger.Debug("NewSession: sending NTLM authenticate")
	amsg, err := initiator.Authenticate(setupResp.SecurityBlob)
	if err != nil {
		return nil, fmt.Errorf("smb1: NTLM authenticate failed: %w", err)
	}

	// Create second session setup request with authenticate message
	req2 := &smb1.SessionSetupRequest{
		AndXCommand:        smb1.SMB_COM_NO_ANDX_COMMAND,
		MaxBufferSize:      uint16(c.maxBufferSize),
		MaxMpxCount:        c.maxMpxCount,
		VcNumber:           0,
		SessionKey:         c.sessionKey,
		SecurityBlobLength: uint16(len(amsg)),
		Capabilities:       c.capabilities,
		SecurityBlob:       amsg,
		NativeOS:           "Unix",
		NativeLanMan:       "smb1client",
		UseUnicode:         req.UseUnicode,
	}

	params2, data2, err := smb1.EncodeSessionSetupRequest(req2)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode session setup request: %w", err)
	}

	header2 := smb1.NewHeader(smb1.SMB_COM_SESSION_SETUP_ANDX)
	// Use UID from first response
	header2.UID = resp.header.UID

	resp2, err := c.sendRecv(header2, params2, data2, ctx)
	if err != nil {
		return nil, fmt.Errorf("smb1: session setup (authenticate) failed: %w", err)
	}

	// Check for errors
	if resp2.err != nil {
		return nil, fmt.Errorf("smb1: session setup (authenticate) returned error: %w", resp2.err)
	}

	// Store UID from response
	s.uid = resp2.header.UID
	logger.Debug("NewSession: session setup complete (UID=%d)", s.uid)

	return s, nil
}

// send sends an SMB request with the session's UID set.
func (s *Session) send(header *smb1.Header, params, data []byte) error {
	header.UID = s.uid
	return s.conn.send(header, params, data)
}

// sendRecv sends an SMB request with the session's UID set and waits for response.
func (s *Session) sendRecv(header *smb1.Header, params, data []byte, ctx context.Context) (*response, error) {
	header.UID = s.uid
	return s.conn.sendRecv(header, params, data, ctx)
}

// Logoff performs SMB_COM_LOGOFF_ANDX to close the session.
// After logoff, the session should not be used.
func (s *Session) Logoff(ctx context.Context) error {
	logger := logging.FromContext(ctx)
	logger.Debug("Logoff: logging off session (UID=%d)", s.uid)

	// Create logoff request (WordCount = 2, no data)
	params := make([]byte, 4)
	params[0] = smb1.SMB_COM_NO_ANDX_COMMAND // AndXCommand
	params[1] = 0                            // AndXReserved
	// AndXOffset = 0 (already zero)

	header := smb1.NewHeader(smb1.SMB_COM_LOGOFF_ANDX)
	header.UID = s.uid

	resp, err := s.conn.sendRecv(header, params, nil, ctx)
	if err != nil {
		return fmt.Errorf("smb1: logoff failed: %w", err)
	}

	if resp.err != nil {
		return fmt.Errorf("smb1: logoff returned error: %w", resp.err)
	}

	return nil
}

// TreeConnect connects to a share on the server.
// The path should be in UNC format (e.g., "\\server\share").
// Returns a tree handle that can be used for file operations.
func (s *Session) TreeConnect(path string, ctx context.Context) (*Tree, error) {
	logger := logging.FromContext(ctx)
	logger.Debug("TreeConnect: connecting to %s", path)

	// Determine service type based on share name
	service := smb1.SERVICE_DISK_SHARE // Default to disk share ("A:")
	if strings.HasSuffix(strings.ToUpper(path), "\\IPC$") {
		service = smb1.SERVICE_IPC // Use "IPC" for IPC$ share
	}

	// Per impacket reference implementation, SMB1 paths must be UPPERCASE
	// and should use the resolved IP address
	path = strings.ToUpper(path)

	// Create tree connect request
	// Note: When using extended security, PasswordLength must be 1 and Password
	// must be a single null padding byte, per [MS-CIFS] section 3.2.4.2.5
	req := &smb1.TreeConnectRequest{
		AndXCommand:    smb1.SMB_COM_NO_ANDX_COMMAND,
		Flags:          0,
		PasswordLength: 1,
		Password:       []byte{0x00}, // Required null padding byte for extended security
		Path:           path,
		Service:        service,
		UseUnicode:     (s.conn.capabilities & smb1.CAP_UNICODE) != 0,
	}

	params, data, err := smb1.EncodeTreeConnectRequest(req)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to encode tree connect request: %w", err)
	}

	header := smb1.NewHeader(smb1.SMB_COM_TREE_CONNECT_ANDX)
	header.UID = s.uid
	// TID should be 0xFFFF for tree connect (not yet connected)
	header.TID = 0xFFFF

	resp, err := s.conn.sendRecv(header, params, data, ctx)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("smb1: tree connect failed (status 0x%08X): %w", resp.header.Status, err)
		}
		return nil, fmt.Errorf("smb1: tree connect failed: %w", err)
	}

	if resp.err != nil {
		return nil, fmt.Errorf("smb1: tree connect returned error (status 0x%08X): %w", resp.header.Status, resp.err)
	}

	// Decode tree connect response
	treeResp, err := smb1.DecodeTreeConnectResponse(resp.params, resp.data, req.UseUnicode)
	if err != nil {
		return nil, fmt.Errorf("smb1: failed to decode tree connect response: %w", err)
	}

	// Create tree struct
	t := &Tree{
		Session:          s,
		TID:              resp.header.TID,
		Path:             path,
		Service:          treeResp.Service,
		OptionalSupport:  treeResp.OptionalSupport,
		NativeFileSystem: treeResp.NativeFileSystem,
	}

	// Store in session's tree map
	s.mu.Lock()
	s.trees[t.TID] = t
	s.mu.Unlock()

	logger.Debug("TreeConnect: connected to %s (TID=%d)", path, t.TID)

	return t, nil
}

// TreeDisconnect disconnects from a share.
func (s *Session) TreeDisconnect(tid uint16, ctx context.Context) error {
	logger := logging.FromContext(ctx)
	logger.Debug("TreeDisconnect: disconnecting from TID=%d", tid)

	// Create tree disconnect request (empty)
	params, data, err := smb1.EncodeTreeDisconnectRequest()
	if err != nil {
		return fmt.Errorf("smb1: failed to encode tree disconnect request: %w", err)
	}

	header := smb1.NewHeader(smb1.SMB_COM_TREE_DISCONNECT)
	header.UID = s.uid
	header.TID = tid

	resp, err := s.conn.sendRecv(header, params, data, ctx)
	if err != nil {
		return fmt.Errorf("smb1: tree disconnect failed: %w", err)
	}

	if resp.err != nil {
		return fmt.Errorf("smb1: tree disconnect returned error: %w", resp.err)
	}

	// Remove from trees map
	s.mu.Lock()
	delete(s.trees, tid)
	s.mu.Unlock()

	return nil
}

// GetCapabilities returns the negotiated capabilities for the session.
func (t *Tree) GetCapabilities() uint32 {
	return t.Session.conn.capabilities
}

// SendTransact2 sends a TRANS2 request and returns the decoded response.
// This is a helper for the public API layer to send TRANS2 commands.
func (t *Tree) SendTransact2(subcommand uint16, params, data []byte, ctx context.Context) (*smb1.Trans2Response, error) {
	// Encode TRANS2 request
	allParams, dataBytes, err := smb1.EncodeTrans2Request(
		[]uint16{subcommand},
		params,
		data,
		"",
	)
	if err != nil {
		return nil, err
	}

	header := smb1.NewHeader(smb1.SMB_COM_TRANSACTION2)
	header.UID = t.Session.uid
	header.TID = t.TID

	resp, trans2Resp, err := t.Session.conn.sendRecvTransaction(header, allParams, dataBytes, ctx)
	if err != nil {
		return nil, err
	}

	// For TRANS2, we need to decode the response even if there's a warning status
	// (e.g., STATUS_NO_MORE_FILES). We only fail on actual errors.
	if resp.err != nil && resp.header.IsError() {
		return nil, resp.err
	}

	// If there was a warning status, preserve it in the response
	// (caller may want to check for STATUS_NO_MORE_FILES, etc.)
	if resp.err != nil {
		trans2Resp.Status = resp.header.Status
	}

	return trans2Resp, nil
}

// SendRename sends a RENAME command.
// This is a helper for the public API layer.
func (t *Tree) SendRename(oldpath, newpath string, ctx context.Context) error {
	// SearchAttributes for files to rename.
	// Use same attributes as smbclient: HIDDEN | SYSTEM | DIRECTORY
	req := &smb1.RenameRequest{
		SearchAttributes: 0x0016, // HIDDEN (0x0002) | SYSTEM (0x0004) | DIRECTORY (0x0010)
		OldFileName:      oldpath,
		NewFileName:      newpath,
		UseUnicode:       (t.Session.conn.capabilities & smb1.CAP_UNICODE) != 0,
	}

	params, data, err := smb1.EncodeRenameRequest(req)
	if err != nil {
		return err
	}

	header := smb1.NewHeader(smb1.SMB_COM_RENAME)
	header.UID = t.Session.uid
	header.TID = t.TID

	resp, err := t.Session.conn.sendRecv(header, params, data, ctx)
	if err != nil {
		return err
	}

	if resp.err != nil {
		return resp.err
	}

	// Decode rename response (should be empty)
	_, err = smb1.DecodeRenameResponse(resp.params, resp.data)
	return err
}

// SendSetInformation sends a core-protocol SMB_COM_SET_INFORMATION request,
// setting the DOS file attributes (and optionally the UTIME last-write time;
// 0 leaves it unchanged) of the file at path. This is the legacy set-attributes
// path for servers that reject the TRANS2 information levels.
func (t *Tree) SendSetInformation(path string, attrs uint16, lastWriteTime uint32, ctx context.Context) error {
	req := &smb1.SetInformationRequest{
		FileAttributes: attrs,
		LastWriteTime:  lastWriteTime,
		FileName:       path,
		UseUnicode:     (t.Session.conn.capabilities & smb1.CAP_UNICODE) != 0,
	}

	params, data, err := smb1.EncodeSetInformationRequest(req)
	if err != nil {
		return err
	}

	header := smb1.NewHeader(smb1.SMB_COM_SET_INFORMATION)
	header.UID = t.Session.uid
	header.TID = t.TID

	resp, err := t.Session.conn.sendRecv(header, params, data, ctx)
	if err != nil {
		return err
	}

	if resp.err != nil {
		return resp.err
	}

	// Decode set information response (should be empty)
	return smb1.DecodeSetInformationResponse(resp.params, resp.data)
}

// SetPathAttributes sets the extended file attributes of the file at path.
// It first tries TRANS2_SET_PATH_INFORMATION at the SMB_SET_FILE_BASIC_INFO
// level, with all timestamps zero ("leave unchanged"). Legacy servers that
// reject attribute changes at that level with STATUS_NOT_SUPPORTED get the
// core-protocol SMB_COM_SET_INFORMATION fallback instead, which carries the
// DOS 16-bit attribute subset (see dosAttributes). Any other error is
// returned as-is, with no fallback attempt.
func (t *Tree) SetPathAttributes(path string, attrs uint32, ctx context.Context) error {
	useUnicode := (t.GetCapabilities() & smb1.CAP_UNICODE) != 0
	info := &smb1.FileBasicInfo{Attributes: attrs}
	params, data, err := smb1.EncodeSetPathInfo(path, smb1.SMB_SET_FILE_BASIC_INFO, smb1.EncodeFileBasicInfo(info), useUnicode)
	if err != nil {
		return err
	}

	_, err = t.SendTransact2(smb1.TRANS2_SET_PATH_INFORMATION, params, data, ctx)
	if err == nil || !errors.Is(err, erref.STATUS_NOT_SUPPORTED) {
		return err
	}

	return t.SendSetInformation(path, dosAttributes(attrs), 0, ctx)
}

// dosAttributes maps 32-bit extended file attributes onto the 16-bit DOS
// attribute set carried by the core-protocol SMB_COM_SET_INFORMATION
// command. The four expressible bits (READONLY, HIDDEN, SYSTEM, ARCHIVE)
// coincide in the low word; everything else is dropped — notably the
// directory bit, which must not be sent, and FILE_ATTRIBUTE_NORMAL, whose
// DOS encoding is 0x0000 (the command sets attributes absolutely, so zero
// means "normal" rather than "leave unchanged").
func dosAttributes(attrs uint32) uint16 {
	return uint16(attrs & (smb1.FILE_ATTRIBUTE_READONLY |
		smb1.FILE_ATTRIBUTE_HIDDEN |
		smb1.FILE_ATTRIBUTE_SYSTEM |
		smb1.FILE_ATTRIBUTE_ARCHIVE))
}

// SendTransaction sends a TRANSACTION request (for RAP and named pipes).
// This is a helper for the public API layer to send TRANSACTION commands.
// The name parameter is typically a pipe name like "\\PIPE\\LANMAN".
func (t *Tree) SendTransaction(name string, params, data []byte, ctx context.Context) (*smb1.Trans2Response, error) {
	// Encode TRANSACTION request
	allParams, dataBytes, err := smb1.EncodeTransactionRequest(name, params, data)
	if err != nil {
		return nil, err
	}

	header := smb1.NewHeader(smb1.SMB_COM_TRANSACTION)
	header.UID = t.Session.uid
	header.TID = t.TID

	resp, transResp, err := t.Session.conn.sendRecvTransaction(header, allParams, dataBytes, ctx)
	if err != nil {
		return nil, err
	}

	// Check for errors (but allow warnings like TRANS2)
	if resp.err != nil && resp.header.IsError() {
		return nil, resp.err
	}

	// Preserve warning status if present
	if resp.err != nil {
		transResp.Status = resp.header.Status
	}

	return transResp, nil
}

// OpenNamedPipe opens a named pipe for RPC communication.
// The pipeName should be in the format "\pipename" (e.g., "\srvsvc").
// Returns a File handle for the opened pipe.
func (t *Tree) OpenNamedPipe(pipeName string, ctx context.Context) (*File, error) {
	logger := logging.FromContext(ctx)
	logger.Debug("OpenNamedPipe: opening pipe %s", pipeName)

	// Open the named pipe using NT_CREATE_ANDX
	// Access: GENERIC_READ | GENERIC_WRITE for bidirectional pipe communication
	// ShareAccess: FILE_SHARE_READ | FILE_SHARE_WRITE to allow concurrent access
	// CreateDisposition: FILE_OPEN (pipe must exist)
	// CreateOptions: 0 (no special options for pipes)
	access := smb1.GENERIC_READ | smb1.GENERIC_WRITE
	shareAccess := smb1.FILE_SHARE_READ | smb1.FILE_SHARE_WRITE
	disposition := smb1.FILE_OPEN
	createOptions := uint32(0)

	f, err := t.OpenFile(pipeName, access, shareAccess, disposition, createOptions, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open named pipe %s: %w", pipeName, err)
	}

	logger.Debug("OpenNamedPipe: pipe %s opened successfully (FID=%d)", pipeName, f.fid)
	return f, nil
}

// RPCBind binds to an RPC interface over an open named pipe.
// Returns the context ID for subsequent RPC requests.
func (t *Tree) RPCBind(pipe *File, interfaceUUID [16]byte, version uint32, ctx context.Context) (uint16, error) {
	logger := logging.FromContext(ctx)
	logger.Debug("RPCBind: binding to interface UUID")

	// Create Bind request
	bindRequest := dcerpc.EncodeBind(interfaceUUID, version)

	// Send Bind request using TransactNamedPipe (FID-based operation)
	responseData, err := pipe.TransactNamedPipe(bindRequest, ctx)
	if err != nil {
		return 0, fmt.Errorf("RPC Bind failed: %w", err)
	}

	// The response data contains the Bind_Ack PDU
	if len(responseData) == 0 {
		return 0, fmt.Errorf("RPC Bind response is empty")
	}

	logger.Debug("RPCBind: received Bind_Ack response (%d bytes)", len(responseData))

	// Decode Bind_Ack response
	contextID, err := dcerpc.DecodeBindAck(responseData)
	if err != nil {
		return 0, fmt.Errorf("failed to decode Bind_Ack: %w", err)
	}

	logger.Debug("RPCBind: bind successful, context ID=%d", contextID)
	return contextID, nil
}

// RPCRequest sends an RPC request over an open named pipe and receives the response.
// Returns the response data (stub data).
func (t *Tree) RPCRequest(pipe *File, contextID uint16, opnum uint16, requestData []byte, callID uint32, ctx context.Context) ([]byte, error) {
	logger := logging.FromContext(ctx)
	logger.Debug("RPCRequest: sending RPC request (opnum=%d, callID=%d)", opnum, callID)

	// Create Request PDU
	requestPDU := dcerpc.EncodeRequest(contextID, opnum, requestData, callID)

	// Send Request using TransactNamedPipe (FID-based operation)
	responseData, err := pipe.TransactNamedPipe(requestPDU, ctx)
	if err != nil {
		return nil, fmt.Errorf("RPC Request failed: %w", err)
	}

	// The response data contains the Response PDU
	if len(responseData) == 0 {
		return nil, fmt.Errorf("RPC Request response is empty")
	}

	logger.Debug("RPCRequest: received RPC response (%d bytes)", len(responseData))

	// Decode Response PDU
	responseData, status, err := dcerpc.DecodeResponse(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RPC response: %w", err)
	}

	if status != 0 {
		return nil, fmt.Errorf("RPC request failed with status: 0x%08x", status)
	}

	logger.Debug("RPCRequest: request successful, response data=%d bytes", len(responseData))
	return responseData, nil
}
