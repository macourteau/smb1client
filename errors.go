package smb1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/macourteau/smb1client/internal/erref"
)

// InvalidResponseError indicates the server sent a malformed response.
// This usually indicates a protocol error or incompatible server.
type InvalidResponseError struct {
	Message string
}

func (e *InvalidResponseError) Error() string {
	return fmt.Sprintf("smb1: invalid response: %s", e.Message)
}

// InternalError indicates a client-side error (not a server error).
// This usually indicates a programming error or configuration issue.
type InternalError struct {
	Message string
}

func (e *InternalError) Error() string {
	return fmt.Sprintf("smb1: internal error: %s", e.Message)
}

// ResponseError wraps an NT_STATUS error code from the server.
// The Code field contains the raw NT_STATUS value.
// The underlying error string describes the error condition.
type ResponseError struct {
	Code uint32 // NT_STATUS code
}

func (e *ResponseError) Error() string {
	status := erref.NtStatus(e.Code)
	return fmt.Sprintf("smb1: %s (0x%08X)", status.Error(), e.Code)
}

// SMBError represents an SMB protocol error with detailed context.
// It provides more information than ResponseError including the command
// that failed and a human-readable message.
type SMBError struct {
	Status  uint32 // NT_STATUS code
	Command uint8  // SMB command that failed
	Message string // Human-readable message
}

func (e *SMBError) Error() string {
	status := erref.NtStatus(e.Status)
	if e.Message != "" {
		return fmt.Sprintf("smb1: %s (command 0x%02X): %s", status.Error(), e.Command, e.Message)
	}
	return fmt.Sprintf("smb1: %s (command 0x%02X)", status.Error(), e.Command)
}

// Unwrap returns the underlying ResponseError for errors.Is/As support.
func (e *SMBError) Unwrap() error {
	return &ResponseError{Code: e.Status}
}

// ConnectionError represents connection-level errors.
// This includes TCP connection failures, disconnects, and I/O errors.
type ConnectionError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

func (e *ConnectionError) Error() string {
	return fmt.Sprintf("smb1: connection error during %s: %v", e.Op, e.Err)
}

func (e *ConnectionError) Unwrap() error {
	return e.Err
}

// TransportError represents an error coming from the net.Conn layer, such as
// a dropped TCP connection or a socket read/write failure. The type and its
// message format mirror go-smb2's TransportError for source compatibility.
type TransportError struct {
	Err error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("connection error: %v", e.Err)
}

// Unwrap exposes the underlying failure so errors.Is/As and predicates like
// IsNetworkError keep classifying wrapped errors. (go-smb2's TransportError
// has no Unwrap; ours does so the existing error chains stay intact.)
func (e *TransportError) Unwrap() error {
	return e.Err
}

// ContextError wraps a context cancellation or deadline error surfaced by a
// public API call, so that os.IsTimeout recognises deadline expiry. The type
// mirrors go-smb2's ContextError for source compatibility.
type ContextError struct {
	Err error
}

// Timeout reports whether the wrapped error is a deadline expiry. It checks
// the whole chain rather than go-smb2's identity comparison because the
// wrapped error may itself carry context (e.g. "send failed: context
// deadline exceeded").
func (e *ContextError) Timeout() bool {
	return errors.Is(e.Err, context.DeadlineExceeded)
}

func (e *ContextError) Error() string {
	return e.Err.Error()
}

// Unwrap exposes the underlying context error so errors.Is(err,
// context.Canceled) and IsTimeoutError keep working through the wrapper.
func (e *ContextError) Unwrap() error {
	return e.Err
}

// wrapError classifies an error on its way out of the public API: context
// cancellation and deadline expiry become *ContextError, and connection-level
// I/O failures become *TransportError. Both wrappers unwrap to the original
// chain, so errors.Is/As and the Is* predicates keep seeing the underlying
// causes. Errors already carrying one of the wrappers pass through untouched.
func wrapError(err error) error {
	if err == nil {
		return nil
	}
	var ctxErr *ContextError
	var transErr *TransportError
	if errors.As(err, &ctxErr) || errors.As(err, &transErr) {
		return err
	}
	// Context errors first: context.DeadlineExceeded satisfies net.Error, so
	// the network check below would otherwise claim it.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &ContextError{Err: err}
	}
	if IsNetworkError(err) {
		return &TransportError{Err: err}
	}
	return err
}

// AuthenticationError represents authentication failures.
// This provides more context about why authentication failed.
type AuthenticationError struct {
	User   string // Username that failed to authenticate
	Domain string // Domain (if applicable)
	Reason string // Human-readable reason for failure
}

func (e *AuthenticationError) Error() string {
	if e.Domain != "" {
		return fmt.Sprintf("smb1: authentication failed for %s\\%s: %s", e.Domain, e.User, e.Reason)
	}
	return fmt.Sprintf("smb1: authentication failed for %s: %s", e.User, e.Reason)
}

// IsNetworkError returns true if the error is a network-level error.
// This includes connection failures, timeouts, and I/O errors.
func IsNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for net.Error (includes timeout, temporary errors)
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// Check for common network syscall errors
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	// Check for EOF and connection reset errors
	if errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}

	return false
}

// IsAuthError returns true if the error is an authentication failure.
// This includes invalid credentials, access denied, and logon failures.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}

	// Check for ResponseError with authentication-related NT_STATUS codes
	var respErr *ResponseError
	if errors.As(err, &respErr) {
		status := erref.NtStatus(respErr.Code)
		switch status {
		case erref.STATUS_LOGON_FAILURE,
			erref.STATUS_ACCESS_DENIED,
			erref.STATUS_INVALID_LOGON_HOURS,
			erref.STATUS_INVALID_LOGON_TYPE,
			erref.STATUS_LOGON_TYPE_NOT_GRANTED,
			erref.STATUS_LOGON_NOT_GRANTED,
			erref.STATUS_ACCOUNT_DISABLED,
			erref.STATUS_ACCOUNT_EXPIRED,
			erref.STATUS_PASSWORD_EXPIRED,
			erref.STATUS_PASSWORD_MUST_CHANGE,
			erref.STATUS_WRONG_PASSWORD,
			erref.STATUS_NO_SUCH_USER,
			erref.STATUS_INVALID_ACCOUNT_NAME,
			erref.STATUS_INVALID_WORKSTATION,
			erref.STATUS_ACCOUNT_RESTRICTION,
			erref.STATUS_INSUFFICIENT_LOGON_INFO,
			erref.STATUS_SMARTCARD_LOGON_REQUIRED:
			return true
		}
	}

	// Check for erref.NtStatus directly (this is what StatusToError returns)
	var ntStatus erref.NtStatus
	if errors.As(err, &ntStatus) {
		switch ntStatus {
		case erref.STATUS_LOGON_FAILURE,
			erref.STATUS_ACCESS_DENIED,
			erref.STATUS_INVALID_LOGON_HOURS,
			erref.STATUS_INVALID_LOGON_TYPE,
			erref.STATUS_LOGON_TYPE_NOT_GRANTED,
			erref.STATUS_LOGON_NOT_GRANTED,
			erref.STATUS_ACCOUNT_DISABLED,
			erref.STATUS_ACCOUNT_EXPIRED,
			erref.STATUS_PASSWORD_EXPIRED,
			erref.STATUS_PASSWORD_MUST_CHANGE,
			erref.STATUS_WRONG_PASSWORD,
			erref.STATUS_NO_SUCH_USER,
			erref.STATUS_INVALID_ACCOUNT_NAME,
			erref.STATUS_INVALID_WORKSTATION,
			erref.STATUS_ACCOUNT_RESTRICTION,
			erref.STATUS_INSUFFICIENT_LOGON_INFO,
			erref.STATUS_SMARTCARD_LOGON_REQUIRED:
			return true
		}
	}

	// Check for path errors wrapping authentication errors
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return IsAuthError(pathErr.Err)
	}

	return false
}

// IsNotFoundError returns true if the error indicates a file or object was not found.
// This includes file not found, path not found, and object name not found errors.
func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	// Check for os.ErrNotExist
	if errors.Is(err, os.ErrNotExist) {
		return true
	}

	// Check for ResponseError with not-found NT_STATUS codes
	var respErr *ResponseError
	if errors.As(err, &respErr) {
		status := erref.NtStatus(respErr.Code)
		switch status {
		case erref.STATUS_NO_SUCH_FILE,
			erref.STATUS_OBJECT_NAME_NOT_FOUND,
			erref.STATUS_OBJECT_PATH_NOT_FOUND,
			erref.STATUS_NOT_FOUND:
			return true
		}
	}

	// Check for erref.NtStatus directly (this is what StatusToError returns)
	var ntStatus erref.NtStatus
	if errors.As(err, &ntStatus) {
		switch ntStatus {
		case erref.STATUS_NO_SUCH_FILE,
			erref.STATUS_OBJECT_NAME_NOT_FOUND,
			erref.STATUS_OBJECT_PATH_NOT_FOUND,
			erref.STATUS_NOT_FOUND:
			return true
		}
	}

	// Check for path errors wrapping not-found errors
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return IsNotFoundError(pathErr.Err)
	}

	return false
}

// IsPermissionError returns true if the error indicates a permission/access denied error.
func IsPermissionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for os.ErrPermission
	if errors.Is(err, os.ErrPermission) {
		return true
	}

	// Check for ResponseError with permission-related NT_STATUS codes
	var respErr *ResponseError
	if errors.As(err, &respErr) {
		status := erref.NtStatus(respErr.Code)
		switch status {
		case erref.STATUS_ACCESS_DENIED,
			erref.STATUS_PRIVILEGE_NOT_HELD,
			erref.STATUS_NETWORK_ACCESS_DENIED,
			erref.STATUS_SHARING_VIOLATION:
			return true
		}
	}

	// Check for erref.NtStatus directly (this is what StatusToError returns)
	var ntStatus erref.NtStatus
	if errors.As(err, &ntStatus) {
		switch ntStatus {
		case erref.STATUS_ACCESS_DENIED,
			erref.STATUS_PRIVILEGE_NOT_HELD,
			erref.STATUS_NETWORK_ACCESS_DENIED,
			erref.STATUS_SHARING_VIOLATION:
			return true
		}
	}

	// Check for path errors wrapping permission errors
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return IsPermissionError(pathErr.Err)
	}

	return false
}

// IsExistError returns true if the error indicates a file or object already exists.
func IsExistError(err error) bool {
	if err == nil {
		return false
	}

	// Check for os.ErrExist
	if errors.Is(err, os.ErrExist) {
		return true
	}

	// Check for ResponseError with exists-related NT_STATUS codes
	var respErr *ResponseError
	if errors.As(err, &respErr) {
		status := erref.NtStatus(respErr.Code)
		switch status {
		case erref.STATUS_OBJECT_NAME_COLLISION,
			erref.STATUS_OBJECT_NAME_EXISTS:
			return true
		}
	}

	// Check for erref.NtStatus directly (this is what StatusToError returns)
	var ntStatus erref.NtStatus
	if errors.As(err, &ntStatus) {
		switch ntStatus {
		case erref.STATUS_OBJECT_NAME_COLLISION,
			erref.STATUS_OBJECT_NAME_EXISTS:
			return true
		}
	}

	// Check for path errors wrapping exist errors
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return IsExistError(pathErr.Err)
	}

	return false
}

// IsTimeoutError returns true if the error indicates a timeout.
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// Check for context deadline exceeded
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Check for net.Error with Timeout() == true
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}

// IsTemporary returns true if the error is temporary and the operation can be retried.
// This includes network timeouts, temporary network errors, and transient SMB errors.
func IsTemporary(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific temporary network errors
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ECONNABORTED) {
		return true
	}

	// Check for timeout errors
	if IsTimeoutError(err) {
		return true
	}

	// Check for ResponseError with temporary NT_STATUS codes
	var respErr *ResponseError
	if errors.As(err, &respErr) {
		status := erref.NtStatus(respErr.Code)
		switch status {
		case erref.STATUS_PENDING,
			erref.STATUS_RETRY,
			erref.STATUS_DEVICE_NOT_READY,
			erref.STATUS_TOO_MANY_SESSIONS,
			erref.STATUS_NETWORK_BUSY:
			return true
		}
	}

	// Check for erref.NtStatus directly (this is what StatusToError returns)
	var ntStatus erref.NtStatus
	if errors.As(err, &ntStatus) {
		switch ntStatus {
		case erref.STATUS_PENDING,
			erref.STATUS_RETRY,
			erref.STATUS_DEVICE_NOT_READY,
			erref.STATUS_TOO_MANY_SESSIONS,
			erref.STATUS_NETWORK_BUSY:
			return true
		}
	}

	return false
}
