package smb1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/macourteau/smb1client/internal/erref"
)

// TestSMBError tests the SMBError type
func TestSMBError(t *testing.T) {
	tests := []struct {
		name    string
		err     *SMBError
		wantMsg string
	}{
		{
			name: "with message",
			err: &SMBError{
				Status:  uint32(erref.STATUS_ACCESS_DENIED),
				Command: 0x2E,
				Message: "file access denied",
			},
			wantMsg: "file access denied",
		},
		{
			name: "without message",
			err: &SMBError{
				Status:  uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND),
				Command: 0x32,
			},
			wantMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			if tt.wantMsg != "" && !contains(errStr, tt.wantMsg) {
				t.Errorf("SMBError.Error() = %q, want to contain %q", errStr, tt.wantMsg)
			}

			// Test unwrapping
			var respErr *ResponseError
			if !errors.As(tt.err, &respErr) {
				t.Error("SMBError should unwrap to ResponseError")
			}
			if respErr.Code != tt.err.Status {
				t.Errorf("Unwrapped ResponseError has code %d, want %d", respErr.Code, tt.err.Status)
			}
		})
	}
}

// TestConnectionError tests the ConnectionError type
func TestConnectionError(t *testing.T) {
	innerErr := errors.New("connection reset")
	connErr := &ConnectionError{
		Op:  "read",
		Err: innerErr,
	}

	if !errors.Is(connErr, innerErr) {
		t.Error("ConnectionError should unwrap to inner error")
	}

	errStr := connErr.Error()
	if !contains(errStr, "read") {
		t.Errorf("ConnectionError.Error() = %q, want to contain 'read'", errStr)
	}
}

// TestAuthenticationError tests the AuthenticationError type
func TestAuthenticationError(t *testing.T) {
	tests := []struct {
		name       string
		err        *AuthenticationError
		wantDomain bool
	}{
		{
			name: "with domain",
			err: &AuthenticationError{
				User:   "testuser",
				Domain: "TESTDOMAIN",
				Reason: "invalid password",
			},
			wantDomain: true,
		},
		{
			name: "without domain",
			err: &AuthenticationError{
				User:   "testuser",
				Reason: "account locked",
			},
			wantDomain: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			if !contains(errStr, tt.err.User) {
				t.Errorf("AuthenticationError.Error() = %q, want to contain %q", errStr, tt.err.User)
			}
			if tt.wantDomain && !contains(errStr, tt.err.Domain) {
				t.Errorf("AuthenticationError.Error() = %q, want to contain %q", errStr, tt.err.Domain)
			}
			if !contains(errStr, tt.err.Reason) {
				t.Errorf("AuthenticationError.Error() = %q, want to contain %q", errStr, tt.err.Reason)
			}
		})
	}
}

// TestIsNetworkError tests the IsNetworkError function
func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "net.OpError",
			err:  &net.OpError{Op: "read", Err: errors.New("test")},
			want: true,
		},
		{
			name: "net.ErrClosed",
			err:  net.ErrClosed,
			want: true,
		},
		{
			name: "wrapped net.ErrClosed",
			err:  fmt.Errorf("connection failed: %w", net.ErrClosed),
			want: true,
		},
		{
			name: "connection reset",
			err:  syscall.ECONNRESET,
			want: true,
		},
		{
			name: "connection aborted",
			err:  syscall.ECONNABORTED,
			want: true,
		},
		{
			name: "broken pipe",
			err:  syscall.EPIPE,
			want: true,
		},
		{
			name: "wrapped broken pipe",
			err:  fmt.Errorf("write failed: %w", syscall.EPIPE),
			want: true,
		},
		{
			name: "net.Error with timeout",
			err:  &timeoutError{timeout: true},
			want: true,
		},
		{
			name: "net.Error temporary",
			err:  &timeoutError{temporary: true},
			want: true,
		},
		{
			name: "double wrapped net error",
			err:  fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", syscall.ECONNRESET)),
			want: true,
		},
		{
			name: "regular error",
			err:  errors.New("not a network error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNetworkError(tt.err); got != tt.want {
				t.Errorf("IsNetworkError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsAuthError tests the IsAuthError function
func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "logon failure",
			err:  &ResponseError{Code: uint32(erref.STATUS_LOGON_FAILURE)},
			want: true,
		},
		{
			name: "access denied",
			err:  &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)},
			want: true,
		},
		{
			name: "wrong password",
			err:  &ResponseError{Code: uint32(erref.STATUS_WRONG_PASSWORD)},
			want: true,
		},
		{
			name: "account disabled",
			err:  &ResponseError{Code: uint32(erref.STATUS_ACCOUNT_DISABLED)},
			want: true,
		},
		{
			name: "account expired",
			err:  &ResponseError{Code: uint32(erref.STATUS_ACCOUNT_EXPIRED)},
			want: true,
		},
		{
			name: "password expired",
			err:  &ResponseError{Code: uint32(erref.STATUS_PASSWORD_EXPIRED)},
			want: true,
		},
		{
			name: "password must change",
			err:  &ResponseError{Code: uint32(erref.STATUS_PASSWORD_MUST_CHANGE)},
			want: true,
		},
		{
			name: "no such user",
			err:  &ResponseError{Code: uint32(erref.STATUS_NO_SUCH_USER)},
			want: true,
		},
		{
			name: "invalid account name",
			err:  &ResponseError{Code: uint32(erref.STATUS_INVALID_ACCOUNT_NAME)},
			want: true,
		},
		{
			name: "invalid workstation",
			err:  &ResponseError{Code: uint32(erref.STATUS_INVALID_WORKSTATION)},
			want: true,
		},
		{
			name: "account restriction",
			err:  &ResponseError{Code: uint32(erref.STATUS_ACCOUNT_RESTRICTION)},
			want: true,
		},
		{
			name: "invalid logon hours",
			err:  &ResponseError{Code: uint32(erref.STATUS_INVALID_LOGON_HOURS)},
			want: true,
		},
		{
			name: "wrapped in PathError",
			err:  &os.PathError{Op: "open", Path: "test", Err: &ResponseError{Code: uint32(erref.STATUS_LOGON_FAILURE)}},
			want: true,
		},
		{
			name: "wrapped in fmt.Errorf",
			err:  fmt.Errorf("authentication failed: %w", &ResponseError{Code: uint32(erref.STATUS_WRONG_PASSWORD)}),
			want: true,
		},
		{
			name: "double wrapped",
			err:  fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &ResponseError{Code: uint32(erref.STATUS_ACCOUNT_DISABLED)})),
			want: true,
		},
		{
			name: "not auth error",
			err:  &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND)},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAuthError(tt.err); got != tt.want {
				t.Errorf("IsAuthError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsNotFoundError tests the IsNotFoundError function
func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "os.ErrNotExist",
			err:  os.ErrNotExist,
			want: true,
		},
		{
			name: "object name not found",
			err:  &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND)},
			want: true,
		},
		{
			name: "object path not found",
			err:  &ResponseError{Code: uint32(erref.STATUS_OBJECT_PATH_NOT_FOUND)},
			want: true,
		},
		{
			name: "no such file",
			err:  &ResponseError{Code: uint32(erref.STATUS_NO_SUCH_FILE)},
			want: true,
		},
		{
			name: "not found status",
			err:  &ResponseError{Code: uint32(erref.STATUS_NOT_FOUND)},
			want: true,
		},
		{
			name: "wrapped in PathError",
			err:  &os.PathError{Op: "open", Path: "test", Err: os.ErrNotExist},
			want: true,
		},
		{
			name: "wrapped ResponseError in PathError",
			err:  &os.PathError{Op: "open", Path: "test", Err: &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND)}},
			want: true,
		},
		{
			name: "wrapped in fmt.Errorf",
			err:  fmt.Errorf("file operation failed: %w", os.ErrNotExist),
			want: true,
		},
		{
			name: "double wrapped",
			err:  fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &ResponseError{Code: uint32(erref.STATUS_NO_SUCH_FILE)})),
			want: true,
		},
		{
			name: "not found error",
			err:  &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFoundError(tt.err); got != tt.want {
				t.Errorf("IsNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsPermissionError tests the IsPermissionError function
func TestIsPermissionError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "os.ErrPermission",
			err:  os.ErrPermission,
			want: true,
		},
		{
			name: "access denied",
			err:  &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)},
			want: true,
		},
		{
			name: "sharing violation",
			err:  &ResponseError{Code: uint32(erref.STATUS_SHARING_VIOLATION)},
			want: true,
		},
		{
			name: "privilege not held",
			err:  &ResponseError{Code: uint32(erref.STATUS_PRIVILEGE_NOT_HELD)},
			want: true,
		},
		{
			name: "network access denied",
			err:  &ResponseError{Code: uint32(erref.STATUS_NETWORK_ACCESS_DENIED)},
			want: true,
		},
		{
			name: "wrapped in PathError",
			err:  &os.PathError{Op: "open", Path: "test", Err: os.ErrPermission},
			want: true,
		},
		{
			name: "wrapped ResponseError in PathError",
			err:  &os.PathError{Op: "open", Path: "test", Err: &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)}},
			want: true,
		},
		{
			name: "wrapped in fmt.Errorf",
			err:  fmt.Errorf("file access failed: %w", os.ErrPermission),
			want: true,
		},
		{
			name: "double wrapped",
			err:  fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &ResponseError{Code: uint32(erref.STATUS_SHARING_VIOLATION)})),
			want: true,
		},
		{
			name: "not permission error",
			err:  &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND)},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPermissionError(tt.err); got != tt.want {
				t.Errorf("IsPermissionError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsExistError tests the IsExistError function
func TestIsExistError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "os.ErrExist",
			err:  os.ErrExist,
			want: true,
		},
		{
			name: "object name collision",
			err:  &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_COLLISION)},
			want: true,
		},
		{
			name: "object name exists",
			err:  &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_EXISTS)},
			want: true,
		},
		{
			name: "wrapped in PathError",
			err:  &os.PathError{Op: "create", Path: "test", Err: os.ErrExist},
			want: true,
		},
		{
			name: "wrapped ResponseError in PathError",
			err:  &os.PathError{Op: "mkdir", Path: "test", Err: &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_COLLISION)}},
			want: true,
		},
		{
			name: "wrapped in fmt.Errorf",
			err:  fmt.Errorf("file creation failed: %w", os.ErrExist),
			want: true,
		},
		{
			name: "double wrapped",
			err:  fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_EXISTS)})),
			want: true,
		},
		{
			name: "not exist error",
			err:  &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND)},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExistError(tt.err); got != tt.want {
				t.Errorf("IsExistError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsTimeoutError tests the IsTimeoutError function
func TestIsTimeoutError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "context deadline exceeded",
			err:  context.DeadlineExceeded,
			want: true,
		},
		{
			name: "wrapped context deadline exceeded",
			err:  fmt.Errorf("operation timed out: %w", context.DeadlineExceeded),
			want: true,
		},
		{
			name: "double wrapped context deadline exceeded",
			err:  fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", context.DeadlineExceeded)),
			want: true,
		},
		{
			name: "net.OpError with timeout",
			err:  &net.OpError{Op: "read", Err: &timeoutError{timeout: true}},
			want: true,
		},
		{
			name: "net.OpError without timeout",
			err:  &net.OpError{Op: "read", Err: errors.New("not timeout")},
			want: false,
		},
		{
			name: "not timeout error",
			err:  errors.New("regular error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTimeoutError(tt.err); got != tt.want {
				t.Errorf("IsTimeoutError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// timeoutError is a test helper that implements net.Error with configurable timeout
type timeoutError struct {
	timeout   bool
	temporary bool
}

func (e *timeoutError) Error() string   { return "timeout error" }
func (e *timeoutError) Timeout() bool   { return e.timeout }
func (e *timeoutError) Temporary() bool { return e.temporary }

// TestIsTemporary tests the IsTemporary function
func TestIsTemporary(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "retry status",
			err:  &ResponseError{Code: uint32(erref.STATUS_RETRY)},
			want: true,
		},
		{
			name: "device not ready",
			err:  &ResponseError{Code: uint32(erref.STATUS_DEVICE_NOT_READY)},
			want: true,
		},
		{
			name: "network busy",
			err:  &ResponseError{Code: uint32(erref.STATUS_NETWORK_BUSY)},
			want: true,
		},
		{
			name: "pending status",
			err:  &ResponseError{Code: uint32(erref.STATUS_PENDING)},
			want: true,
		},
		{
			name: "too many sessions",
			err:  &ResponseError{Code: uint32(erref.STATUS_TOO_MANY_SESSIONS)},
			want: true,
		},
		{
			name: "connection refused syscall",
			err:  syscall.ECONNREFUSED,
			want: true,
		},
		{
			name: "timeout syscall",
			err:  syscall.ETIMEDOUT,
			want: true,
		},
		{
			name: "host unreachable syscall",
			err:  syscall.EHOSTUNREACH,
			want: true,
		},
		{
			name: "network unreachable syscall",
			err:  syscall.ENETUNREACH,
			want: true,
		},
		{
			name: "connection aborted syscall",
			err:  syscall.ECONNABORTED,
			want: true,
		},
		{
			name: "wrapped syscall error",
			err:  fmt.Errorf("connection failed: %w", syscall.ECONNREFUSED),
			want: true,
		},
		{
			name: "timeout via context deadline",
			err:  context.DeadlineExceeded,
			want: true,
		},
		{
			name: "not temporary error",
			err:  &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTemporary(tt.err); got != tt.want {
				t.Errorf("IsTemporary() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsExistError_NtStatus tests that IsExistError correctly detects erref.NtStatus errors
func TestIsExistError_NtStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "direct NtStatus - object name collision",
			err:  erref.STATUS_OBJECT_NAME_COLLISION,
			want: true,
		},
		{
			name: "direct NtStatus - object name exists",
			err:  erref.STATUS_OBJECT_NAME_EXISTS,
			want: true,
		},
		{
			name: "wrapped NtStatus in fmt.Errorf",
			err:  errors.New("smb1: nt create returned error: " + erref.STATUS_OBJECT_NAME_EXISTS.Error()),
			want: false, // String wrapping doesn't preserve type
		},
		{
			name: "wrapped NtStatus in PathError",
			err:  &os.PathError{Op: "mkdir", Path: "test", Err: erref.STATUS_OBJECT_NAME_EXISTS},
			want: true,
		},
		{
			name: "wrapped NtStatus in fmt.Errorf with %w",
			err:  fmt.Errorf("smb1: nt create returned error: %w", erref.STATUS_OBJECT_NAME_EXISTS),
			want: true,
		},
		{
			name: "double wrapped in PathError and fmt.Errorf",
			err:  &os.PathError{Op: "mkdir", Path: "test", Err: fmt.Errorf("smb1: nt create returned error: %w", erref.STATUS_OBJECT_NAME_EXISTS)},
			want: true,
		},
		{
			name: "not exist NtStatus",
			err:  erref.STATUS_OBJECT_NAME_NOT_FOUND,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExistError(tt.err); got != tt.want {
				t.Errorf("IsExistError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsNotFoundError_NtStatus tests that IsNotFoundError correctly detects erref.NtStatus errors
func TestIsNotFoundError_NtStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "direct NtStatus - object name not found",
			err:  erref.STATUS_OBJECT_NAME_NOT_FOUND,
			want: true,
		},
		{
			name: "direct NtStatus - object path not found",
			err:  erref.STATUS_OBJECT_PATH_NOT_FOUND,
			want: true,
		},
		{
			name: "direct NtStatus - no such file",
			err:  erref.STATUS_NO_SUCH_FILE,
			want: true,
		},
		{
			name: "wrapped NtStatus in PathError",
			err:  &os.PathError{Op: "open", Path: "test", Err: erref.STATUS_OBJECT_NAME_NOT_FOUND},
			want: true,
		},
		{
			name: "wrapped NtStatus in fmt.Errorf with %w",
			err:  fmt.Errorf("smb1: nt create returned error: %w", erref.STATUS_OBJECT_NAME_NOT_FOUND),
			want: true,
		},
		{
			name: "not a not-found error",
			err:  erref.STATUS_ACCESS_DENIED,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFoundError(tt.err); got != tt.want {
				t.Errorf("IsNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsPermissionError_NtStatus tests that IsPermissionError correctly detects erref.NtStatus errors
func TestIsPermissionError_NtStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "direct NtStatus - access denied",
			err:  erref.STATUS_ACCESS_DENIED,
			want: true,
		},
		{
			name: "direct NtStatus - sharing violation",
			err:  erref.STATUS_SHARING_VIOLATION,
			want: true,
		},
		{
			name: "wrapped NtStatus in PathError",
			err:  &os.PathError{Op: "open", Path: "test", Err: erref.STATUS_ACCESS_DENIED},
			want: true,
		},
		{
			name: "wrapped NtStatus in fmt.Errorf with %w",
			err:  fmt.Errorf("smb1: nt create returned error: %w", erref.STATUS_ACCESS_DENIED),
			want: true,
		},
		{
			name: "not a permission error",
			err:  erref.STATUS_OBJECT_NAME_NOT_FOUND,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPermissionError(tt.err); got != tt.want {
				t.Errorf("IsPermissionError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsAuthError_NtStatus tests that IsAuthError correctly detects erref.NtStatus errors
func TestIsAuthError_NtStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "direct NtStatus - logon failure",
			err:  erref.STATUS_LOGON_FAILURE,
			want: true,
		},
		{
			name: "direct NtStatus - wrong password",
			err:  erref.STATUS_WRONG_PASSWORD,
			want: true,
		},
		{
			name: "direct NtStatus - account disabled",
			err:  erref.STATUS_ACCOUNT_DISABLED,
			want: true,
		},
		{
			name: "wrapped NtStatus in fmt.Errorf with %w",
			err:  fmt.Errorf("smb1: session setup returned error: %w", erref.STATUS_LOGON_FAILURE),
			want: true,
		},
		{
			name: "not an auth error",
			err:  erref.STATUS_OBJECT_NAME_NOT_FOUND,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAuthError(tt.err); got != tt.want {
				t.Errorf("IsAuthError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsTemporary_NtStatus tests that IsTemporary correctly detects erref.NtStatus errors
func TestIsTemporary_NtStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "direct NtStatus - retry",
			err:  erref.STATUS_RETRY,
			want: true,
		},
		{
			name: "direct NtStatus - device not ready",
			err:  erref.STATUS_DEVICE_NOT_READY,
			want: true,
		},
		{
			name: "direct NtStatus - network busy",
			err:  erref.STATUS_NETWORK_BUSY,
			want: true,
		},
		{
			name: "wrapped NtStatus in fmt.Errorf with %w",
			err:  fmt.Errorf("smb1: operation failed: %w", erref.STATUS_RETRY),
			want: true,
		},
		{
			name: "not a temporary error",
			err:  erref.STATUS_ACCESS_DENIED,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTemporary(tt.err); got != tt.want {
				t.Errorf("IsTemporary() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestErrorClassificationEdgeCases tests edge cases for all classification functions
func TestErrorClassificationEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		isAuth   bool
		isNotFnd bool
		isPerm   bool
		isExist  bool
		isNet    bool
		isTemp   bool
		isTime   bool
	}{
		{
			name:     "nil error",
			err:      nil,
			isAuth:   false,
			isNotFnd: false,
			isPerm:   false,
			isExist:  false,
			isNet:    false,
			isTemp:   false,
			isTime:   false,
		},
		{
			name:     "unknown status code",
			err:      &ResponseError{Code: 0xDEADBEEF},
			isAuth:   false,
			isNotFnd: false,
			isPerm:   false,
			isExist:  false,
			isNet:    false,
			isTemp:   false,
			isTime:   false,
		},
		{
			name:     "STATUS_SUCCESS (not an error)",
			err:      &ResponseError{Code: uint32(erref.STATUS_SUCCESS)},
			isAuth:   false,
			isNotFnd: false,
			isPerm:   false,
			isExist:  false,
			isNet:    false,
			isTemp:   false,
			isTime:   false,
		},
		{
			name:     "access denied matches both auth and permission",
			err:      &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)},
			isAuth:   true,
			isNotFnd: false,
			isPerm:   true,
			isExist:  false,
			isNet:    false,
			isTemp:   false,
			isTime:   false,
		},
		{
			name:     "connection aborted matches both network and temporary",
			err:      syscall.ECONNABORTED,
			isAuth:   false,
			isNotFnd: false,
			isPerm:   false,
			isExist:  false,
			isNet:    true,
			isTemp:   true,
			isTime:   false,
		},
		{
			name:     "deeply nested error chain",
			err:      fmt.Errorf("layer 3: %w", fmt.Errorf("layer 2: %w", fmt.Errorf("layer 1: %w", os.ErrNotExist))),
			isAuth:   false,
			isNotFnd: true,
			isPerm:   false,
			isExist:  false,
			isNet:    false,
			isTemp:   false,
			isTime:   false,
		},
		{
			name:     "PathError wrapping NtStatus wrapping",
			err:      &os.PathError{Op: "open", Path: "/test/file", Err: fmt.Errorf("smb error: %w", erref.STATUS_LOGON_FAILURE)},
			isAuth:   true,
			isNotFnd: false,
			isPerm:   false,
			isExist:  false,
			isNet:    false,
			isTemp:   false,
			isTime:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAuthError(tt.err); got != tt.isAuth {
				t.Errorf("IsAuthError() = %v, want %v", got, tt.isAuth)
			}
			if got := IsNotFoundError(tt.err); got != tt.isNotFnd {
				t.Errorf("IsNotFoundError() = %v, want %v", got, tt.isNotFnd)
			}
			if got := IsPermissionError(tt.err); got != tt.isPerm {
				t.Errorf("IsPermissionError() = %v, want %v", got, tt.isPerm)
			}
			if got := IsExistError(tt.err); got != tt.isExist {
				t.Errorf("IsExistError() = %v, want %v", got, tt.isExist)
			}
			if got := IsNetworkError(tt.err); got != tt.isNet {
				t.Errorf("IsNetworkError() = %v, want %v", got, tt.isNet)
			}
			if got := IsTemporary(tt.err); got != tt.isTemp {
				t.Errorf("IsTemporary() = %v, want %v", got, tt.isTemp)
			}
			if got := IsTimeoutError(tt.err); got != tt.isTime {
				t.Errorf("IsTimeoutError() = %v, want %v", got, tt.isTime)
			}
		})
	}
}

// TestErrorConstructorClassification tests that error constructors produce correctly classified errors
func TestErrorConstructorClassification(t *testing.T) {
	t.Run("SMBError with access denied", func(t *testing.T) {
		err := &SMBError{
			Status:  uint32(erref.STATUS_ACCESS_DENIED),
			Command: 0x2E,
			Message: "access denied",
		}

		if !IsAuthError(err) {
			t.Error("SMBError with STATUS_ACCESS_DENIED should be classified as auth error")
		}
		if !IsPermissionError(err) {
			t.Error("SMBError with STATUS_ACCESS_DENIED should be classified as permission error")
		}
	})

	t.Run("SMBError with not found", func(t *testing.T) {
		err := &SMBError{
			Status:  uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND),
			Command: 0x32,
			Message: "file not found",
		}

		if !IsNotFoundError(err) {
			t.Error("SMBError with STATUS_OBJECT_NAME_NOT_FOUND should be classified as not found error")
		}
		if IsAuthError(err) {
			t.Error("SMBError with STATUS_OBJECT_NAME_NOT_FOUND should not be classified as auth error")
		}
	})

	t.Run("ConnectionError with network error", func(t *testing.T) {
		err := &ConnectionError{
			Op:  "read",
			Err: syscall.ECONNRESET,
		}

		if !IsNetworkError(err) {
			t.Error("ConnectionError with ECONNRESET should be classified as network error")
		}
		// ECONNRESET is a network error but not necessarily temporary
		if IsTemporary(err) {
			t.Error("ConnectionError with ECONNRESET should not be classified as temporary error")
		}
	})

	t.Run("ConnectionError with temporary network error", func(t *testing.T) {
		err := &ConnectionError{
			Op:  "dial",
			Err: syscall.ECONNREFUSED,
		}

		if !IsNetworkError(err) {
			t.Error("ConnectionError with ECONNREFUSED should be classified as network error")
		}
		if !IsTemporary(err) {
			t.Error("ConnectionError with ECONNREFUSED should be classified as temporary error")
		}
	})

	t.Run("ResponseError with retry status", func(t *testing.T) {
		err := &ResponseError{Code: uint32(erref.STATUS_RETRY)}

		if !IsTemporary(err) {
			t.Error("ResponseError with STATUS_RETRY should be classified as temporary error")
		}
	})
}

// TestMultipleErrorWrapping tests complex error wrapping scenarios
func TestMultipleErrorWrapping(t *testing.T) {
	tests := []struct {
		name       string
		buildError func() error
		classifier func(error) bool
		want       bool
	}{
		{
			name: "triple wrapped auth error",
			buildError: func() error {
				return fmt.Errorf("operation failed: %w",
					&os.PathError{Op: "open", Path: "test",
						Err: fmt.Errorf("smb error: %w", erref.STATUS_LOGON_FAILURE)})
			},
			classifier: IsAuthError,
			want:       true,
		},
		{
			name: "PathError around ResponseError",
			buildError: func() error {
				return &os.PathError{
					Op:   "stat",
					Path: "/share/file",
					Err:  &ResponseError{Code: uint32(erref.STATUS_OBJECT_PATH_NOT_FOUND)},
				}
			},
			classifier: IsNotFoundError,
			want:       true,
		},
		{
			name: "fmt.Errorf around PathError around os.ErrExist",
			buildError: func() error {
				return fmt.Errorf("mkdir failed: %w",
					&os.PathError{Op: "mkdir", Path: "test", Err: os.ErrExist})
			},
			classifier: IsExistError,
			want:       true,
		},
		{
			name: "ConnectionError wrapping net.OpError",
			buildError: func() error {
				return &ConnectionError{
					Op:  "dial",
					Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
				}
			},
			classifier: IsNetworkError,
			want:       true,
		},
		{
			name: "NtStatus wrapped in multiple fmt.Errorf layers",
			buildError: func() error {
				return fmt.Errorf("outer: %w",
					fmt.Errorf("middle: %w",
						fmt.Errorf("inner: %w", erref.STATUS_SHARING_VIOLATION)))
			},
			classifier: IsPermissionError,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.buildError()
			if got := tt.classifier(err); got != tt.want {
				t.Errorf("classifier() = %v, want %v for error: %v", got, tt.want, err)
			}
		})
	}
}

// TestUnknownStatusCodes tests behavior with unknown NT_STATUS codes
func TestUnknownStatusCodes(t *testing.T) {
	unknownCodes := []uint32{
		0xFFFFFFFF,
		0xDEADBEEF,
		0x12345678,
		0x00000001, // STATUS_WAIT_1 - valid but not in any category
	}

	for _, code := range unknownCodes {
		t.Run(fmt.Sprintf("code_0x%08X", code), func(t *testing.T) {
			err := &ResponseError{Code: code}

			// Unknown codes should not match any category
			if IsAuthError(err) {
				t.Error("Unknown code should not be classified as auth error")
			}
			if IsNotFoundError(err) {
				t.Error("Unknown code should not be classified as not found error")
			}
			if IsPermissionError(err) {
				t.Error("Unknown code should not be classified as permission error")
			}
			if IsExistError(err) {
				t.Error("Unknown code should not be classified as exist error")
			}
			if IsTemporary(err) {
				t.Error("Unknown code should not be classified as temporary error")
			}
			if IsTimeoutError(err) {
				t.Error("Unknown code should not be classified as timeout error")
			}
			if IsNetworkError(err) {
				t.Error("Unknown code should not be classified as network error")
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
