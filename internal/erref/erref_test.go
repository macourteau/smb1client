package erref

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestNtStatusError tests the Error() method of NtStatus
func TestNtStatusError(t *testing.T) {
	tests := []struct {
		name         string
		status       NtStatus
		wantContains []string
		wantNotEmpty bool
		wantEmpty    bool
	}{
		{
			name:         "STATUS_SUCCESS",
			status:       STATUS_SUCCESS,
			wantContains: []string{"success"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_ACCESS_DENIED",
			status:       STATUS_ACCESS_DENIED,
			wantContains: []string{"Access", "Denied"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_OBJECT_NAME_NOT_FOUND",
			status:       STATUS_OBJECT_NAME_NOT_FOUND,
			wantContains: []string{"not found"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_NO_SUCH_FILE",
			status:       STATUS_NO_SUCH_FILE,
			wantContains: []string{"not exist"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_INVALID_PARAMETER",
			status:       STATUS_INVALID_PARAMETER,
			wantContains: []string{"invalid parameter"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_LOGON_FAILURE",
			status:       STATUS_LOGON_FAILURE,
			wantContains: []string{"logon"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_WRONG_PASSWORD",
			status:       STATUS_WRONG_PASSWORD,
			wantContains: []string{"password"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_ACCOUNT_DISABLED",
			status:       STATUS_ACCOUNT_DISABLED,
			wantContains: []string{"disabled"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_OBJECT_NAME_COLLISION",
			status:       STATUS_OBJECT_NAME_COLLISION,
			wantContains: []string{"already exists"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_OBJECT_PATH_NOT_FOUND",
			status:       STATUS_OBJECT_PATH_NOT_FOUND,
			wantContains: []string{"not found"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_SHARING_VIOLATION",
			status:       STATUS_SHARING_VIOLATION,
			wantContains: []string{"share access"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_RETRY",
			status:       STATUS_RETRY,
			wantContains: []string{"retried"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_DEVICE_NOT_READY",
			status:       STATUS_DEVICE_NOT_READY,
			wantContains: []string{"not ready"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_NETWORK_BUSY",
			status:       STATUS_NETWORK_BUSY,
			wantContains: []string{"busy"},
			wantNotEmpty: true,
		},
		{
			name:         "STATUS_TIMEOUT",
			status:       STATUS_TIMEOUT,
			wantContains: []string{"timeout"},
			wantNotEmpty: true,
		},
		{
			name:      "unknown status code",
			status:    NtStatus(0xDEADBEEF),
			wantEmpty: true,
		},
		{
			name:      "zero unknown status",
			status:    STATUS_SUCCESS,
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.status.Error()

			if tt.wantEmpty && got != "" {
				t.Errorf("Error() = %q, want empty string for unknown status", got)
			}

			if tt.wantNotEmpty && got == "" {
				t.Errorf("Error() = empty string, want non-empty for known status")
			}

			for _, want := range tt.wantContains {
				if !containsIgnoreCase(got, want) {
					t.Errorf("Error() = %q, want to contain %q (case-insensitive)", got, want)
				}
			}
		})
	}
}

// TestNtStatusAsError tests that NtStatus implements the error interface
func TestNtStatusAsError(t *testing.T) {
	var err error = STATUS_ACCESS_DENIED

	errStr := err.Error()
	if errStr == "" {
		t.Error("Error() should return non-empty string for known status")
	}
}

// TestNtStatusErrorsIs tests that errors.Is works with NtStatus values
func TestNtStatusErrorsIs(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{
			name:   "same status direct comparison",
			err:    STATUS_ACCESS_DENIED,
			target: STATUS_ACCESS_DENIED,
			want:   true,
		},
		{
			name:   "different status direct comparison",
			err:    STATUS_ACCESS_DENIED,
			target: STATUS_OBJECT_NAME_NOT_FOUND,
			want:   false,
		},
		{
			name:   "wrapped with fmt.Errorf",
			err:    fmt.Errorf("operation failed: %w", STATUS_ACCESS_DENIED),
			target: STATUS_ACCESS_DENIED,
			want:   true,
		},
		{
			name:   "wrapped different status",
			err:    fmt.Errorf("operation failed: %w", STATUS_OBJECT_NAME_NOT_FOUND),
			target: STATUS_ACCESS_DENIED,
			want:   false,
		},
		{
			name:   "double wrapped",
			err:    fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", STATUS_LOGON_FAILURE)),
			target: STATUS_LOGON_FAILURE,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.target); got != tt.want {
				t.Errorf("errors.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNtStatusErrorsAs tests that errors.As can extract NtStatus from wrapped errors
func TestNtStatusErrorsAs(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus NtStatus
		wantOk     bool
	}{
		{
			name:       "direct NtStatus",
			err:        STATUS_ACCESS_DENIED,
			wantStatus: STATUS_ACCESS_DENIED,
			wantOk:     true,
		},
		{
			name:       "wrapped NtStatus",
			err:        fmt.Errorf("operation failed: %w", STATUS_OBJECT_NAME_NOT_FOUND),
			wantStatus: STATUS_OBJECT_NAME_NOT_FOUND,
			wantOk:     true,
		},
		{
			name:       "double wrapped NtStatus",
			err:        fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", STATUS_LOGON_FAILURE)),
			wantStatus: STATUS_LOGON_FAILURE,
			wantOk:     true,
		},
		{
			name:       "not an NtStatus error",
			err:        errors.New("regular error"),
			wantStatus: 0,
			wantOk:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var status NtStatus
			ok := errors.As(tt.err, &status)

			if ok != tt.wantOk {
				t.Errorf("errors.As() ok = %v, want %v", ok, tt.wantOk)
			}

			if ok && status != tt.wantStatus {
				t.Errorf("errors.As() extracted status = 0x%08x, want 0x%08x", status, tt.wantStatus)
			}
		})
	}
}

// TestNtStatusComparison tests comparison between NtStatus values
func TestNtStatusComparison(t *testing.T) {
	tests := []struct {
		name  string
		a     NtStatus
		b     NtStatus
		equal bool
	}{
		{
			name:  "same status",
			a:     STATUS_SUCCESS,
			b:     STATUS_SUCCESS,
			equal: true,
		},
		{
			name:  "different status",
			a:     STATUS_ACCESS_DENIED,
			b:     STATUS_OBJECT_NAME_NOT_FOUND,
			equal: false,
		},
		{
			name:  "same error status",
			a:     STATUS_LOGON_FAILURE,
			b:     STATUS_LOGON_FAILURE,
			equal: true,
		},
		{
			name:  "zero value",
			a:     NtStatus(0),
			b:     STATUS_SUCCESS,
			equal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal := (tt.a == tt.b)
			if equal != tt.equal {
				t.Errorf("(%v == %v) = %v, want %v", tt.a, tt.b, equal, tt.equal)
			}
		})
	}
}

// TestNtStatusConstants tests that important constants have expected values
func TestNtStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		status   NtStatus
		expected uint32
	}{
		{
			name:     "STATUS_SUCCESS",
			status:   STATUS_SUCCESS,
			expected: 0x00000000,
		},
		{
			name:     "STATUS_ACCESS_DENIED",
			status:   STATUS_ACCESS_DENIED,
			expected: 0xC0000022,
		},
		{
			name:     "STATUS_OBJECT_NAME_NOT_FOUND",
			status:   STATUS_OBJECT_NAME_NOT_FOUND,
			expected: 0xC0000034,
		},
		{
			name:     "STATUS_INVALID_PARAMETER",
			status:   STATUS_INVALID_PARAMETER,
			expected: 0xC000000D,
		},
		{
			name:     "STATUS_NO_SUCH_FILE",
			status:   STATUS_NO_SUCH_FILE,
			expected: 0xC000000F,
		},
		{
			name:     "STATUS_LOGON_FAILURE",
			status:   STATUS_LOGON_FAILURE,
			expected: 0xC000006D,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint32(tt.status) != tt.expected {
				t.Errorf("%s = 0x%08x, want 0x%08x", tt.name, uint32(tt.status), tt.expected)
			}
		})
	}
}

// TestNtStatusType tests that NtStatus is the correct underlying type
func TestNtStatusType(t *testing.T) {
	var status NtStatus = 0x12345678

	// Test that we can convert to uint32
	val := uint32(status)
	if val != 0x12345678 {
		t.Errorf("uint32(status) = 0x%08x, want 0x12345678", val)
	}

	// Test that we can convert from uint32
	status2 := NtStatus(0xABCDEF00)
	if uint32(status2) != 0xABCDEF00 {
		t.Errorf("NtStatus(0xABCDEF00) = 0x%08x, want 0xABCDEF00", uint32(status2))
	}
}

// TestNtStatusStringsMapExists tests that the ntStatusStrings map exists and contains expected entries
func TestNtStatusStringsMapExists(t *testing.T) {
	// Test that common status codes have entries in the map
	tests := []NtStatus{
		STATUS_SUCCESS,
		STATUS_ACCESS_DENIED,
		STATUS_OBJECT_NAME_NOT_FOUND,
		STATUS_INVALID_PARAMETER,
		STATUS_NO_SUCH_FILE,
		STATUS_LOGON_FAILURE,
		STATUS_WRONG_PASSWORD,
		STATUS_ACCOUNT_DISABLED,
		STATUS_OBJECT_NAME_COLLISION,
		STATUS_SHARING_VIOLATION,
	}

	for _, status := range tests {
		t.Run(fmt.Sprintf("0x%08x", uint32(status)), func(t *testing.T) {
			msg := ntStatusStrings[status]
			if msg == "" {
				t.Errorf("ntStatusStrings[0x%08x] is empty, expected non-empty string", uint32(status))
			}
		})
	}
}

// TestNtStatusZeroValue tests the zero value behavior
func TestNtStatusZeroValue(t *testing.T) {
	var status NtStatus

	if status != 0 {
		t.Errorf("zero value of NtStatus = %d, want 0", status)
	}

	if status != STATUS_SUCCESS {
		t.Error("zero value of NtStatus should equal STATUS_SUCCESS")
	}

	// Zero value should have a valid error message (STATUS_SUCCESS)
	msg := status.Error()
	if msg == "" {
		t.Error("Error() for zero NtStatus should return non-empty string (STATUS_SUCCESS message)")
	}
}

// TestNtStatusErrorInterface tests error interface implementation details
func TestNtStatusErrorInterface(t *testing.T) {
	// Test that different status codes produce different error messages
	err1 := STATUS_ACCESS_DENIED.Error()
	err2 := STATUS_OBJECT_NAME_NOT_FOUND.Error()

	if err1 == err2 {
		t.Error("Different NtStatus values should produce different error messages")
	}

	if err1 == "" {
		t.Error("STATUS_ACCESS_DENIED.Error() should not be empty")
	}

	if err2 == "" {
		t.Error("STATUS_OBJECT_NAME_NOT_FOUND.Error() should not be empty")
	}
}

// TestNtStatusCommonErrorCategories tests various categories of common errors
func TestNtStatusCommonErrorCategories(t *testing.T) {
	categories := map[string][]NtStatus{
		"authentication errors": {
			STATUS_LOGON_FAILURE,
			STATUS_WRONG_PASSWORD,
			STATUS_ACCOUNT_DISABLED,
			STATUS_PASSWORD_EXPIRED,
			STATUS_ACCOUNT_EXPIRED,
		},
		"file not found errors": {
			STATUS_NO_SUCH_FILE,
			STATUS_OBJECT_NAME_NOT_FOUND,
			STATUS_OBJECT_PATH_NOT_FOUND,
		},
		"access errors": {
			STATUS_ACCESS_DENIED,
			STATUS_SHARING_VIOLATION,
		},
		"parameter errors": {
			STATUS_INVALID_PARAMETER,
			STATUS_INVALID_PARAMETER_1,
			STATUS_INVALID_PARAMETER_2,
		},
		"temporary errors": {
			STATUS_RETRY,
			STATUS_DEVICE_NOT_READY,
			STATUS_NETWORK_BUSY,
		},
	}

	for category, statuses := range categories {
		t.Run(category, func(t *testing.T) {
			for _, status := range statuses {
				msg := status.Error()
				if msg == "" {
					t.Errorf("Status 0x%08x in category %q has empty error message", uint32(status), category)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
