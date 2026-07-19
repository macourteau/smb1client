package smb1

import (
	"testing"
	"time"
)

func TestConvertFileTimeToTime(t *testing.T) {
	tests := []struct {
		name     string
		filetime uint64
		wantZero bool
	}{
		{
			name:     "zero filetime returns zero time",
			filetime: 0,
			wantZero: true,
		},
		{
			name:     "filetime before windows epoch returns zero time",
			filetime: 116444736000000000 - 1,
			wantZero: true,
		},
		{
			name:     "filetime before windows epoch (large underflow) returns zero time",
			filetime: 1000,
			wantZero: true,
		},
		{
			name:     "unix epoch time (Jan 1, 1970) converts correctly",
			filetime: 116444736000000000, // Windows epoch to Unix epoch
			wantZero: false,
		},
		{
			name:     "valid filetime after unix epoch converts correctly",
			filetime: 116444736000000000 + 10000000, // 1 second after Unix epoch
			wantZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertFileTimeToTime(tt.filetime)
			if tt.wantZero {
				if !got.IsZero() {
					t.Errorf("convertFileTimeToTime(%d) = %v, want zero time", tt.filetime, got)
				}
			} else {
				if got.IsZero() {
					t.Errorf("convertFileTimeToTime(%d) returned zero time, want valid time", tt.filetime)
				}
			}
		})
	}
}

func TestConvertFileTimeToTime_UnixEpoch(t *testing.T) {
	// Test that the Unix epoch (Jan 1, 1970 00:00:00 UTC) converts correctly
	const windowsToUnixEpoch = 116444736000000000
	got := convertFileTimeToTime(windowsToUnixEpoch)

	// Unix epoch should be Jan 1, 1970 00:00:00 UTC
	want := time.Unix(0, 0)
	if !got.Equal(want) {
		t.Errorf("convertFileTimeToTime(windowsToUnixEpoch) = %v, want %v", got, want)
	}
}

func TestConvertFileTimeToTime_KnownTimestamp(t *testing.T) {
	// Test with a known timestamp: Jan 1, 2020 00:00:00 UTC
	// Unix timestamp: 1577836800 seconds
	// In 100-nanosecond intervals: 1577836800 * 10000000 = 15778368000000000
	// Plus Windows epoch offset: 15778368000000000 + 116444736000000000 = 132223104000000000
	const jan1_2020 = uint64(132223104000000000)

	got := convertFileTimeToTime(jan1_2020)
	want := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	if !got.Equal(want) {
		t.Errorf("convertFileTimeToTime(jan1_2020) = %v, want %v", got, want)
	}
}

func TestConvertTimeToFileTime(t *testing.T) {
	tests := []struct {
		name string
		time time.Time
		want uint64
	}{
		{
			name: "zero time returns zero",
			time: time.Time{},
			want: 0,
		},
		{
			name: "unix epoch converts correctly",
			time: time.Unix(0, 0),
			want: 116444736000000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertTimeToFileTime(tt.time)
			if got != tt.want {
				t.Errorf("convertTimeToFileTime(%v) = %d, want %d", tt.time, got, tt.want)
			}
		})
	}
}

func TestConvertTimeToFileTime_KnownTimestamp(t *testing.T) {
	// Test with a known timestamp: Jan 1, 2020 00:00:00 UTC
	input := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	const want = uint64(132223104000000000)

	got := convertTimeToFileTime(input)
	if got != want {
		t.Errorf("convertTimeToFileTime(Jan 1, 2020) = %d, want %d", got, want)
	}
}

func TestRoundTripConversion(t *testing.T) {
	// Test that converting to filetime and back produces the same result
	// Note: precision is limited to 100-nanosecond intervals
	tests := []struct {
		name string
		time time.Time
	}{
		{
			name: "unix epoch",
			time: time.Unix(0, 0),
		},
		{
			name: "specific date",
			time: time.Date(2020, 1, 1, 12, 30, 45, 0, time.UTC),
		},
		{
			name: "recent date",
			time: time.Date(2024, 10, 15, 10, 20, 30, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Round to 100-nanosecond precision for comparison
			original := tt.time.Truncate(100 * time.Nanosecond)

			filetime := convertTimeToFileTime(original)
			roundtrip := convertFileTimeToTime(filetime)

			if !roundtrip.Equal(original) {
				t.Errorf("Round-trip conversion failed: original=%v, filetime=%d, roundtrip=%v",
					original, filetime, roundtrip)
			}
		})
	}
}

func TestConvertFileTimeToTime_SecurityBounds(t *testing.T) {
	// Test edge cases for security
	tests := []struct {
		name     string
		filetime uint64
		wantZero bool
	}{
		{
			name:     "maximum uint64 is valid",
			filetime: ^uint64(0), // max uint64
			wantZero: false,
		},
		{
			name:     "one before windows epoch triggers bounds check",
			filetime: 116444736000000000 - 1,
			wantZero: true,
		},
		{
			name:     "minimum non-zero value triggers bounds check",
			filetime: 1,
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertFileTimeToTime(tt.filetime)
			if tt.wantZero && !got.IsZero() {
				t.Errorf("convertFileTimeToTime(%d) = %v, want zero time for security bounds", tt.filetime, got)
			}
			if !tt.wantZero && got.IsZero() {
				t.Errorf("convertFileTimeToTime(%d) returned zero time, want valid time", tt.filetime)
			}
		})
	}
}
