package smb1

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/macourteau/smb1client/internal/client"
	"github.com/macourteau/smb1client/internal/smb1"
)

// windowsToUnixEpochFileTime is the Unix epoch (1970-01-01T00:00:00Z) as a
// Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC).
const windowsToUnixEpochFileTime = uint64(116444736000000000)

// jan1_2020FileTime is 2020-01-01T00:00:00Z as a Windows FILETIME.
const jan1_2020FileTime = uint64(132223104000000000)

func TestNewServerTime(t *testing.T) {
	receivedAt := time.Date(2020, 1, 1, 0, 0, 1, 0, time.UTC)

	tests := []struct {
		name            string
		systemTime      uint64
		timeZoneMinutes int16
		wantTime        time.Time
	}{
		{
			name:       "zero filetime yields zero time",
			systemTime: 0,
			wantTime:   time.Time{},
		},
		{
			name:       "filetime before unix epoch yields zero time",
			systemTime: windowsToUnixEpochFileTime - 1,
			wantTime:   time.Time{},
		},
		{
			name:       "unix epoch converts correctly",
			systemTime: windowsToUnixEpochFileTime,
			wantTime:   time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:            "known timestamp converts correctly",
			systemTime:      jan1_2020FileTime,
			timeZoneMinutes: 300,
			wantTime:        time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:            "negative time zone offset is preserved",
			systemTime:      jan1_2020FileTime,
			timeZoneMinutes: -600,
			wantTime:        time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:       "sub-second precision is preserved",
			systemTime: jan1_2020FileTime + 15000001, // 1.5000001 seconds later
			wantTime:   time.Date(2020, 1, 1, 0, 0, 1, 500000100, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newServerTime(tt.systemTime, tt.timeZoneMinutes, receivedAt)

			if tt.wantTime.IsZero() {
				if !got.Time.IsZero() {
					t.Errorf("Time: got %v, want zero time", got.Time)
				}
			} else {
				if !got.Time.Equal(tt.wantTime) {
					t.Errorf("Time: got %v, want %v", got.Time, tt.wantTime)
				}
				if got.Time.Location() != time.UTC {
					t.Errorf("Time location: got %v, want UTC", got.Time.Location())
				}
			}
			if got.TimeZoneOffsetMinutes != tt.timeZoneMinutes {
				t.Errorf("TimeZoneOffsetMinutes: got %d, want %d", got.TimeZoneOffsetMinutes, tt.timeZoneMinutes)
			}
			if !got.ReceivedAt.Equal(receivedAt) {
				t.Errorf("ReceivedAt: got %v, want %v", got.ReceivedAt, receivedAt)
			}
		})
	}
}

// TestSessionServerTime tests the Session.ServerTime accessor end-to-end:
// it drives a real protocol negotiation against a fake server over net.Pipe
// and verifies that the server clock from the negotiate response is exposed
// on the public API.
func TestSessionServerTime(t *testing.T) {
	const timeZoneMinutes = int16(300)

	clientEnd, serverEnd := net.Pipe()
	defer serverEnd.Close()

	conn := client.NewConn(clientEnd)
	defer conn.Close()
	go conn.Receive()

	// Fake server: consume the negotiate request, then send a canned response.
	go func() {
		// NetBIOS header: 1-byte type + 3-byte big-endian length.
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(serverEnd, hdr); err != nil {
			return
		}
		reqLen := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		if _, err := io.ReadFull(serverEnd, make([]byte, reqLen)); err != nil {
			return
		}

		respHeader := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
		respHeader.Flags |= smb1.SMB_FLAGS_REPLY

		params := make([]byte, 34)
		params[2] = smb1.NEGOTIATE_ENCRYPT_PASSWORDS
		caps := smb1.CAP_NT_SMBS | smb1.CAP_UNICODE | smb1.CAP_LARGE_FILES | smb1.CAP_STATUS32
		binary.LittleEndian.PutUint32(params[19:23], caps)
		binary.LittleEndian.PutUint64(params[23:31], jan1_2020FileTime)
		binary.LittleEndian.PutUint16(params[31:33], uint16(timeZoneMinutes))
		params[33] = 8 // ChallengeLength

		data := make([]byte, 8) // challenge

		packet, err := smb1.EncodePacket(respHeader, params, data)
		if err != nil {
			return
		}
		framed := append([]byte{0x00, byte(len(packet) >> 16), byte(len(packet) >> 8), byte(len(packet))}, packet...)
		serverEnd.Write(framed)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	before := time.Now()
	if err := client.Negotiate(conn, ctx); err != nil {
		t.Fatalf("Negotiate failed: %v", err)
	}
	after := time.Now()

	session := &Session{conn: conn, ctx: context.Background()}
	st := session.ServerTime()

	wantTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if !st.Time.Equal(wantTime) {
		t.Errorf("Time: got %v, want %v", st.Time, wantTime)
	}
	if st.TimeZoneOffsetMinutes != timeZoneMinutes {
		t.Errorf("TimeZoneOffsetMinutes: got %d, want %d", st.TimeZoneOffsetMinutes, timeZoneMinutes)
	}
	if st.ReceivedAt.Before(before) || st.ReceivedAt.After(after) {
		t.Errorf("ReceivedAt: got %v, want between %v and %v", st.ReceivedAt, before, after)
	}
}
