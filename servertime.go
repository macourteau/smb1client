package smb1

import "time"

// ServerTime describes the server's clock as reported in the SMB negotiate
// response. It allows callers to compare the server clock against the local
// clock, e.g. to compute a clock offset as Time.Sub(ReceivedAt).
type ServerTime struct {
	// Time is the server's system time in UTC at the moment the server built
	// the negotiate response. It is the zero time if the server did not
	// report a valid clock.
	Time time.Time

	// TimeZoneOffsetMinutes is the server's time zone offset in minutes from
	// UTC, taken verbatim from the ServerTimeZone field of the negotiate
	// response. Time is already in UTC; this value only describes the
	// server's local time zone.
	TimeZoneOffsetMinutes int16

	// ReceivedAt is the local time at which the negotiate response was
	// received. Comparing it against Time gives the offset between the
	// server clock and the local clock as of the protocol handshake.
	ReceivedAt time.Time
}

// ServerTime returns the server clock information captured during protocol
// negotiation. The values are recorded once at dial time and do not change
// for the lifetime of the session.
//
// Example (computing the server/local clock offset right after dialing):
//
//	st := session.ServerTime()
//	offset := st.Time.Sub(st.ReceivedAt)
func (s *Session) ServerTime() ServerTime {
	systemTime, timeZoneMinutes, receivedAt := s.conn.ServerTime()
	return newServerTime(systemTime, timeZoneMinutes, receivedAt)
}

// newServerTime builds a ServerTime from the raw negotiate response values:
// the server system time as a Windows FILETIME (100-nanosecond intervals
// since January 1, 1601 UTC), the server time zone in minutes from UTC, and
// the local receive time of the negotiate response.
func newServerTime(systemTime uint64, timeZoneMinutes int16, receivedAt time.Time) ServerTime {
	return ServerTime{
		Time:                  convertFileTimeToTime(systemTime).UTC(),
		TimeZoneOffsetMinutes: timeZoneMinutes,
		ReceivedAt:            receivedAt,
	}
}
