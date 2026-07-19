package smb1

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/macourteau/smb1client/internal/client"
	"github.com/macourteau/smb1client/internal/netbios"
)

// The connection-teardown errors are the ones a long-running caller sees when a
// device drops mid-transfer. They must be classifiable with errors.Is and
// IsNetworkError; before this was fixed they were bare fmt.Errorf values and the
// only way to recognise them was to match the message text.
func TestConnectionClosedIsClassifiableAsNetworkError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"client", client.ErrConnectionClosed},
		{"netbios", netbios.ErrConnectionClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !IsNetworkError(tc.err) {
				t.Errorf("IsNetworkError(%v) = false, want true", tc.err)
			}
			if !errors.Is(tc.err, net.ErrClosed) {
				t.Errorf("errors.Is(%v, net.ErrClosed) = false, want true", tc.err)
			}

			// The public API wraps device errors in *os.PathError; classification
			// has to survive that, since it is what callers actually receive.
			wrapped := &os.PathError{Op: "read", Path: "captures/session01/light/x.fit", Err: tc.err}
			if !IsNetworkError(wrapped) {
				t.Errorf("IsNetworkError(*os.PathError{%v}) = false, want true", tc.err)
			}

			// And through an arbitrary %w chain.
			if !IsNetworkError(fmt.Errorf("pull failed: %w", tc.err)) {
				t.Errorf("IsNetworkError(wrapped %v) = false, want true", tc.err)
			}
		})
	}
}

// A connection dying mid-frame is not an orderly end of data. Callers that test
// for io.EOF to mean "file finished" must not see these errors as EOF.
func TestConnectionClosedIsNotEOF(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"client", client.ErrConnectionClosed},
		{"netbios", netbios.ErrConnectionClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if errors.Is(tc.err, io.EOF) {
				t.Errorf("errors.Is(%v, io.EOF) = true; a mid-frame hangup must not read as end of data", tc.err)
			}
			if errors.Is(tc.err, io.ErrUnexpectedEOF) {
				t.Errorf("errors.Is(%v, io.ErrUnexpectedEOF) = true, want false", tc.err)
			}
		})
	}
}

// The two sentinels are distinct: a caller must be able to tell the SMB layer's
// teardown from the framing layer's hangup.
func TestConnectionClosedSentinelsAreDistinct(t *testing.T) {
	if errors.Is(client.ErrConnectionClosed, netbios.ErrConnectionClosed) {
		t.Error("client.ErrConnectionClosed matches netbios.ErrConnectionClosed; want distinct sentinels")
	}
	if errors.Is(netbios.ErrConnectionClosed, client.ErrConnectionClosed) {
		t.Error("netbios.ErrConnectionClosed matches client.ErrConnectionClosed; want distinct sentinels")
	}
}

// IsNetworkError must stay narrow: a plain EOF or a protocol-level refusal is
// not a transport failure, and misclassifying one would turn a permanent error
// into an infinite retry.
func TestIsNetworkErrorRejectsNonNetworkErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"eof", io.EOF},
		{"not-exist", os.ErrNotExist},
		{"permission", os.ErrPermission},
		{"plain", errors.New("some failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if IsNetworkError(tc.err) {
				t.Errorf("IsNetworkError(%v) = true, want false", tc.err)
			}
		})
	}
}
