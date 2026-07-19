package smb1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/macourteau/smb1client/internal/client"
)

func TestContextErrorTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"deadline", context.DeadlineExceeded, true},
		{"wrapped_deadline", fmt.Errorf("op failed: %w", context.DeadlineExceeded), true},
		{"canceled", context.Canceled, false},
		{"plain", errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ce := &ContextError{Err: tt.err}
			if got := ce.Timeout(); got != tt.want {
				t.Errorf("Timeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ContextError exists so os.IsTimeout recognises deadline expiry, matching
// go-smb2. Its message is the underlying error's message, unprefixed.
func TestContextErrorMessageAndClassification(t *testing.T) {
	ce := &ContextError{Err: context.DeadlineExceeded}

	if !os.IsTimeout(ce) {
		t.Error("os.IsTimeout(*ContextError{DeadlineExceeded}) = false, want true")
	}
	if got, want := ce.Error(), context.DeadlineExceeded.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	// The wrapper must stay transparent to errors.Is and the Is* predicates.
	if !errors.Is(ce, context.DeadlineExceeded) {
		t.Error("errors.Is(ce, context.DeadlineExceeded) = false, want true")
	}
	if !IsTimeoutError(ce) {
		t.Error("IsTimeoutError(*ContextError{DeadlineExceeded}) = false, want true")
	}
	if !errors.Is(&ContextError{Err: context.Canceled}, context.Canceled) {
		t.Error("errors.Is(*ContextError{Canceled}, context.Canceled) = false, want true")
	}
}

// TransportError mirrors go-smb2's message format and stays transparent to
// errors.Is and IsNetworkError.
func TestTransportErrorMessageAndClassification(t *testing.T) {
	inner := errors.New("boom")
	te := &TransportError{Err: inner}

	if got, want := te.Error(), "connection error: boom"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(te, inner) {
		t.Error("errors.Is(te, inner) = false, want true")
	}
	if !IsNetworkError(&TransportError{Err: client.ErrConnectionClosed}) {
		t.Error("IsNetworkError(*TransportError{ErrConnectionClosed}) = false, want true")
	}
}

func TestWrapError(t *testing.T) {
	plain := errors.New("plain failure")
	alreadyCtx := &ContextError{Err: context.Canceled}
	alreadyTrans := &TransportError{Err: net.ErrClosed}

	tests := []struct {
		name        string
		err         error
		wantCtx     bool
		wantTrans   bool
		wantPassthr bool // wrapError must return the error unchanged
	}{
		{"nil", nil, false, false, true},
		{"canceled", context.Canceled, true, false, false},
		{"deadline", context.DeadlineExceeded, true, false, false},
		{"wrapped_canceled", fmt.Errorf("send: %w", context.Canceled), true, false, false},
		{"connection_closed", client.ErrConnectionClosed, false, true, false},
		{"econnreset", fmt.Errorf("read: %w", syscall.ECONNRESET), false, true, false},
		{"plain", plain, false, false, true},
		{"response_error", &ResponseError{Code: 0xC0000034}, false, false, true},
		{"already_context", alreadyCtx, true, false, true},
		{"already_transport", alreadyTrans, false, true, true},
		{"already_context_in_chain", fmt.Errorf("op: %w", alreadyCtx), true, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapError(tt.err)

			var ce *ContextError
			if hasCtx := errors.As(got, &ce); hasCtx != tt.wantCtx {
				t.Errorf("errors.As(*ContextError) = %v, want %v (got %v)", hasCtx, tt.wantCtx, got)
			}
			var te *TransportError
			if hasTrans := errors.As(got, &te); hasTrans != tt.wantTrans {
				t.Errorf("errors.As(*TransportError) = %v, want %v (got %v)", hasTrans, tt.wantTrans, got)
			}
			// Identity comparison on purpose: pass-through means the very
			// same error value, not merely an equivalent chain.
			if tt.wantPassthr && got != tt.err {
				t.Errorf("wrapError(%v) = %v, want the identical error", tt.err, got)
			}
			// Wrapping must never hide the original chain.
			if tt.err != nil && !errors.Is(got, unwrapAllTarget(tt.err)) {
				t.Errorf("wrapError(%v) lost the original error chain", tt.err)
			}
		})
	}
}

// unwrapAllTarget returns the innermost error of a chain, giving the tests a
// sentinel that must remain reachable through whatever wrapError adds.
func unwrapAllTarget(err error) error {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			return err
		}
		err = inner
	}
}

// context.DeadlineExceeded satisfies net.Error, so the classification order in
// wrapError matters: a deadline must become a ContextError, never a
// TransportError.
func TestWrapErrorPrefersContextOverTransport(t *testing.T) {
	got := wrapError(context.DeadlineExceeded)
	var te *TransportError
	if errors.As(got, &te) {
		t.Errorf("wrapError(DeadlineExceeded) produced a TransportError: %v", got)
	}
	var ce *ContextError
	if !errors.As(got, &ce) {
		t.Errorf("wrapError(DeadlineExceeded) = %v, want *ContextError", got)
	}
}

// The public API hands out wrapError results inside *os.PathError; both the
// wrapper type and the predicates must survive that layer.
func TestWrapErrorThroughPathError(t *testing.T) {
	err := &os.PathError{Op: "read", Path: "x.bin", Err: wrapError(fmt.Errorf("recv: %w", context.DeadlineExceeded))}

	var ce *ContextError
	if !errors.As(err, &ce) {
		t.Fatal("errors.As(*ContextError) through os.PathError = false, want true")
	}
	if !IsTimeoutError(err) {
		t.Error("IsTimeoutError through os.PathError = false, want true")
	}

	err = &os.PathError{Op: "read", Path: "x.bin", Err: wrapError(client.ErrConnectionClosed)}
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatal("errors.As(*TransportError) through os.PathError = false, want true")
	}
	if !IsNetworkError(err) {
		t.Error("IsNetworkError through os.PathError = false, want true")
	}
}
