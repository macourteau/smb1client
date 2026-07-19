# Error Handling Guide

This document describes the error handling conventions used throughout the smb1client codebase. Following these patterns ensures consistent, predictable error handling that works well with Go's error inspection tools (`errors.Is`, `errors.As`).

## Table of Contents

- [Error Types](#error-types)
- [Error Wrapping Patterns](#error-wrapping-patterns)
- [Error Classification](#error-classification)
- [Best Practices](#best-practices)
- [Testing Errors](#testing-errors)

## Error Types

The library defines several custom error types to provide detailed context about failures:

### Protocol-Level Errors

#### `ResponseError`
Wraps an NT_STATUS error code from the SMB server.

```go
type ResponseError struct {
    Code uint32 // NT_STATUS code
}
```

**When returned:** Internal protocol layer when server returns non-zero status.

**Example:**
```go
if resp.header.Status != STATUS_SUCCESS {
    return &ResponseError{Code: resp.header.Status}
}
```

#### `SMBError`
Extended SMB error with command context and human-readable message.

```go
type SMBError struct {
    Status  uint32 // NT_STATUS code
    Command uint8  // SMB command that failed
    Message string // Human-readable message
}
```

**When returned:** When additional context beyond status code is helpful.

**Unwraps to:** `ResponseError` (via `Unwrap()` method)

**Example:**
```go
return &SMBError{
    Status:  STATUS_ACCESS_DENIED,
    Command: SMB_COM_NT_CREATE_ANDX,
    Message: "insufficient permissions to create file",
}
```

#### `InvalidResponseError`
Indicates the server sent a malformed or unexpected response.

```go
type InvalidResponseError struct {
    Message string
}
```

**When returned:** Protocol decoding failures, unexpected message formats.

**Example:**
```go
if len(data) < expectedSize {
    return &InvalidResponseError{
        Message: fmt.Sprintf("response too short: got %d bytes, need %d", len(data), expectedSize),
    }
}
```

### Client-Side Errors

#### `InternalError`
Indicates a client-side programming error or invalid state.

```go
type InternalError struct {
    Message string
}
```

**When returned:** Programming errors, invalid API usage, internal inconsistencies.

**Example:**
```go
if f.fid == 0 {
    return &InternalError{Message: "file handle is invalid"}
}
```

#### `ConnectionError`
Represents network-level failures.

```go
type ConnectionError struct {
    Op  string // Operation that failed
    Err error  // Underlying error
}
```

**When returned:** TCP failures, I/O errors, disconnects.

**Unwraps to:** Underlying network error

**Example:**
```go
if err := conn.Write(data); err != nil {
    return &ConnectionError{Op: "write", Err: err}
}
```

#### `AuthenticationError`
Represents authentication failures with user context.

```go
type AuthenticationError struct {
    User   string // Username that failed to authenticate
    Domain string // Domain (if applicable)
    Reason string // Human-readable reason
}
```

**When returned:** NTLM authentication failures, invalid credentials.

**Example:**
```go
return &AuthenticationError{
    User:   i.User,
    Domain: i.Domain,
    Reason: "invalid credentials",
}
```

### Wrapper Errors (go-smb2 Compatible)

On its way out of the public API, every error passes through a classification
step (`wrapError` in `errors.go`): context cancellations and deadline expiries
become `*ContextError`, and connection-level I/O failures become
`*TransportError`. Both types mirror go-smb2's types of the same name for
source compatibility. The resulting chain for a failed path operation is:

```
*os.PathError (or *os.LinkError)
    └── *ContextError or *TransportError
            └── underlying cause (context.Canceled, *net.OpError, ...)
```

Both wrappers implement `Unwrap()`, so `errors.Is`/`errors.As` and the `Is*`
predicates keep seeing the underlying cause through them.

#### `ContextError`
Wraps a context cancellation or deadline error surfaced by a public API call.

```go
type ContextError struct {
    Err error
}
```

**When returned:** An operation is aborted because its context was canceled or
its deadline expired.

**Unwraps to:** The underlying context error, so
`errors.Is(err, context.Canceled)` and
`errors.Is(err, context.DeadlineExceeded)` work through the wrapper.

**Extras:** `Timeout() bool` reports whether the wrapped error is a deadline
expiry — checked against the whole chain with `errors.Is`, so
`os.IsTimeout` recognises deadline expiry even when the context error carries
extra context (e.g. `"send failed: context deadline exceeded"`).

**Example:**
```go
_, err := share.WithContext(ctx).Open("file.txt")
if errors.Is(err, context.DeadlineExceeded) { // sees through ContextError
    // handle timeout
}
if os.IsTimeout(err) { // also works, via ContextError.Timeout
    // handle timeout
}
```

#### `TransportError`
Wraps an error coming from the `net.Conn` layer, such as a dropped TCP
connection or a socket read/write failure.

```go
type TransportError struct {
    Err error
}
```

**When returned:** A public API call fails because of a network-level error
(`IsNetworkError` reports true for the cause).

**Unwraps to:** The underlying network failure. go-smb2's `TransportError` has
no `Unwrap`; this one does so that `errors.Is`/`errors.As` and predicates like
`IsNetworkError` keep classifying the wrapped chain.

**Example:**
```go
_, err := share.ReadFile("file.txt")
var terr *smb1.TransportError
if errors.As(err, &terr) {
    log.Printf("connection lost: %v", terr.Err)
}
```

### Standard Library Errors

The library uses `os.PathError` and `os.LinkError` to maintain compatibility with Go's standard filesystem APIs.

#### `os.PathError`
Used for single-path operations that fail.

```go
type os.PathError struct {
    Op   string
    Path string
    Err  error
}
```

#### `os.LinkError`
Used for operations involving two paths (rename, link, etc.).

```go
type os.LinkError struct {
    Op  string
    Old string
    New string
    Err error
}
```

## Error Wrapping Patterns

### Pattern 1: Direct Return (Internal Packages)

**When:** Internal package returning protocol or transport errors.

**Pattern:** Return the error directly or with minimal wrapping.

```go
// Internal package - return erref.NtStatus directly
func StatusToError(status uint32) error {
    if status == STATUS_SUCCESS {
        return nil
    }
    return erref.NtStatus(status)
}
```

**Example:**
```go
// internal/client/conn.go
if err := c.allocateMID(); err != nil {
    return err  // Direct return - no wrapping needed
}
```

### Pattern 2: Wrapped Errors with Context (Internal to Internal)

**When:** Adding context while propagating errors between internal packages.

**Pattern:** Use `fmt.Errorf` with `%w` to preserve error chain.

```go
params, data, err := smb1.EncodeNTCreateRequest(req)
if err != nil {
    return nil, fmt.Errorf("smb1: failed to encode nt create request: %w", err)
}
```

**Rules:**
- Use `%w` verb to preserve error chain for `errors.Is` and `errors.As`
- Add descriptive context about what failed
- Prefix with `"smb1:"` for protocol-level errors

### Pattern 3: PathError Wrapping (Public API)

**When:** Public API methods that operate on filesystem paths.

**Pattern:** Wrap errors in `os.PathError` to maintain Go filesystem API compatibility.

```go
// Public API - single path operation (file.go)
func (f *File) Read(b []byte) (n int, err error) {
    n, err = f.f.Read(b, f.ctx)
    if err != nil && err != io.EOF {
        return n, &os.PathError{Op: "read", Path: f.name, Err: wrapError(err)}
    }
    return n, err
}
```

The `wrapError` call is the classification step described under
[Wrapper Errors](#wrapper-errors-go-smb2-compatible): context errors become
`*ContextError` and network failures become `*TransportError` before the
`os.PathError`/`os.LinkError` wrapping. Errors already carrying one of the
wrappers pass through untouched.

**Special cases:**
- `io.EOF` is NEVER wrapped - return it directly
- Context errors (`context.DeadlineExceeded`, `context.Canceled`) are wrapped
  in `*ContextError` inside the `os.PathError`, and remain visible to
  `errors.Is`

### Pattern 4: Error Translation (Public API Helpers)

**When:** Converting SMB errors to Go standard errors.

**Pattern:** Check error type and wrap with appropriate standard library error.

```go
func mapSMBErrorToOSError(err error, op, path string) error {
    if err == nil {
        return nil
    }

    // Translate to standard errors when possible
    if IsNotFoundError(err) {
        return &os.PathError{Op: op, Path: path, Err: os.ErrNotExist}
    }

    if IsPermissionError(err) {
        return &os.PathError{Op: op, Path: path, Err: os.ErrPermission}
    }

    // Wrap original error, classifying context and transport failures
    return &os.PathError{Op: op, Path: path, Err: wrapError(err)}
}
```

This allows callers to use both SMB-specific checks and standard Go error checks:

```go
err := share.Stat("file.txt")
// Both work:
if smb1.IsNotFoundError(err) { }  // SMB-specific check
if errors.Is(err, os.ErrNotExist) { }  // Standard Go check
```

### Pattern 5: Sentinel Errors

**When:** Package-level errors that represent specific conditions.

**Pattern:** Use `errors.New` for constant errors.

```go
var (
    ErrPoolClosed    = errors.New("connection pool is closed")
    ErrPoolExhausted = errors.New("connection pool exhausted")
)
```

**Usage:**
```go
if p.closed {
    return ErrPoolClosed
}

// Callers check with errors.Is
if errors.Is(err, smb1.ErrPoolClosed) {
    // Handle closed pool
}
```

## Error Classification

The library provides helper functions to classify errors without type assertions.

### Available Classifiers

```go
// Network-level errors
func IsNetworkError(err error) bool

// Authentication failures
func IsAuthError(err error) bool

// File/path not found
func IsNotFoundError(err error) bool

// Permission/access denied
func IsPermissionError(err error) bool

// File/object already exists
func IsExistError(err error) bool

// Timeout errors
func IsTimeoutError(err error) bool

// Temporary/retryable errors
func IsTemporary(err error) bool
```

### How Classifiers Work

Classifiers check multiple error types and sources:

1. **Standard library errors** (via `errors.Is`)
2. **Custom error types** (via `errors.As`)
3. **NT_STATUS codes** (via `ResponseError` or `erref.NtStatus`)
4. **Wrapped errors** (recursively via `os.PathError.Err`)

Example implementation:

```go
func IsNotFoundError(err error) bool {
    if err == nil {
        return false
    }

    // Check standard library error
    if errors.Is(err, os.ErrNotExist) {
        return true
    }

    // Check ResponseError with not-found NT_STATUS codes
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

    // Check erref.NtStatus directly
    var ntStatus erref.NtStatus
    if errors.As(err, &ntStatus) {
        // Same status checks...
    }

    // Check wrapped errors in PathError
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        return IsNotFoundError(pathErr.Err)
    }

    return false
}
```

### Using Classifiers

```go
data, err := share.ReadFile("config.txt")
if err != nil {
    if smb1.IsNotFoundError(err) {
        // Use default config
        data = defaultConfig
    } else if smb1.IsPermissionError(err) {
        return fmt.Errorf("insufficient permissions: %w", err)
    } else if smb1.IsTemporary(err) {
        // Retry the operation
        return retryWithBackoff(...)
    } else {
        return fmt.Errorf("unexpected error: %w", err)
    }
}
```

## Best Practices

### 1. Always Preserve Error Chains

**Good:**
```go
if err := doSomething(); err != nil {
    return fmt.Errorf("operation failed: %w", err)
}
```

**Bad:**
```go
if err := doSomething(); err != nil {
    return fmt.Errorf("operation failed: %v", err)  // %v breaks error chain!
}
```

### 2. Never Wrap io.EOF

**Good:**
```go
n, err := reader.Read(buf)
if err != nil && err != io.EOF {
    return n, &os.PathError{Op: "read", Path: path, Err: err}
}
return n, err  // Return io.EOF directly
```

**Bad:**
```go
n, err := reader.Read(buf)
if err != nil {
    return n, &os.PathError{Op: "read", Path: path, Err: err}  // Wraps io.EOF!
}
```

### 3. Use Appropriate Error Types by Layer

**Internal packages** (`internal/*`):
- Return protocol errors directly: `erref.NtStatus`, `ResponseError`
- Use `fmt.Errorf` with `%w` to add context
- Never use `os.PathError` or `os.LinkError`

**Public API** (`*.go` in root):
- Wrap in `os.PathError` for single-path operations
- Wrap in `os.LinkError` for two-path operations
- Translate common errors to standard library errors (`os.ErrNotExist`, `os.ErrPermission`)

### 4. Provide Context in Error Messages

**Good:**
```go
return fmt.Errorf("failed to encode nt create request for %q: %w", name, err)
```

**Bad:**
```go
return fmt.Errorf("encode failed: %w", err)  // Too vague
```

### 5. Use Classifiers for Error Checking

**Good:**
```go
if smb1.IsNotFoundError(err) {
    // Handle not found
}
```

**Better:**
```go
// Also works with standard errors
if errors.Is(err, os.ErrNotExist) {
    // Handle not found - works because mapSMBErrorToOSError translates
}
```

**Bad:**
```go
// Fragile - breaks if error is wrapped
if err.Error() == "file not found" {
    // Handle not found
}
```

### 6. Document Error Returns

```go
// ReadFile reads the entire file and returns its contents.
// It returns os.ErrNotExist if the file doesn't exist,
// os.ErrPermission if access is denied, or other errors
// for protocol or network failures.
func (s *Share) ReadFile(name string) ([]byte, error)
```

### 7. Handle Context Errors Appropriately

```go
select {
case <-ctx.Done():
    return ctx.Err()  // Return context error directly
case result := <-resultCh:
    return result
}
```

At the public API boundary, context errors are wrapped in `*ContextError`
(inside the `os.PathError` where applicable) by `wrapError`. The original
error stays reachable:

```go
err := ctx.Err()
if err != nil {
    return &os.PathError{Op: "read", Path: path, Err: wrapError(err)}
}
// Callers: errors.Is(err, context.Canceled) and os.IsTimeout(err) both work.
```

## Testing Errors

### Testing Error Classification

```go
func TestIsNotFoundError(t *testing.T) {
    tests := []struct {
        name string
        err  error
        want bool
    }{
        {
            name: "os.ErrNotExist",
            err:  os.ErrNotExist,
            want: true,
        },
        {
            name: "ResponseError with STATUS_NO_SUCH_FILE",
            err:  &ResponseError{Code: uint32(erref.STATUS_NO_SUCH_FILE)},
            want: true,
        },
        {
            name: "wrapped in PathError",
            err:  &os.PathError{Op: "open", Path: "test", Err: os.ErrNotExist},
            want: true,
        },
        {
            name: "wrapped with fmt.Errorf",
            err:  fmt.Errorf("file operation failed: %w", os.ErrNotExist),
            want: true,
        },
        {
            name: "permission error",
            err:  &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)},
            want: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := IsNotFoundError(tt.err)
            if got != tt.want {
                t.Errorf("IsNotFoundError() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Testing Error Unwrapping

```go
func TestSMBErrorUnwrap(t *testing.T) {
    smbErr := &SMBError{
        Status:  uint32(erref.STATUS_ACCESS_DENIED),
        Command: SMB_COM_NT_CREATE_ANDX,
        Message: "access denied",
    }

    // Test errors.As unwrapping
    var respErr *ResponseError
    if !errors.As(smbErr, &respErr) {
        t.Fatal("SMBError should unwrap to ResponseError")
    }

    if respErr.Code != smbErr.Status {
        t.Errorf("unwrapped code = %d, want %d", respErr.Code, smbErr.Status)
    }
}
```

### Testing Error Messages

```go
func TestErrorMessages(t *testing.T) {
    err := &InvalidResponseError{
        Message: "response too short",
    }

    got := err.Error()
    want := "smb1: invalid response: response too short"

    if got != want {
        t.Errorf("Error() = %q, want %q", got, want)
    }
}
```

### Testing Error Wrapping in Public API

```go
func TestFileReadError(t *testing.T) {
    // Mock a read failure
    f := &File{
        name: "/test/file.txt",
        // ... mock internal file that returns error
    }

    _, err := f.Read(make([]byte, 100))
    if err == nil {
        t.Fatal("expected error, got nil")
    }

    // Should be wrapped in PathError
    var pathErr *os.PathError
    if !errors.As(err, &pathErr) {
        t.Fatalf("expected *os.PathError, got %T", err)
    }

    if pathErr.Op != "read" {
        t.Errorf("Op = %q, want %q", pathErr.Op, "read")
    }

    if pathErr.Path != "/test/file.txt" {
        t.Errorf("Path = %q, want %q", pathErr.Path, "/test/file.txt")
    }
}
```

## Common Patterns Summary

### Internal Package Error Returns

```go
// Pattern: Direct return or simple wrapping
func internalFunction() error {
    if err := operation(); err != nil {
        return err  // or fmt.Errorf("context: %w", err)
    }
    return nil
}
```

### Public API Single-Path Operations

```go
// Pattern: Wrap in os.PathError (except io.EOF), classifying via wrapError
func (s *Share) PublicOperation(path string) error {
    err := s.internalOperation(path)
    if err != nil {
        return &os.PathError{Op: "operation", Path: path, Err: wrapError(err)}
    }
    return nil
}
```

### Public API Two-Path Operations

```go
// Pattern: Wrap in os.LinkError via the mapSMBErrorToLinkError helper,
// which translates not-found/permission causes to standard errors and
// classifies the rest with wrapError
func (s *Share) Rename(oldpath, newpath string) error {
    err := s.internalRename(oldpath, newpath)
    if err != nil {
        return mapSMBErrorToLinkError(err, "rename", oldpath, newpath)
    }
    return nil
}
```

### Public API with Error Translation

```go
// Pattern: Map to standard errors when appropriate
func (s *Share) Stat(name string) (os.FileInfo, error) {
    info, err := s.internalStat(name)
    if err != nil {
        return nil, mapSMBErrorToOSError(err, "stat", name)
    }
    return info, nil
}
```

### Error Checking in Calling Code

```go
// Pattern: Use classifiers or errors.Is/errors.As
err := share.ReadFile("config.txt")
if err != nil {
    // Approach 1: Use library classifiers
    if smb1.IsNotFoundError(err) {
        // handle
    }

    // Approach 2: Use standard library checks
    if errors.Is(err, os.ErrNotExist) {
        // handle
    }

    // Approach 3: Check specific error types
    var authErr *smb1.AuthenticationError
    if errors.As(err, &authErr) {
        log.Printf("auth failed for user %s: %s", authErr.User, authErr.Reason)
    }
}
```

## Decision Tree

When returning an error, follow this decision tree:

```
1. Is this io.EOF?
   YES → Return directly, never wrap
   NO  → Continue

2. What layer am I in?

   INTERNAL PACKAGE:
   a) Is this a new error I'm creating?
      → Return appropriate custom type (ResponseError, etc.)
   b) Is this an error I'm propagating?
      → Return directly OR wrap with fmt.Errorf("context: %w", err)

   PUBLIC API:
   a) Is this a single-path filesystem operation?
      → Wrap in os.PathError
   b) Is this a two-path filesystem operation?
      → Wrap in os.LinkError
   c) Should I translate to standard errors?
      → Use mapSMBErrorToOSError helper
   d) Is this a non-filesystem operation?
      → Return directly or wrap with fmt.Errorf

3. Always use %w to preserve error chains for errors.Is/errors.As
```

## References

- Error type definitions: `/errors.go`
- Error helpers: `mapSMBErrorToOSError`, `mapSMBErrorToLinkError` in `/session.go`
- Error classification: `Is*Error()` functions in `/errors.go`
- NT_STATUS codes: `/internal/erref/ntstatus.go`
- Error tests: `/errors_test.go`
