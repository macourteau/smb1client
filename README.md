# smb1client

[![Go Reference](https://pkg.go.dev/badge/github.com/macourteau/smb1client.svg)](https://pkg.go.dev/github.com/macourteau/smb1client)
[![CI](https://github.com/macourteau/smb1client/actions/workflows/ci.yml/badge.svg)](https://github.com/macourteau/smb1client/actions/workflows/ci.yml)

## ⚠️ Security Warning

**SMB1/CIFS is deprecated and insecure. Microsoft disabled it by default starting with Windows 10 Fall Creators Update (1709) and Windows Server version 1709.**

This library should **ONLY** be used in controlled, isolated environments where:
- Legacy systems require SMB1 support
- Modern protocols (SMB2/3) are not available
- The network is trusted and isolated from external threats

**Known security issues with SMB1:**
- Exploited by ransomware (e.g., WannaCry, NotPetya)
- No encryption support
- Susceptible to man-in-the-middle attacks
- Credential replay attacks possible
- No message integrity checking (this client does not implement SMB signing)

**For modern SMB support, use [github.com/hirochachacha/go-smb2](https://github.com/hirochachacha/go-smb2) instead.**

## Overview

Pure Go implementation of the SMB1/CIFS client protocol (root package `smb1`). The exported API is a superset of go-smb2's: every exported go-smb2 symbol exists here with an identical signature, so migrating code between the two libraries is an import swap. On top of that parity surface, this library adds connection pooling, error-classification predicates, copy helpers, server capability/clock/volume queries, and context-based logging hooks.

### Why use this library?

- **Pure Go**: no CGO dependencies; cross-platform compilation works out of the box
- **go-smb2 API parity**: code written against go-smb2 compiles unchanged after swapping the import
- **No privileges**: does not require root/admin or mounting filesystems
- **Modern Go**: context support, standard library error semantics (`*os.PathError`, `os.ErrNotExist`), `io/fs` integration via `Share.DirFS`
- **Legacy support**: connects to old NAS devices, Windows XP/2003, embedded systems

### When to use SMB1 vs SMB2/3

Use SMB1 (this library) when:
- Connecting to devices that only support SMB1 (pre-2007 systems)
- Legacy NAS devices or embedded systems
- Windows XP, Windows Server 2003, or old Samba versions

Use SMB2/3 (go-smb2) when:
- Windows Vista or later, Windows Server 2008 or later
- Modern Linux with Samba 3.6+
- Security and performance are priorities
- Encryption or signing is required

## Installation

```bash
go get github.com/macourteau/smb1client
```

## Quick Start

```go
package main

import (
    "fmt"
    "net"

    "github.com/macourteau/smb1client"
)

func main() {
    // Connect to SMB server
    conn, err := net.Dial("tcp", "192.0.2.10:445")
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    // Authenticate with NTLM
    d := &smb1.Dialer{
        Initiator: &smb1.NTLMInitiator{
            User:     "username",
            Password: "password",
            Domain:   "WORKGROUP",
        },
    }

    session, err := d.Dial(conn)
    if err != nil {
        panic(err)
    }
    defer session.Logoff()

    // Mount share
    share, err := session.Mount("sharename")
    if err != nil {
        panic(err)
    }
    defer share.Umount()

    // Read file
    data, err := share.ReadFile("file.txt")
    if err != nil {
        panic(err)
    }
    fmt.Printf("File contents: %s\n", data)
}
```

## Features

### Supported Operations

**Session management:**
- Protocol negotiation with SMB1 servers (dialect `NT LM 0.12`)
- NTLM v2 authentication (password or precomputed hash)
- Share enumeration (`ListSharenames`, via RAP with a DCE/RPC SRVSVC fallback)
- Negotiated server capabilities (`Session.Capabilities`)
- Server clock reporting (`Session.ServerTime`, from the negotiate response)
- Context support for timeouts and cancellation (`WithContext`, `DialContext`)
- Session logoff

**Share operations:**
- Mount/unmount shares (share name or full UNC path)
- Directory listing (`ReadDir`, `Readdir`), tree walking (`Walk`), globbing (`Glob`, `Match`)
- Create directories (`Mkdir`, `MkdirAll`)
- Stat operations (`Stat`, `Lstat`, `Exists`, `IsDir`)
- Timestamp and attribute changes (`Chtimes`, `Chmod`)
- Filesystem capacity (`Share.Statfs`, `File.Statfs`, with legacy-level fallback)
- Volume identity — serial number and label (`Share.VolumeInfo`)
- Rename, remove (`Remove`, `RemoveAll`), truncate
- Copy helpers (`CopyFile` within the share, `CopyFrom`/`CopyTo` between local disk and the share)
- Read-only `io/fs` view of a share subtree (`Share.DirFS`)

**File operations:**
- `Open`, `Create`, `OpenFile` with standard os package semantics
- `Read`, `Write`, `ReadAt`, `WriteAt`, `Seek`, `Truncate`, `Sync`
- `ReadFile`, `WriteFile` convenience methods
- `ReadFrom`/`WriteTo` streaming (client-side; see compatibility notes)
- Pipelined reads and writes for large transfers, sized to the server's advertised `MaxMpxCount`
- Standard `io.Reader`, `io.Writer`, `io.Seeker`, `io.ReaderFrom`, `io.WriterTo` interfaces

**Connection pooling:**
- `ConnectionPool` for reusing authenticated sessions (see [Connection Pooling](#connection-pooling))

**Error handling:**
- Standard os package error types (`*os.PathError`, `*os.LinkError`, `os.ErrNotExist`, ...)
- Classification predicates: `IsNotFoundError`, `IsPermissionError`, `IsAuthError`, `IsExistError`, `IsNetworkError`, `IsTimeoutError`, `IsTemporary`
- go-smb2-compatible wrapper types `ContextError` and `TransportError`

**Path compatibility:**
- Automatic `/` to `\` normalization (controlled by `NORMALIZE_PATH`)
- UNC path handling, validation, and traversal protection
- Helpers: `ToWindowsPath`, `ToUnixPath`, `NormalizeShareName`, `ValidateShareName`

**Logging:**
- Context-based: attach any `smb1.Logger` implementation (Debug/Info/Warn/Error methods) with `smb1.WithLogger`

### Not Supported

- Plaintext/legacy authentication (security reasons); NTLM v2 only
- SMB signing
- SMB encryption (does not exist in SMB1)
- NetBIOS over NetBEUI (only direct TCP on port 445)
- DFS (Distributed File System)
- General named pipe operations (only `\srvsvc` for share enumeration)
- Symbolic links (`Symlink`/`Readlink` exist for API parity but return `errors.ErrUnsupported`)
- File locking
- Extended attributes

## Documentation

- **[API Reference](https://pkg.go.dev/github.com/macourteau/smb1client)**: full godoc documentation
- **[Examples](examples/)**: runnable example programs
- **[ARCHITECTURE.md](ARCHITECTURE.md)**: internal implementation details
- **[ERRORS.md](ERRORS.md)**: error handling conventions
- **[integration/README.md](integration/README.md)**: dockerized SMB1 test server

## Usage Examples

### Basic File Operations

```go
// Write a file
err := share.WriteFile("test.txt", []byte("Hello, SMB1!"), 0644)

// Read a file
data, err := share.ReadFile("test.txt")

// Check if file exists
_, err = share.Stat("test.txt")
if os.IsNotExist(err) {
    fmt.Println("File does not exist")
}

// Rename a file
err = share.Rename("old.txt", "new.txt")
```

### Directory Operations

```go
// Create directory
err := share.Mkdir("mydir", 0755)

// Create nested directories
err = share.MkdirAll("path/to/nested/dir", 0755)

// List directory contents
files, err := share.ReadDir("mydir")
for _, f := range files {
    fmt.Printf("%s (%d bytes)\n", f.Name(), f.Size())
}

// Remove file or empty directory
err = share.Remove("mydir/file.txt")

// Remove a tree
err = share.RemoveAll("mydir")
```

### Advanced File Operations

```go
// Open file with specific flags
f, err := share.OpenFile("data.bin",
    os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
if err != nil {
    return err
}
defer f.Close()

// Write at specific offset
n, err := f.WriteAt([]byte("data"), 100)

// Seek to position
offset, err := f.Seek(0, io.SeekStart)

// Read incrementally
buf := make([]byte, 4096)
for {
    n, err := f.Read(buf)
    if err == io.EOF {
        break
    }
    // Process buf[:n]
}
```

### Context Support

```go
// Set timeout for dial
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

session, err := d.DialContext(ctx, conn)

// Use context for all operations
sessionWithTimeout := session.WithContext(ctx)
share, err := sessionWithTimeout.Mount("Share")
```

### Share Enumeration

```go
// List all shares on the server
shares, err := session.ListSharenames()
if err != nil {
    log.Fatalf("Failed to list shares: %v", err)
}

for _, share := range shares {
    fmt.Printf("Share: %s\n", share)
}
```

The library uses RAP (Remote Administration Protocol) for share enumeration on most servers. If RAP is not supported (common on some embedded devices), it falls back to DCE/RPC with the SRVSVC interface.

### Filesystem Information

```go
// Capacity of the filesystem backing the mounted share. The name argument
// exists for go-smb2 parity; "" queries the share root.
info, err := share.Statfs("")
if err != nil {
    log.Fatalf("Failed to query capacity: %v", err)
}
totalBytes := info.TotalBlockCount() * info.FragmentSize() * info.BlockSize()
freeBytes := info.FreeBlockCount() * info.FragmentSize() * info.BlockSize()
fmt.Printf("total=%d free=%d\n", totalBytes, freeBytes)

// Identity of the volume behind the share
vol, err := share.VolumeInfo()
if err != nil {
    log.Fatalf("Failed to query volume: %v", err)
}
fmt.Printf("serial=%#08x label=%q\n", vol.SerialNumber, vol.Label)
```

`Statfs` prefers `SMB_QUERY_FS_SIZE_INFO`, whose allocation-unit counts are
64-bit, and falls back to the legacy `SMB_INFO_ALLOCATION` level when a server
declines it — the same accommodation share enumeration makes for servers
lacking RAP. The fallback is chosen from the returned NT_STATUS, so a network
or permission failure propagates instead of triggering a pointless retry.

`Statfs` returns go-smb2's `FileFsInfo` interface with the same field mapping:
`BlockSize` is bytes per sector, `FragmentSize` is sectors per allocation unit,
and the three counts are in allocation units. SMB1's
`TRANS2_QUERY_FS_INFORMATION` is share-wide, so the name argument is validated
but does not affect the query, and SMB1 has no per-caller quota concept, so
`AvailableBlockCount` always equals `FreeBlockCount`.

`VolumeInfo` reports the serial number assigned when the volume was formatted,
which distinguishes one piece of removable media from another **without writing
anything to the share**. It is not a strong identifier: it is not globally
unique, and reformatting changes it. `Label` is often empty, and `CreationTime`
is the zero time on servers whose filesystem does not record it.

### Connection Pooling

For workloads with many short-lived operations, `ConnectionPool` reuses
authenticated sessions instead of re-dialing and re-authenticating each time:

```go
d := &smb1.Dialer{
    Initiator: &smb1.NTLMInitiator{User: "username", Password: "password"},
}

pool := smb1.NewConnectionPool("192.0.2.10:445", d, nil) // nil = DefaultPoolConfig()
defer pool.Close()

conn, err := pool.Get(context.Background())
if err != nil {
    return err
}
defer conn.Close() // returns the session to the pool

share, err := conn.Mount("Public")
```

`PoolConfig` controls sizing and lifetime: `MaxIdle` (default 5), `MaxActive`
(default 10), `IdleTimeout` (default 5 minutes), `WaitTimeout` (default 30
seconds), and an optional `HealthCheck` callback run before an idle session is
reused. `PooledSession.Close` returns the session to the pool;
`ReallyClose` tears the connection down instead. `Pool.Stats()` reports idle
and active counts. Getting from a closed or exhausted pool fails with the
sentinel errors `ErrPoolClosed` / `ErrPoolExhausted`.

### Error Handling

The library provides both SMB-specific and standard Go error types:

```go
f, err := share.Open("file.txt")
if err != nil {
    // Check specific error types
    if smb1.IsNotFoundError(err) {
        log.Println("File not found")
    } else if smb1.IsPermissionError(err) {
        log.Println("Permission denied")
    } else if smb1.IsAuthError(err) {
        log.Println("Authentication failed")
    } else if smb1.IsNetworkError(err) {
        log.Println("Network error")
    } else {
        log.Printf("Other error: %v", err)
    }
    return
}
defer f.Close()

// Also works with standard library error checking
if errors.Is(err, os.ErrNotExist) {
    // File not found
}
```

See [ERRORS.md](ERRORS.md) for the complete error taxonomy, including the
go-smb2-compatible `ContextError` and `TransportError` wrappers.

### Logging Configuration

Logging is context-based. Implement the four-method `smb1.Logger` interface
and attach it to the context before calling SMB operations:

```go
// Create a custom logger that implements smb1.Logger interface
type MyLogger struct {
    logger *log.Logger
}

func (l *MyLogger) Debug(format string, v ...interface{}) {
    l.logger.Printf("[DEBUG] "+format, v...)
}

func (l *MyLogger) Info(format string, v ...interface{}) {
    l.logger.Printf("[INFO] "+format, v...)
}

func (l *MyLogger) Warn(format string, v ...interface{}) {
    l.logger.Printf("[WARN] "+format, v...)
}

func (l *MyLogger) Error(format string, v ...interface{}) {
    l.logger.Printf("[ERROR] "+format, v...)
}

// Attach logger to context
logger := &MyLogger{logger: log.New(os.Stderr, "[smb1] ", log.LstdFlags)}
ctx := smb1.WithLogger(context.Background(), logger)

// Use context with SMB operations
session, err := dialer.DialContext(ctx, conn)
```

Operations invoked without a logger in their context log nothing. Level
filtering is up to the `Logger` implementation — the library calls the method
matching the message's severity.

## API Compatibility with go-smb2

The exported API is a strict superset of go-smb2 v1.1.0: every exported
go-smb2 symbol — types, methods, functions, fields, and constants — exists
here with an identical signature. Migrating code from go-smb2 to this library
(or back) is an import swap:

```go
// SMB2 code
import "github.com/hirochachacha/go-smb2"
d := &smb2.Dialer{
    Initiator: &smb2.NTLMInitiator{
        User:     "username",
        Password: "password",
    },
}

// SMB1 code (import swap; the package name changes from smb2 to smb1)
import "github.com/macourteau/smb1client"
d := &smb1.Dialer{
    Initiator: &smb1.NTLMInitiator{
        User:     "username",
        Password: "password",
    },
}
```

Signatures match, but SMB1 cannot express everything SMB2 can, so a few
methods behave differently. These are the behavioral notes to review when
migrating:

- `Dialer.MaxCreditBalance` and `Dialer.Negotiator` are accepted but ignored:
  SMB1 has no credit-based flow control, and SMB1 negotiation carries none of
  the SMB2 negotiate options (signing, client GUID, dialect selection — the
  dialect is always `NT LM 0.12`).
- `Statfs(name)` matches go-smb2's signature and validates the name like any
  other path, but SMB1's `TRANS2_QUERY_FS_INFORMATION` is share-wide, so the
  name does not affect the query. `AvailableBlockCount` equals
  `FreeBlockCount` because SMB1 has no per-caller quota figure.
- `Lstat` is identical to `Stat`: SMB1 has no symbolic links, so there are no
  separate lstat semantics.
- `Symlink` and `Readlink` always fail with `errors.ErrUnsupported` (wrapped
  in `*os.LinkError` / `*os.PathError`): the reparse-point FSCTLs go-smb2
  uses are SMB2 constructs with no SMB1 equivalent.
- `Chmod` maps only the owner-write bit (0200) to `FILE_ATTRIBUTE_READONLY` —
  the only permission SMB attributes can express. All other attributes are
  preserved via read-modify-write, matching go-smb2's behavior. Servers that
  reject the TRANS2 set with `STATUS_NOT_SUPPORTED` get a second attempt via
  the core-protocol `SMB_COM_SET_INFORMATION` command; some embedded servers
  support no attribute mutation at all, in which case `Chmod` surfaces that
  status to the caller.
- `Chtimes` treats a zero `time.Time` as "leave that timestamp unchanged"
  (SMB1 encodes it as FILETIME 0, which the protocol defines that way). This
  is a deliberate improvement over go-smb2, which encodes zero times
  literally.
- `Rename` does not replace an existing target — `SMB_COM_RENAME` fails with
  `STATUS_OBJECT_NAME_COLLISION` (detect with `IsExistError`). go-smb2's
  `Rename` also does not overwrite an existing target.
- `File.ReadFrom` and `File.WriteTo` are client-side streaming in buffered
  chunks. Unlike go-smb2, no server-side copy is attempted when the other end
  is also a remote file; the data always flows through the client.
- `Mount` accepts either a bare share name or a full UNC path
  (`\\server\share`), same as go-smb2.

## Requirements

- **Go version**: per the `go` directive in [go.mod](go.mod) (Go 1.26)
- **Network**: TCP connectivity to the SMB server on port 445
- **Server**: SMB1/CIFS capable server (Samba with `NT1` enabled, legacy Windows, NAS devices)

## Testing

Unit tests run without any server:

```bash
go test ./...        # or ./test.sh
go test -race ./...  # race detection
go test -cover ./... # coverage
```

Integration tests run against a dockerized Samba server configured to speak
SMB1 (NT1), included in [integration/](integration/):

```bash
integration/up.sh                  # build + start the server (idempotent)
go test -tags integration ./...    # run unit + integration tests
integration/down.sh                # stop + remove the server
```

The integration suite reads these environment variables; the defaults match
the dockerized server, so none need to be set when using it:

| Variable       | Default           |
|----------------|-------------------|
| `SMB_SERVER`   | `localhost:10445` |
| `SMB_USER`     | `smbtest`         |
| `SMB_PASSWORD` | `smbtest`         |
| `SMB_DOMAIN`   | (empty)           |
| `SMB_SHARE`    | `testshare`       |

Point the variables at any other SMB1-capable server to test against real
hardware.

## Contributing

Contributions are welcome. Please:
1. Open an issue to discuss significant changes
2. Follow existing code style and conventions
3. Add tests for new functionality
4. Update documentation

Note the compatibility contract: the public API must not drift from go-smb2's
signatures (`compat_gosmb2_test.go` guards part of this).

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- API design based on the excellent [go-smb2](https://github.com/hirochachacha/go-smb2) library by hirochachacha
- NTLM implementation adapted from go-smb2 (BSD-2-Clause License)
- Protocol specifications from Microsoft [MS-CIFS] and [MS-SMB]
- Tested against Samba and Windows implementations

## References

- [MS-CIFS]: Common Internet File System (CIFS) Protocol Specification
- [MS-SMB]: Server Message Block (SMB) Protocol Specification
- [MS-SRVS]: Server Service (SRVSVC) Remote Protocol Specification
- [MS-RPCE]: Remote Procedure Call Protocol Extensions
- [go-smb2](https://github.com/hirochachacha/go-smb2): SMB2/3 client library for Go
- [Samba](https://www.samba.org/): Open-source SMB/CIFS implementation
