# Pure Go SMB1 Client Library

Pure Go SMB1/CIFS client for legacy systems. Root package `smb1`. The exported
API is a strict superset of go-smb2 v1.1.0 — every exported go-smb2 symbol
exists here with an identical signature.

## Quick Start

```go
d := &smb1.Dialer{
    Initiator: &smb1.NTLMInitiator{User: "user", Password: "pass", Domain: "WORKGROUP"},
}
session, _ := d.Dial(conn)
share, _ := session.Mount("ShareName")
data, _ := share.ReadFile("file.txt")
```

See [README.md](README.md) for complete API documentation and examples.

## Build and Test

```bash
go test ./...                      # Unit tests (no server needed)
./test.sh                          # Same; args pass through to go test
./test.sh -race ./...              # Race detection
go fmt ./... && go vet ./...       # Before committing
staticcheck ./...                  # Before committing (also -tags integration)

# Integration tests (dockerized Samba, NT1)
integration/up.sh                  # Start server (idempotent)
go test -tags integration ./...    # Env: SMB_SERVER/SMB_USER/SMB_PASSWORD/SMB_DOMAIN/SMB_SHARE
                                   # Defaults: localhost:10445, smbtest, smbtest, empty, testshare
integration/down.sh                # Stop server
```

## Architecture

5-layer design: TCP → NetBIOS (framing) → SMB1 (wire protocol) → Client (request/response, pipelining) → Public API

- **Public API** (root package): `dialer.go`, `session.go`, `file.go`, `fileinfo.go`,
  `fsinfo.go`, `initiator.go`, `capabilities.go`, `servertime.go`, `setinfo.go`,
  `match.go`, `dirfs.go`, `pool.go`, `errors.go`, `compat.go`, `smb1.go`
- **Internal packages** (never import from outside this module):
  - `internal/smb1` - Wire protocol encoding/decoding, Trans2, RAP
  - `internal/client` - Connection management, MID-based request/response, pipelined reads/writes
  - `internal/netbios` - Session framing (RFC 1001/1002)
  - `internal/ntlm`, `internal/spnego` - Authentication (NTLM adapted from go-smb2, BSD-2-Clause)
  - `internal/dcerpc`, `internal/srvsvc` - RPC fallback for share enumeration
  - `internal/logging` - Context-based Logger interface (re-exported at root)
  - `internal/utf16le` - String encoding
  - `internal/erref` - NT status → Go error mapping

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design and
[ERRORS.md](ERRORS.md) for error wrapping conventions.

## Key Conventions

- **go-smb2 parity contract**: the public API must not drift from go-smb2's
  signatures. Behavioral differences are allowed only where SMB1 cannot express
  the SMB2 semantics, and must be documented (README "API Compatibility"
  section) and covered by `compat_gosmb2_test.go` / `integration_parity_test.go`.
- **Table-driven tests** throughout; integration tests live behind the
  `integration` build tag.
- **Comments explain why**, not what. Wire-format quirks and server
  accommodations (e.g. RAP fallback, legacy Statfs level) get a why-comment.
- **Error wrapping**: public API wraps in `*os.PathError`/`*os.LinkError` with
  `wrapError` classification (`*ContextError`/`*TransportError`); internal
  packages return protocol errors directly. Never wrap `io.EOF`.
- **Protocol limits**: read chunks 65,520 bytes (130,048 with CAP_LARGE_READX),
  write chunks 130,048 bytes; large transfers are pipelined up to the server's
  MaxMpxCount.
- **Security scope**: NTLM v2 only, no SMB signing/encryption. For legacy
  SMB1-only servers in isolated networks.
- **Go version floor**: the `go` directive in go.mod is a consumer-facing
  minimum, kept at the oldest release the module supports (Go's two-release
  support window; currently also pinned by golang.org/x/crypto's own floor).
  Maintenance is automated: `update-go-floor.yml` raises it to the window
  floor when a new Go minor ships (raise-only, `major.minor.0`). Never raise
  it by hand to the latest version just because development uses a newer
  toolchain. A dependency demanding more than the window floor fails the CI
  floor leg on its Dependabot PR — that raise is a human call.
- **Commit messages**: Conventional Commits; no AI attribution. Example:
  "fix: respect the uint16 limit when encoding read lengths"

## CI and Releases

- CI (`.github/workflows/ci.yml`): `build-test` runs the unit suite on two Go
  toolchains — the go.mod floor and latest stable — and both matrix legs are
  required checks on `main`. The `integration` job runs the dockerized-Samba
  blackbox suite on pushes to `main` only.
- Releases (`.github/workflows/release.yml`) are automatic: a daily job parses
  Conventional Commit subjects since the last `v*` tag and publishes a GitHub
  Release (the tag is the deliverable). Mapping: `feat:` → minor, `fix:` →
  patch, `!`/`BREAKING CHANGE:` → major; `chore:/docs:/test:/refactor:/ci:` →
  no release. A releasable change without a `feat:`/`fix:` prefix never ships
  — prefix accordingly. Commits touching no shippable file (`*.go`, go.mod,
  go.sum) never release.
- Run the full CI-equivalent locally before pushing (the Build and Test
  commands above plus the cross-builds: `GOOS=windows go build ./...`,
  `GOOS=darwin GOARCH=arm64 go build ./...`); CI confirms, it does not
  discover.
