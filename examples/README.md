# SMB1 Client Examples

This directory contains practical examples demonstrating how to use the smb1client library.

## Prerequisites

To run these examples, you need:
1. A running SMB1-capable server (Samba with NT1 enabled, legacy Windows, NAS device)
2. Valid credentials (username, password)
3. Network connectivity to the server

## Environment Variables

Except for `listshares/` (which takes command-line arguments), all examples use the following environment variables:

```bash
export SMB_SERVER="192.0.2.10:445"  # SMB server address and port
export SMB_SHARE="Public"           # Share name to mount
export SMB_USER="username"          # Username for authentication
export SMB_PASSWORD="password"      # Password for authentication
export SMB_DOMAIN="WORKGROUP"       # Domain (optional, defaults to WORKGROUP)
```

## Running Examples

Each example is in its own directory. To run an example:

```bash
# From the repository root
go run ./examples/basic

# Or from the example directory
cd examples/basic
go run main.go
```

## Available Examples

### 1. Basic Usage (`basic/`)

Demonstrates the fundamental workflow:
- Connecting to an SMB server
- Authenticating with NTLM
- Mounting a share
- Reading and writing files
- Getting file information
- Proper cleanup

**Run:**
```bash
go run ./examples/basic
```

### 2. Directory Operations (`dirops/`)

Shows directory management:
- Creating directories
- Creating nested directories (MkdirAll)
- Listing directory contents
- Walking directory trees
- Removing directories

**Run:**
```bash
go run ./examples/dirops
```

### 3. File Operations (`fileops/`)

Demonstrates advanced file operations:
- Opening files with different modes
- Reading and writing at specific offsets
- Seeking within files
- Copying files
- Checking file existence
- Renaming files

**Run:**
```bash
go run ./examples/fileops
```

### 4. Advanced Features (`advanced/`)

Covers advanced usage patterns:
- Context usage for timeouts and cancellation
- Error handling with type checking
- Concurrent file operations
- Custom logging via `smb1.WithLogger`

**Run:**
```bash
go run ./examples/advanced
```

### 5. Upload/Download (`uploaddownload/`)

Demonstrates file transfer between local filesystem and SMB share:
- Uploading files from local disk
- Downloading files to local disk
- Batch upload/download operations
- Progress reporting for large files

**Run:**
```bash
go run ./examples/uploaddownload
```

### 6. Share Enumeration (`listshares/`)

Lists the shares available on a server. Takes command-line arguments instead
of environment variables and does not mount anything:

**Run:**
```bash
go run ./examples/listshares <server:port> <username> <password>
```

### 7. Connection Pooling (`pool/`)

Demonstrates `smb1.ConnectionPool` for workloads with many short-lived
operations:
- Creating a pool with a custom `PoolConfig`
- Getting and returning pooled sessions
- Concurrent use from multiple goroutines
- Pool statistics

**Run:**
```bash
go run ./examples/pool
```

## Setting Up a Test Server

The repository ships a dockerized Samba server configured for SMB1 (NT1) —
the same one the integration test suite uses. See
[integration/README.md](../integration/README.md) for details.

```bash
# From the repository root
integration/up.sh

# Configure environment to match the test server
export SMB_SERVER=localhost:10445
export SMB_SHARE=testshare
export SMB_USER=smbtest
export SMB_PASSWORD=smbtest

# Run an example
go run ./examples/basic

# Stop and remove the server when done
integration/down.sh
```

## Common Issues

### Connection Refused

If you get "connection refused", ensure:
- The SMB server is running
- The port is accessible (check firewall)
- You're using the correct server address

### Authentication Failed

If authentication fails:
- Verify username and password are correct
- Check that the domain/workgroup is correct
- Ensure the server supports NTLM authentication

### Permission Denied

If you get permission errors:
- Verify the user has access to the share
- Check file permissions on the server
- Ensure the share allows write operations (if writing)

### Not Found Errors

If files/directories are not found:
- Verify the share name is correct
- Check that paths use backslashes or let the library normalize them
- Ensure files exist on the server

## Learning Path

Recommended order for learning:

1. **basic/** - Start here to understand the basics
2. **fileops/** - Learn file operations
3. **dirops/** - Understand directory management
4. **uploaddownload/** - Practice file transfers
5. **listshares/** - Enumerate shares on a server
6. **advanced/** - Explore contexts, error handling, and logging
7. **pool/** - Reuse connections for high-churn workloads

## Tips

- Always use `defer` for cleanup (Logoff, Umount, Close)
- Use contexts for timeouts on long-running operations
- Check errors and use helper functions (IsNotFoundError, etc.)
- Path separators can be forward or backslashes (normalized automatically)
- Enable debug logging by attaching a logger to context with `smb1.WithLogger()` for troubleshooting

## More Information

- [API Documentation](https://pkg.go.dev/github.com/macourteau/smb1client)
- [README.md](../README.md) - Main project documentation
- [ARCHITECTURE.md](../ARCHITECTURE.md) - Internal implementation details
- [ERRORS.md](../ERRORS.md) - Error handling conventions
