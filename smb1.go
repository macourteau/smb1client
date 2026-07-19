// Package smb1 implements a pure Go SMB1/CIFS client library.
//
// # Security Warning
//
// SMB1/CIFS is an outdated protocol with known security vulnerabilities.
// It should only be used with legacy systems that do not support SMB2 or SMB3.
// For modern systems, use the go-smb2 library instead:
// https://github.com/hirochachacha/go-smb2
//
// This library is provided for compatibility with old NAS devices, embedded systems,
// and Windows XP/2003 servers that require SMB1.
//
// # Usage
//
// Basic usage example:
//
//	package main
//
//	import (
//		"context"
//		"fmt"
//		"io"
//		"log"
//		"net"
//		"os"
//
//		"github.com/macourteau/smb1client"
//	)
//
//	func main() {
//		// Connect to SMB server
//		conn, err := net.Dial("tcp", "192.168.1.100:445")
//		if err != nil {
//			panic(err)
//		}
//		defer conn.Close()
//
//		// Setup authentication
//		d := &smb1.Dialer{
//			Initiator: &smb1.NTLMInitiator{
//				User:     "username",
//				Password: "password",
//				Domain:   "WORKGROUP",
//			},
//		}
//
//		// Establish SMB session
//		session, err := d.Dial(conn)
//		if err != nil {
//			panic(err)
//		}
//		defer session.Logoff()
//
//		// Mount share
//		share, err := session.Mount("Share")
//		if err != nil {
//			panic(err)
//		}
//		defer share.Umount()
//
//		// Open file
//		f, err := share.Open("file.txt")
//		if err != nil {
//			panic(err)
//		}
//		defer f.Close()
//
//		// Read file
//		data, err := io.ReadAll(f)
//		if err != nil {
//			panic(err)
//		}
//		fmt.Printf("File contents: %s\n", data)
//	}
//
// # Logging
//
// This library uses context-based logging. To enable logging, attach a logger
// to the context before calling SMB operations:
//
//	// Create a custom logger
//	type myLogger struct{}
//
//	func (l *myLogger) Debug(format string, v ...interface{}) {
//		log.Printf("[DEBUG] "+format, v...)
//	}
//
//	func (l *myLogger) Info(format string, v ...interface{}) {
//		log.Printf("[INFO] "+format, v...)
//	}
//
//	func (l *myLogger) Warn(format string, v ...interface{}) {
//		log.Printf("[WARN] "+format, v...)
//	}
//
//	func (l *myLogger) Error(format string, v ...interface{}) {
//		log.Printf("[ERROR] "+format, v...)
//	}
//
//	// Attach logger to context
//	ctx := smb1.WithLogger(context.Background(), &myLogger{})
//
//	// Use context with SMB operations
//	session, err := d.DialContext(ctx, conn)
//
// # API Compatibility
//
// This library provides an API compatible with go-smb2 for easy migration.
// Code written for go-smb2 can be adapted to SMB1 by changing import paths
// and adjusting for protocol differences.
//
// # Protocol Support
//
// Supported features:
//   - NTLM v2 authentication
//   - Share mounting/unmounting
//   - File read/write operations
//   - Directory operations (create, list, remove)
//   - File operations (stat, truncate, rename)
//
// Unsupported features:
//   - SMB signing (security feature)
//   - Encryption (not available in SMB1)
//   - DFS (Distributed File System)
//   - Extended attributes
//
// For more features and better security, migrate to SMB2/SMB3 using go-smb2:
// https://github.com/hirochachacha/go-smb2
package smb1

import (
	"context"

	"github.com/macourteau/smb1client/internal/logging"
)

// Logger is the interface for logging. Applications can provide
// their own logger implementation for custom logging behavior.
type Logger = logging.Logger

// WithLogger returns a new context with the provided logger attached.
// The logger will be used by SMB operations that accept this context.
func WithLogger(ctx context.Context, logger Logger) context.Context {
	return logging.WithLogger(ctx, logger)
}

// LoggerFromContext retrieves the logger from the context.
// If no logger is attached to the context, it returns a no-op logger.
func LoggerFromContext(ctx context.Context) Logger {
	return logging.FromContext(ctx)
}
