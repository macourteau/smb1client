package smb1_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/macourteau/smb1client"
)

// Example demonstrates basic error handling with the SMB1 client
func Example_errorHandling() {
	// Connect to SMB server
	conn, err := net.DialTimeout("tcp", "192.168.1.100:445", 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Setup authentication
	d := &smb1.Dialer{
		Initiator: &smb1.NTLMInitiator{
			User:     "username",
			Password: "password",
			Domain:   "WORKGROUP",
		},
	}

	// Establish SMB session with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session, err := d.DialContext(ctx, conn)
	if err != nil {
		// Check for specific error types
		if smb1.IsAuthError(err) {
			log.Fatal("Authentication failed - check username/password")
		}
		if smb1.IsNetworkError(err) {
			log.Fatal("Network error - check connectivity")
		}
		log.Fatal(err)
	}
	defer session.Logoff()

	// Mount share
	share, err := session.Mount("Share")
	if err != nil {
		log.Fatal(err)
	}
	defer share.Umount()

	// Try to open a file with error handling
	file, err := share.Open("nonexistent.txt")
	if err != nil {
		if smb1.IsNotFoundError(err) {
			fmt.Println("File not found - this is expected")
			return
		}
		if smb1.IsPermissionError(err) {
			log.Fatal("Permission denied")
		}
		log.Fatal(err)
	}
	defer file.Close()
}

// Example demonstrates retry logic for transient errors
func Example_retryLogic() {
	// The library does not retry on your behalf and does not reconnect: once a
	// connection fails it stays failed, so a caller that needs durability owns
	// the backoff and the redial. IsTemporary classifies which errors are worth
	// another attempt.

	// Simulated operation that might fail transiently
	operation := func() error {
		// Your SMB operation here
		return nil
	}

	// Retry on temporary errors
	err := operation()
	if err != nil && smb1.IsTemporary(err) {
		// Back off and try again — or dial a fresh session, if the failure was
		// the connection itself (errors.Is(err, net.ErrClosed)).
		log.Printf("Temporary error, retrying: %v", err)
	}

	fmt.Println("Operation completed:", err == nil)
	// Output: Operation completed: true
}

// Example demonstrates compatibility features
func Example_compatibility() {
	// Path conversion
	windowsPath := smb1.ToWindowsPath("dir/subdir/file.txt")
	fmt.Println("Windows path:", windowsPath)

	unixPath := smb1.ToUnixPath("dir\\subdir\\file.txt")
	fmt.Println("Unix path:", unixPath)

	// Share name normalization
	shareName := smb1.NormalizeShareName("MyShare", "192.168.1.100:445")
	fmt.Println("Normalized share:", shareName)

	// Validate share name
	err := smb1.ValidateShareName("ValidShare")
	fmt.Println("Valid share name:", err == nil)

	// Output:
	// Windows path: dir\subdir\file.txt
	// Unix path: dir/subdir/file.txt
	// Normalized share: \\192.168.1.100\MyShare
	// Valid share name: true
}

// Example demonstrates logging configuration with context
func Example_logging() {
	// Note: In real code, define a logger type that implements smb1.Logger interface.
	// For this example, we just show the concept.

	// Logging is now context-based. To enable logging:
	// 1. Create a type that implements the smb1.Logger interface
	// 2. Attach it to context using smb1.WithLogger()
	// 3. Pass the context to SMB operations

	fmt.Println("Logging configured via context")
	// Output: Logging configured via context
}

// Example demonstrates how to list available shares on an SMB1 server
func Example_listShares() {
	// Connect to SMB server
	conn, err := net.DialTimeout("tcp", "192.168.1.100:445", 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Setup authentication
	d := &smb1.Dialer{
		Initiator: &smb1.NTLMInitiator{
			User:     "username",
			Password: "password",
		},
	}

	// Establish SMB session
	session, err := d.Dial(conn)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Logoff()

	// List available shares using RAP NetShareEnum
	shares, err := session.ListSharenames()
	if err != nil {
		log.Fatal(err)
	}

	// Display the shares
	fmt.Println("Available shares:")
	for _, share := range shares {
		// Filter out administrative shares if desired
		if share[len(share)-1] == '$' {
			continue // Skip hidden/admin shares
		}
		fmt.Printf("  - %s\n", share)
	}

	// Mount one of the shares
	if len(shares) > 0 {
		// Find first non-admin share
		for _, shareName := range shares {
			if shareName != "IPC$" && shareName[len(shareName)-1] != '$' {
				share, err := session.Mount(shareName)
				if err != nil {
					log.Printf("Failed to mount %s: %v", shareName, err)
					continue
				}
				defer share.Umount()

				fmt.Printf("Successfully mounted: %s\n", shareName)
				break
			}
		}
	}
}
