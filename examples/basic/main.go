package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/macourteau/smb1client"
)

// This example demonstrates the basic usage of the SMB1 client library:
// connecting to a server, authenticating, mounting a share, and performing
// simple file operations (read and write).
//
// To run this example:
//   go run examples/basic_usage.go
//
// Environment variables:
//   SMB_SERVER   - SMB server address (e.g., "192.168.1.100:445")
//   SMB_SHARE    - Share name (e.g., "Public")
//   SMB_USER     - Username
//   SMB_PASSWORD - Password
//   SMB_DOMAIN   - Domain (optional, defaults to "WORKGROUP")

func main() {
	// Read configuration from environment
	server := os.Getenv("SMB_SERVER")
	shareName := os.Getenv("SMB_SHARE")
	username := os.Getenv("SMB_USER")
	password := os.Getenv("SMB_PASSWORD")
	domain := os.Getenv("SMB_DOMAIN")
	if domain == "" {
		domain = "WORKGROUP"
	}

	if server == "" || shareName == "" || username == "" || password == "" {
		log.Fatal("Please set SMB_SERVER, SMB_SHARE, SMB_USER, and SMB_PASSWORD environment variables")
	}

	// Step 1: Connect to the SMB server
	// This establishes a TCP connection to port 445 (direct SMB over TCP)
	fmt.Printf("Connecting to %s...\n", server)
	conn, err := net.Dial("tcp", server)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Step 2: Create a dialer with authentication credentials
	// The NTLMInitiator handles NTLM v2 authentication
	d := &smb1.Dialer{
		Initiator: &smb1.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}

	// Step 3: Establish SMB session (protocol negotiation + authentication)
	fmt.Println("Authenticating...")
	session, err := d.Dial(conn)
	if err != nil {
		log.Fatalf("Failed to authenticate: %v", err)
	}
	defer session.Logoff()
	fmt.Println("Authentication successful!")

	// Step 4: Mount the share
	fmt.Printf("Mounting share %s...\n", shareName)
	share, err := session.Mount(shareName)
	if err != nil {
		log.Fatalf("Failed to mount share: %v", err)
	}
	defer share.Umount()
	fmt.Println("Share mounted successfully!")

	// Step 5: Write a test file
	testFile := "basic_usage_test.txt"
	testData := []byte("Hello from SMB1 client!\nThis is a test file.\n")

	fmt.Printf("Writing file %s...\n", testFile)
	err = share.WriteFile(testFile, testData, 0644)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}
	fmt.Printf("Wrote %d bytes\n", len(testData))

	// Step 6: Read the file back
	fmt.Printf("Reading file %s...\n", testFile)
	data, err := share.ReadFile(testFile)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}
	fmt.Printf("Read %d bytes:\n%s\n", len(data), string(data))

	// Step 7: Get file info
	fmt.Printf("Getting file info for %s...\n", testFile)
	info, err := share.Stat(testFile)
	if err != nil {
		log.Fatalf("Failed to stat file: %v", err)
	}
	fmt.Printf("File: %s\n", info.Name())
	fmt.Printf("Size: %d bytes\n", info.Size())
	fmt.Printf("Modified: %s\n", info.ModTime())
	fmt.Printf("IsDir: %v\n", info.IsDir())

	// Step 8: Clean up - remove the test file
	fmt.Printf("Removing file %s...\n", testFile)
	err = share.Remove(testFile)
	if err != nil {
		log.Fatalf("Failed to remove file: %v", err)
	}
	fmt.Println("File removed successfully!")

	fmt.Println("\nBasic usage example completed successfully!")
}
