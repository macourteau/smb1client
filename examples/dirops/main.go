package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/macourteau/smb1client"
)

// This example demonstrates directory operations:
// - Creating directories
// - Listing directory contents
// - Creating nested directories
// - Removing directories
//
// To run this example:
//   go run examples/directory_operations.go
//
// Environment variables:
//   SMB_SERVER   - SMB server address
//   SMB_SHARE    - Share name
//   SMB_USER     - Username
//   SMB_PASSWORD - Password
//   SMB_DOMAIN   - Domain (optional, defaults to "WORKGROUP")

func main() {
	// Setup connection (same as basic_usage.go)
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

	conn, err := net.Dial("tcp", server)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	d := &smb1.Dialer{
		Initiator: &smb1.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		log.Fatalf("Failed to authenticate: %v", err)
	}
	defer session.Logoff()

	share, err := session.Mount(shareName)
	if err != nil {
		log.Fatalf("Failed to mount share: %v", err)
	}
	defer share.Umount()

	fmt.Println("Directory Operations Example")
	fmt.Println("============================")

	// Example 1: Create a simple directory
	testDir := "test_directory"
	fmt.Printf("Creating directory: %s\n", testDir)
	err = share.Mkdir(testDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}
	fmt.Println("Directory created successfully!")

	// Example 2: Create nested directories
	nestedDir := "parent/child/grandchild"
	fmt.Printf("\nCreating nested directories: %s\n", nestedDir)
	err = share.MkdirAll(nestedDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create nested directories: %v", err)
	}
	fmt.Println("Nested directories created successfully!")

	// Example 3: Create some test files in the directory
	fmt.Println("\nCreating test files in directory...")
	testFiles := []string{
		testDir + "/file1.txt",
		testDir + "/file2.txt",
		testDir + "/file3.txt",
	}

	for _, filename := range testFiles {
		content := []byte(fmt.Sprintf("Content of %s\n", filename))
		err = share.WriteFile(filename, content, 0644)
		if err != nil {
			log.Fatalf("Failed to create file %s: %v", filename, err)
		}
		fmt.Printf("  Created: %s\n", filename)
	}

	// Example 4: List directory contents
	fmt.Printf("\nListing contents of %s:\n", testDir)
	files, err := share.ReadDir(testDir)
	if err != nil {
		log.Fatalf("Failed to read directory: %v", err)
	}

	fmt.Printf("Found %d items:\n", len(files))
	for _, f := range files {
		if f.IsDir() {
			fmt.Printf("  [DIR]  %s\n", f.Name())
		} else {
			fmt.Printf("  [FILE] %-20s  %8d bytes  %s\n",
				f.Name(), f.Size(), f.ModTime().Format("2006-01-02 15:04:05"))
		}
	}

	// Example 5: List root directory
	fmt.Println("\nListing root directory (first 10 items):")
	rootFiles, err := share.ReadDir("")
	if err != nil {
		log.Fatalf("Failed to read root directory: %v", err)
	}

	count := 0
	for _, f := range rootFiles {
		if count >= 10 {
			break
		}
		if f.IsDir() {
			fmt.Printf("  [DIR]  %s\n", f.Name())
		} else {
			fmt.Printf("  [FILE] %s\n", f.Name())
		}
		count++
	}
	if len(rootFiles) > 10 {
		fmt.Printf("  ... and %d more items\n", len(rootFiles)-10)
	}

	// Example 6: Walk directory tree (simple implementation)
	fmt.Println("\nWalking directory tree:")
	var walkDir func(string, int) error
	walkDir = func(path string, depth int) error {
		indent := ""
		for i := 0; i < depth; i++ {
			indent += "  "
		}

		entries, err := share.ReadDir(path)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			entryPath := path
			if entryPath != "" {
				entryPath += "\\"
			}
			entryPath += entry.Name()

			if entry.IsDir() {
				fmt.Printf("%s[DIR] %s\n", indent, entry.Name())
				if depth < 2 { // Limit depth to avoid too much output
					walkDir(entryPath, depth+1)
				}
			} else {
				fmt.Printf("%s[FILE] %s (%d bytes)\n", indent, entry.Name(), entry.Size())
			}
		}
		return nil
	}

	err = walkDir(testDir, 0)
	if err != nil {
		log.Printf("Warning: failed to walk directory: %v", err)
	}

	// Cleanup
	fmt.Println("\nCleaning up...")

	// Remove test files
	for _, filename := range testFiles {
		err = share.Remove(filename)
		if err != nil {
			log.Printf("Warning: failed to remove %s: %v", filename, err)
		}
	}

	// Remove directories
	err = share.Remove(testDir)
	if err != nil {
		log.Printf("Warning: failed to remove %s: %v", testDir, err)
	}

	// Note: RemoveAll is not implemented, so we can't easily clean up nested directories
	fmt.Println("Note: Nested directories were not cleaned up (RemoveAll not implemented)")

	fmt.Println("\nDirectory operations example completed!")
}
