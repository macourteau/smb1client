package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/macourteau/smb1client"
)

// This example demonstrates various file operations:
// - Opening files with different modes
// - Reading and writing at specific offsets
// - Seeking within files
// - Copying files
// - Checking file existence
// - Getting file information
//
// To run this example:
//   go run examples/file_operations.go
//
// Environment variables:
//   SMB_SERVER   - SMB server address
//   SMB_SHARE    - Share name
//   SMB_USER     - Username
//   SMB_PASSWORD - Password
//   SMB_DOMAIN   - Domain (optional, defaults to "WORKGROUP")

func main() {
	// Setup connection
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

	fmt.Println("File Operations Example")
	fmt.Println("=======================")

	// Example 1: Check if file exists
	testFile := "test_operations.txt"
	fmt.Printf("Checking if %s exists...\n", testFile)
	_, err = share.Stat(testFile)
	if os.IsNotExist(err) {
		fmt.Println("File does not exist (expected)")
	} else if err != nil {
		log.Fatalf("Error checking file: %v", err)
	} else {
		fmt.Println("File exists, removing it first...")
		share.Remove(testFile)
	}

	// Example 2: Create file with OpenFile
	fmt.Printf("\nCreating file %s with OpenFile...\n", testFile)
	f, err := share.OpenFile(testFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}

	// Write some initial content
	initialData := []byte("Line 1: Initial content\n")
	n, err := f.Write(initialData)
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}
	fmt.Printf("Wrote %d bytes\n", n)

	// Close the file
	err = f.Close()
	if err != nil {
		log.Fatalf("Failed to close file: %v", err)
	}

	// Example 3: Append to file
	fmt.Println("\nAppending to file...")
	f, err = share.OpenFile(testFile, os.O_RDWR, 0644)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	// Seek to end (would use SeekEnd but it's not supported yet)
	// Instead, we'll use WriteAt with known offset
	appendData := []byte("Line 2: Appended content\n")
	n, err = f.WriteAt(appendData, int64(len(initialData)))
	if err != nil {
		log.Fatalf("Failed to append: %v", err)
	}
	fmt.Printf("Appended %d bytes at offset %d\n", n, len(initialData))
	f.Close()

	// Example 4: Read file in chunks
	fmt.Println("\nReading file in chunks...")
	f, err = share.Open(testFile)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	buffer := make([]byte, 16) // Small buffer to demonstrate chunked reading
	totalRead := 0
	for {
		n, err := f.Read(buffer)
		if n > 0 {
			fmt.Printf("Chunk %d: %q\n", totalRead/16+1, string(buffer[:n]))
			totalRead += n
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Read error: %v", err)
		}
	}
	fmt.Printf("Total bytes read: %d\n", totalRead)
	f.Close()

	// Example 5: Read file at specific offsets
	fmt.Println("\nReading at specific offsets...")
	f, err = share.Open(testFile)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	// Read from offset 0
	buf := make([]byte, 10)
	n, err = f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		log.Fatalf("ReadAt error: %v", err)
	}
	fmt.Printf("Bytes 0-9: %q\n", string(buf[:n]))

	// Read from offset 10
	n, err = f.ReadAt(buf, 10)
	if err != nil && err != io.EOF {
		log.Fatalf("ReadAt error: %v", err)
	}
	fmt.Printf("Bytes 10-19: %q\n", string(buf[:n]))
	f.Close()

	// Example 6: Seek within file
	fmt.Println("\nSeeking within file...")
	f, err = share.Open(testFile)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	// Seek to position 7
	offset, err := f.Seek(7, io.SeekStart)
	if err != nil {
		log.Fatalf("Seek error: %v", err)
	}
	fmt.Printf("Seeked to offset: %d\n", offset)

	// Read from current position
	buf = make([]byte, 20)
	n, err = f.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatalf("Read error: %v", err)
	}
	fmt.Printf("Read from offset 7: %q\n", string(buf[:n]))

	// Seek forward from current position
	offset, err = f.Seek(10, io.SeekCurrent)
	if err != nil {
		log.Fatalf("Seek error: %v", err)
	}
	fmt.Printf("Seeked forward by 10, now at: %d\n", offset)
	f.Close()

	// Example 7: Copy file
	fmt.Println("\nCopying file...")
	srcFile := testFile
	dstFile := "test_operations_copy.txt"

	// Read source
	srcData, err := share.ReadFile(srcFile)
	if err != nil {
		log.Fatalf("Failed to read source: %v", err)
	}

	// Write destination
	err = share.WriteFile(dstFile, srcData, 0644)
	if err != nil {
		log.Fatalf("Failed to write destination: %v", err)
	}
	fmt.Printf("Copied %s to %s (%d bytes)\n", srcFile, dstFile, len(srcData))

	// Verify copy
	dstInfo, err := share.Stat(dstFile)
	if err != nil {
		log.Fatalf("Failed to stat destination: %v", err)
	}
	fmt.Printf("Destination file size: %d bytes\n", dstInfo.Size())

	// Example 8: Rename file
	fmt.Println("\nRenaming file...")
	newName := "test_operations_renamed.txt"
	err = share.Rename(dstFile, newName)
	if err != nil {
		log.Fatalf("Failed to rename: %v", err)
	}
	fmt.Printf("Renamed %s to %s\n", dstFile, newName)

	// Example 9: Get detailed file information
	fmt.Println("\nGetting detailed file information...")
	info, err := share.Stat(testFile)
	if err != nil {
		log.Fatalf("Failed to stat file: %v", err)
	}
	fmt.Printf("  Name:     %s\n", info.Name())
	fmt.Printf("  Size:     %d bytes\n", info.Size())
	fmt.Printf("  Mode:     %v\n", info.Mode())
	fmt.Printf("  ModTime:  %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
	fmt.Printf("  IsDir:    %v\n", info.IsDir())

	// Cleanup
	fmt.Println("\nCleaning up...")
	share.Remove(testFile)
	share.Remove(newName)
	fmt.Println("Cleanup complete!")

	fmt.Println("\nFile operations example completed!")
}
