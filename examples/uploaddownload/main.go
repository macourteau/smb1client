package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/macourteau/smb1client"
)

// This example demonstrates uploading and downloading files between
// the local filesystem and an SMB share.
//
// To run this example:
//   go run examples/upload_download.go
//
// Environment variables:
//   SMB_SERVER   - SMB server address
//   SMB_SHARE    - Share name
//   SMB_USER     - Username
//   SMB_PASSWORD - Password
//   SMB_DOMAIN   - Domain (optional, defaults to "WORKGROUP")

func main() {
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

	fmt.Println("Upload/Download Example")
	fmt.Println("=======================")

	// Example 1: Upload a file from local filesystem
	fmt.Println("Example 1: Upload file")
	fmt.Println("----------------------")

	// Create a temporary local file
	localFile := "local_test_file.txt"
	localContent := []byte("This is a test file from the local filesystem.\nIt will be uploaded to the SMB share.\n")
	err = os.WriteFile(localFile, localContent, 0644)
	if err != nil {
		log.Fatalf("Failed to create local file: %v", err)
	}
	defer os.Remove(localFile)

	fmt.Printf("Created local file: %s (%d bytes)\n", localFile, len(localContent))

	// Upload the file
	remoteFile := "uploaded_test_file.txt"
	err = uploadFile(share, localFile, remoteFile)
	if err != nil {
		log.Fatalf("Failed to upload file: %v", err)
	}
	fmt.Printf("Uploaded to: %s\n\n", remoteFile)

	// Example 2: Download a file to local filesystem
	fmt.Println("Example 2: Download file")
	fmt.Println("------------------------")

	downloadedFile := "downloaded_test_file.txt"
	err = downloadFile(share, remoteFile, downloadedFile)
	if err != nil {
		log.Fatalf("Failed to download file: %v", err)
	}
	defer os.Remove(downloadedFile)

	fmt.Printf("Downloaded to: %s\n", downloadedFile)

	// Verify downloaded content
	downloadedContent, err := os.ReadFile(downloadedFile)
	if err != nil {
		log.Fatalf("Failed to read downloaded file: %v", err)
	}
	fmt.Printf("Downloaded content (%d bytes):\n%s\n", len(downloadedContent), string(downloadedContent))

	// Example 3: Upload multiple files
	fmt.Println("Example 3: Upload multiple files")
	fmt.Println("---------------------------------")

	// Create multiple test files
	localFiles := []string{"test1.txt", "test2.txt", "test3.txt"}
	for i, filename := range localFiles {
		content := []byte(fmt.Sprintf("Content of test file %d\n", i+1))
		err = os.WriteFile(filename, content, 0644)
		if err != nil {
			log.Fatalf("Failed to create %s: %v", filename, err)
		}
		defer os.Remove(filename)
	}

	// Upload all files
	fmt.Printf("Uploading %d files...\n", len(localFiles))
	for _, filename := range localFiles {
		remotePath := "uploaded_" + filename
		err = uploadFile(share, filename, remotePath)
		if err != nil {
			log.Printf("Failed to upload %s: %v", filename, err)
			continue
		}
		fmt.Printf("  Uploaded: %s -> %s\n", filename, remotePath)
	}
	fmt.Println()

	// Example 4: Download multiple files
	fmt.Println("Example 4: Download multiple files")
	fmt.Println("-----------------------------------")

	// Create a directory for downloads
	downloadDir := "downloads"
	err = os.MkdirAll(downloadDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create download directory: %v", err)
	}
	defer os.RemoveAll(downloadDir)

	fmt.Printf("Downloading files to %s/...\n", downloadDir)
	for _, filename := range localFiles {
		remotePath := "uploaded_" + filename
		localPath := filepath.Join(downloadDir, filename)

		err = downloadFile(share, remotePath, localPath)
		if err != nil {
			log.Printf("Failed to download %s: %v", remotePath, err)
			continue
		}
		fmt.Printf("  Downloaded: %s -> %s\n", remotePath, localPath)
	}
	fmt.Println()

	// Example 5: Upload with progress (large file simulation)
	fmt.Println("Example 5: Upload with progress")
	fmt.Println("--------------------------------")

	largeFile := "large_test_file.bin"
	largeFileSize := 1024 * 1024 // 1 MB
	err = createLargeFile(largeFile, largeFileSize)
	if err != nil {
		log.Fatalf("Failed to create large file: %v", err)
	}
	defer os.Remove(largeFile)

	fmt.Printf("Created large file: %s (%d bytes)\n", largeFile, largeFileSize)

	remoteLargeFile := "uploaded_large_file.bin"
	err = uploadFileWithProgress(share, largeFile, remoteLargeFile)
	if err != nil {
		log.Fatalf("Failed to upload large file: %v", err)
	}
	fmt.Println()

	// Cleanup
	fmt.Println("Cleaning up remote files...")
	share.Remove(remoteFile)
	for _, filename := range localFiles {
		share.Remove("uploaded_" + filename)
	}
	share.Remove(remoteLargeFile)
	fmt.Println("Cleanup complete!")

	fmt.Println("\nUpload/download example completed!")
}

// uploadFile uploads a file from the local filesystem to the SMB share
func uploadFile(share *smb1.Share, localPath, remotePath string) error {
	// Read local file
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read local file: %w", err)
	}

	// Write to remote file
	err = share.WriteFile(remotePath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write remote file: %w", err)
	}

	return nil
}

// downloadFile downloads a file from the SMB share to the local filesystem
func downloadFile(share *smb1.Share, remotePath, localPath string) error {
	// Read remote file
	data, err := share.ReadFile(remotePath)
	if err != nil {
		return fmt.Errorf("failed to read remote file: %w", err)
	}

	// Write to local file
	err = os.WriteFile(localPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write local file: %w", err)
	}

	return nil
}

// uploadFileWithProgress uploads a file with progress reporting
func uploadFileWithProgress(share *smb1.Share, localPath, remotePath string) error {
	// Open local file
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer localFile.Close()

	// Get file size
	stat, err := localFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat local file: %w", err)
	}
	totalSize := stat.Size()

	// Open remote file
	remoteFile, err := share.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer remoteFile.Close()

	// Copy with progress
	buffer := make([]byte, 32*1024) // 32 KB chunks
	var bytesWritten int64

	fmt.Println("Upload progress:")
	for {
		n, err := localFile.Read(buffer)
		if n > 0 {
			_, writeErr := remoteFile.Write(buffer[:n])
			if writeErr != nil {
				return fmt.Errorf("failed to write to remote file: %w", writeErr)
			}
			bytesWritten += int64(n)

			// Show progress
			progress := float64(bytesWritten) / float64(totalSize) * 100
			fmt.Printf("\r  %.1f%% (%d / %d bytes)", progress, bytesWritten, totalSize)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read from local file: %w", err)
		}
	}
	fmt.Println(" - Complete!")

	return nil
}

// createLargeFile creates a test file of the specified size
func createLargeFile(filename string, size int) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write in chunks
	buffer := make([]byte, 32*1024)
	for i := range buffer {
		buffer[i] = byte(i % 256)
	}

	remaining := size
	for remaining > 0 {
		writeSize := len(buffer)
		if remaining < writeSize {
			writeSize = remaining
		}

		_, err := file.Write(buffer[:writeSize])
		if err != nil {
			return err
		}

		remaining -= writeSize
	}

	return nil
}
