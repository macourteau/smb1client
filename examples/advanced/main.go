package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/macourteau/smb1client"
)

// This example demonstrates advanced features:
// - Context usage for timeouts and cancellation
// - Error handling with type checking
// - Concurrent operations
// - Custom logging with context
//
// To run this example:
//   go run examples/advanced.go
//
// Environment variables:
//   SMB_SERVER   - SMB server address
//   SMB_SHARE    - Share name
//   SMB_USER     - Username
//   SMB_PASSWORD - Password
//   SMB_DOMAIN   - Domain (optional, defaults to "WORKGROUP")

// customLogger is a simple logger implementation for the example
type customLogger struct{}

func (l *customLogger) Debug(format string, v ...interface{}) {
	log.Printf("[DEBUG] "+format, v...)
}

func (l *customLogger) Info(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

func (l *customLogger) Warn(format string, v ...interface{}) {
	log.Printf("[WARN] "+format, v...)
}

func (l *customLogger) Error(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

func main() {
	// Create a context with a logger for debug logging
	ctx := smb1.WithLogger(context.Background(), &customLogger{})

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

	fmt.Println("Advanced Features Example")
	fmt.Println("=========================")

	// Example 1: Context with timeout for connection
	fmt.Println("Example 1: Connection with timeout")
	fmt.Println("-----------------------------------")

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

	// Use context with timeout for authentication (and logging)
	authCtx, authCancel := context.WithTimeout(ctx, 30*time.Second)
	defer authCancel()

	fmt.Println("Authenticating with 30-second timeout...")
	session, err := d.DialContext(authCtx, conn)
	if err != nil {
		log.Fatalf("Failed to authenticate: %v", err)
	}
	defer session.Logoff()
	fmt.Println("Authentication successful!")

	// Example 2: Context for individual operations
	fmt.Println("Example 2: Operations with timeout")
	fmt.Println("-----------------------------------")

	// Create a session with 10-second timeout for all operations (preserving logger from parent context)
	opCtx, opCancel := context.WithTimeout(ctx, 10*time.Second)
	defer opCancel()

	sessionWithTimeout := session.WithContext(opCtx)
	share, err := sessionWithTimeout.Mount(shareName)
	if err != nil {
		log.Fatalf("Failed to mount share: %v", err)
	}
	defer share.Umount()
	fmt.Println("Share mounted with timeout context")

	// Example 3: Error handling with type checking
	fmt.Println("Example 3: Detailed error handling")
	fmt.Println("-----------------------------------")

	testFile := "nonexistent_file.txt"
	fmt.Printf("Attempting to open non-existent file: %s\n", testFile)

	_, err = share.Open(testFile)
	if err != nil {
		fmt.Printf("Error occurred: %v\n", err)

		// Check specific error types
		if smb1.IsNotFoundError(err) {
			fmt.Println("  -> Error type: File not found")
		} else if smb1.IsPermissionError(err) {
			fmt.Println("  -> Error type: Permission denied")
		} else if smb1.IsAuthError(err) {
			fmt.Println("  -> Error type: Authentication error")
		} else if smb1.IsNetworkError(err) {
			fmt.Println("  -> Error type: Network error")
		} else {
			fmt.Println("  -> Error type: Other")
		}

		// Check if error is temporary and can be retried
		if smb1.IsTemporary(err) {
			fmt.Println("  -> This error is temporary and can be retried")
		} else {
			fmt.Println("  -> This error is permanent")
		}

		// Access underlying os.PathError if available
		if pathErr, ok := err.(*os.PathError); ok {
			fmt.Printf("  -> Operation: %s\n", pathErr.Op)
			fmt.Printf("  -> Path: %s\n", pathErr.Path)
			fmt.Printf("  -> Underlying error: %v\n", pathErr.Err)
		}
	}
	fmt.Println()

	// Example 4: Concurrent file operations
	fmt.Println("Example 4: Concurrent operations")
	fmt.Println("---------------------------------")

	// Create multiple files concurrently
	fileCount := 5
	errChan := make(chan error, fileCount)

	fmt.Printf("Creating %d files concurrently...\n", fileCount)
	for i := 0; i < fileCount; i++ {
		go func(index int) {
			filename := fmt.Sprintf("concurrent_test_%d.txt", index)
			content := []byte(fmt.Sprintf("Content of file %d\n", index))

			err := share.WriteFile(filename, content, 0644)
			errChan <- err
		}(i)
	}

	// Wait for all operations to complete
	successCount := 0
	for i := 0; i < fileCount; i++ {
		err := <-errChan
		if err == nil {
			successCount++
		} else {
			fmt.Printf("  Error creating file: %v\n", err)
		}
	}
	fmt.Printf("Successfully created %d/%d files\n\n", successCount, fileCount)

	// Example 5: Context cancellation
	fmt.Println("Example 5: Context cancellation")
	fmt.Println("-------------------------------")

	// Create a context that we'll cancel (preserving logger from parent context)
	cancelCtx, cancel := context.WithCancel(ctx)
	sessionWithCancel := session.WithContext(cancelCtx)
	shareWithCancel, err := sessionWithCancel.Mount(shareName)
	if err != nil {
		log.Fatalf("Failed to mount share: %v", err)
	}

	fmt.Println("Starting operation that will be cancelled...")

	// Start a long operation in a goroutine
	done := make(chan error)
	go func() {
		// Simulate a long operation by creating many files
		for i := 0; i < 100; i++ {
			filename := fmt.Sprintf("cancel_test_%d.txt", i)
			err := shareWithCancel.WriteFile(filename, []byte("test"), 0644)
			if err != nil {
				done <- err
				return
			}
			time.Sleep(50 * time.Millisecond) // Slow down to make cancellation visible
		}
		done <- nil
	}()

	// Cancel after a short time
	time.Sleep(200 * time.Millisecond)
	fmt.Println("Cancelling context...")
	cancel()

	// Wait for operation to complete or be cancelled
	err = <-done
	if err != nil {
		fmt.Printf("Operation was cancelled or failed: %v\n", err)
	} else {
		fmt.Println("Operation completed before cancellation")
	}

	shareWithCancel.Umount()
	fmt.Println()

	// Cleanup
	fmt.Println("Cleaning up...")
	for i := 0; i < fileCount; i++ {
		filename := fmt.Sprintf("concurrent_test_%d.txt", i)
		share.Remove(filename)
	}
	fmt.Println("Cleanup complete!")

	fmt.Println("\nAdvanced features example completed!")
}
