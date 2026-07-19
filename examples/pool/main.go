package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/macourteau/smb1client"
)

// This example demonstrates using the connection pool for improved performance
// when performing many short-lived operations.
//
// The connection pool maintains a set of reusable SMB connections, avoiding
// the overhead of repeatedly establishing TCP connections and performing
// NTLM authentication for each operation.
//
// To run this example:
//   go run examples/pool/main.go
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

	// Create a dialer with authentication credentials
	dialer := &smb1.Dialer{
		Initiator: &smb1.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}

	// Create a connection pool with custom configuration
	config := &smb1.PoolConfig{
		MaxIdle:     5,                // Keep up to 5 idle connections
		MaxActive:   10,               // Allow up to 10 total connections
		IdleTimeout: 5 * time.Minute,  // Close idle connections after 5 minutes
		WaitTimeout: 30 * time.Second, // Wait up to 30 seconds for a connection
	}

	fmt.Println("Creating connection pool...")
	pool := smb1.NewConnectionPool(server, dialer, config)
	defer pool.Close()

	// Example 1: Simple get and use pattern
	fmt.Println("\n=== Example 1: Simple Usage ===")
	if err := simpleExample(pool, shareName); err != nil {
		log.Printf("Simple example failed: %v", err)
	}

	// Example 2: Concurrent operations
	fmt.Println("\n=== Example 2: Concurrent Operations ===")
	if err := concurrentExample(pool, shareName); err != nil {
		log.Printf("Concurrent example failed: %v", err)
	}

	// Example 3: Pool statistics
	fmt.Println("\n=== Example 3: Pool Statistics ===")
	stats := pool.Stats()
	fmt.Printf("Pool Stats:\n")
	fmt.Printf("  Idle connections: %d\n", stats.Idle)
	fmt.Printf("  Active connections: %d\n", stats.Active)
	fmt.Printf("  Closed: %v\n", stats.Closed)

	// Example 4: Pool with health checks
	fmt.Println("\n=== Example 4: Pool with Health Checks ===")
	if err := healthCheckExample(server, dialer, shareName); err != nil {
		log.Printf("Health check example failed: %v", err)
	}

	fmt.Println("\nConnection pool example completed successfully!")
}

// simpleExample demonstrates basic pool usage
func simpleExample(pool *smb1.ConnectionPool, shareName string) error {
	ctx := context.Background()

	// Get a connection from the pool
	conn, err := pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}
	// Return connection to pool when done
	defer conn.Close()

	// Use the connection to access the share
	share, err := conn.Mount(shareName)
	if err != nil {
		return fmt.Errorf("failed to mount share: %w", err)
	}
	defer share.Umount()

	// Perform file operations
	testFile := "pool_test_simple.txt"
	testData := []byte("Hello from connection pool!\n")

	fmt.Printf("Writing file %s...\n", testFile)
	if err := share.WriteFile(testFile, testData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Reading file %s...\n", testFile)
	data, err := share.ReadFile(testFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	fmt.Printf("Read: %s", string(data))

	// Clean up
	fmt.Printf("Removing file %s...\n", testFile)
	if err := share.Remove(testFile); err != nil {
		return fmt.Errorf("failed to remove file: %w", err)
	}

	return nil
}

// concurrentExample demonstrates using the pool from multiple goroutines
func concurrentExample(pool *smb1.ConnectionPool, shareName string) error {
	ctx := context.Background()
	numWorkers := 5
	opsPerWorker := 3

	var wg sync.WaitGroup
	errors := make(chan error, numWorkers*opsPerWorker)

	fmt.Printf("Starting %d concurrent workers, each performing %d operations...\n", numWorkers, opsPerWorker)

	startTime := time.Now()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for op := 0; op < opsPerWorker; op++ {
				// Get a connection from the pool
				conn, err := pool.Get(ctx)
				if err != nil {
					errors <- fmt.Errorf("worker %d op %d: get failed: %w", workerID, op, err)
					continue
				}

				// Perform operation
				err = performOperation(conn, shareName, workerID, op)

				// Return connection to pool
				conn.Close()

				if err != nil {
					errors <- fmt.Errorf("worker %d op %d: %w", workerID, op, err)
				} else {
					fmt.Printf("Worker %d completed operation %d\n", workerID, op)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	duration := time.Since(startTime)
	fmt.Printf("All workers completed in %v\n", duration)

	// Check for errors
	errorCount := 0
	for err := range errors {
		log.Printf("Error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		return fmt.Errorf("encountered %d errors during concurrent operations", errorCount)
	}

	return nil
}

// performOperation performs a single operation using a pooled connection
func performOperation(conn *smb1.PooledSession, shareName string, workerID, opID int) error {
	share, err := conn.Mount(shareName)
	if err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}
	defer share.Umount()

	// Create a unique file for this operation
	filename := fmt.Sprintf("pool_test_worker%d_op%d.txt", workerID, opID)
	content := []byte(fmt.Sprintf("Worker %d, Operation %d\n", workerID, opID))

	// Write file
	if err := share.WriteFile(filename, content, 0644); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	// Read it back
	data, err := share.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	if string(data) != string(content) {
		return fmt.Errorf("data mismatch")
	}

	// Clean up
	if err := share.Remove(filename); err != nil {
		return fmt.Errorf("remove failed: %w", err)
	}

	return nil
}

// healthCheckExample demonstrates using health checks to verify connection validity
func healthCheckExample(server string, dialer *smb1.Dialer, shareName string) error {
	fmt.Println("Creating pool with health check enabled...")

	var healthCheckCount int
	var mu sync.Mutex

	// Create a pool with a health check function
	config := &smb1.PoolConfig{
		MaxIdle:     3,
		MaxActive:   5,
		IdleTimeout: 5 * time.Minute,
		WaitTimeout: 30 * time.Second,
		// HealthCheck verifies the connection is still alive before reuse
		HealthCheck: func(s *smb1.Session) (bool, error) {
			mu.Lock()
			healthCheckCount++
			checkNum := healthCheckCount
			mu.Unlock()

			fmt.Printf("  Health check %d: verifying connection...\n", checkNum)

			// Try to list shares as a simple health check
			// This sends an actual SMB command to verify the connection works
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			_, err := s.WithContext(ctx).ListSharenames()
			if err != nil {
				fmt.Printf("  Health check %d: FAILED (%v)\n", checkNum, err)
				return false, err
			}

			fmt.Printf("  Health check %d: OK\n", checkNum)
			return true, nil
		},
	}

	pool := smb1.NewConnectionPool(server, dialer, config)
	defer pool.Close()

	ctx := context.Background()

	// Get a connection and use it
	fmt.Println("\nGetting first connection...")
	conn1, err := pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get first connection: %w", err)
	}

	share1, err := conn1.Mount(shareName)
	if err != nil {
		conn1.Close()
		return fmt.Errorf("failed to mount share: %w", err)
	}
	share1.Umount()

	// Return to pool
	fmt.Println("Returning connection to pool...")
	conn1.Close()

	// Get another connection - should reuse and run health check
	fmt.Println("\nGetting second connection (should reuse with health check)...")
	conn2, err := pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get second connection: %w", err)
	}

	share2, err := conn2.Mount(shareName)
	if err != nil {
		conn2.Close()
		return fmt.Errorf("failed to mount share: %w", err)
	}
	share2.Umount()

	conn2.Close()

	mu.Lock()
	totalChecks := healthCheckCount
	mu.Unlock()

	fmt.Printf("\nHealth check summary: %d checks performed\n", totalChecks)
	fmt.Println("Health checks help ensure pooled connections are valid before reuse")

	return nil
}
