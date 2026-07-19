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

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <server:port> <username> <password>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s 192.168.1.100:445 testuser password123\n", os.Args[0])
		os.Exit(1)
	}

	server := os.Args[1]
	username := os.Args[2]
	password := os.Args[3]

	// Connect with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Printf("Connecting to %s...\n", server)

	// Establish TCP connection
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Create SMB1 dialer
	dialer := &smb1.Dialer{
		Initiator: &smb1.NTLMInitiator{
			User:     username,
			Password: password,
		},
	}

	// Perform SMB1 negotiation and authentication
	session, err := dialer.Dial(conn)
	if err != nil {
		log.Fatalf("SMB1 session setup failed: %v", err)
	}
	defer session.Logoff()

	fmt.Println("Connected successfully!")
	fmt.Println()

	// List shares using RAP NetShareEnum
	fmt.Println("Enumerating shares...")
	shares, err := session.WithContext(ctx).ListSharenames()
	if err != nil {
		log.Fatalf("Failed to list shares: %v", err)
	}

	// Display results
	fmt.Printf("\nFound %d shares:\n", len(shares))
	fmt.Println("================")
	for i, share := range shares {
		fmt.Printf("%2d. %s\n", i+1, share)
	}

	// Try to mount one of the non-administrative shares
	if len(shares) > 0 {
		// Find first non-hidden, non-IPC share
		var regularShare string
		for _, share := range shares {
			// Skip IPC$, ADMIN$, C$, etc.
			if share == "IPC$" || share[len(share)-1] == '$' {
				continue
			}
			regularShare = share
			break
		}

		if regularShare != "" {
			fmt.Printf("\nAttempting to mount share: %s\n", regularShare)
			mountedShare, err := session.WithContext(ctx).Mount(regularShare)
			if err != nil {
				log.Printf("Warning: failed to mount %s: %v", regularShare, err)
			} else {
				defer mountedShare.Umount()
				fmt.Printf("Successfully mounted %s!\n", regularShare)

				// List root directory contents as a test
				entries, err := mountedShare.ReadDir("")
				if err != nil {
					log.Printf("Warning: failed to read directory: %v", err)
				} else {
					fmt.Printf("\nRoot directory contains %d entries:\n", len(entries))
					for i, entry := range entries {
						if i >= 5 {
							fmt.Printf("... and %d more\n", len(entries)-5)
							break
						}
						fmt.Printf("  - %s\n", entry.Name())
					}
				}
			}
		}
	}
}
