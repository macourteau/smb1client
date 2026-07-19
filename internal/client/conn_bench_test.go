package client

import (
	"net"
	"sync"
	"testing"
)

// BenchmarkAllocateMID benchmarks MID allocation in sequential access.
func BenchmarkAllocateMID(b *testing.B) {
	// Create a connection with a mock TCP connection
	conn := NewConn(&net.TCPConn{})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		conn.mu.Lock()
		mid, err := conn.allocateMID()
		if err != nil {
			conn.mu.Unlock()
			b.Fatal(err)
		}
		// Immediately free the MID to prevent exhaustion
		// This benchmarks the allocation algorithm itself
		conn.mu.Unlock()

		// Every 100 iterations, actually use the MID briefly
		if i%100 == 0 {
			conn.mu.Lock()
			conn.pending[mid] = &pendingRequest{respCh: make(chan *response, 1), cancelled: false}
			delete(conn.pending, mid)
			conn.mu.Unlock()
		}
	}
}

// BenchmarkAllocateMIDContention benchmarks MID allocation under concurrent access.
func BenchmarkAllocateMIDContention(b *testing.B) {
	tests := []struct {
		name        string
		concurrency int
	}{
		{"2_goroutines", 2},
		{"4_goroutines", 4},
		{"8_goroutines", 8},
		{"16_goroutines", 16},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			conn := NewConn(&net.TCPConn{})

			b.ReportAllocs()
			b.ResetTimer()

			var wg sync.WaitGroup
			iterations := b.N / tt.concurrency
			if iterations == 0 {
				iterations = 1
			}

			for g := 0; g < tt.concurrency; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < iterations; i++ {
						conn.mu.Lock()
						mid, err := conn.allocateMID()
						if err == nil {
							conn.pending[mid] = &pendingRequest{respCh: make(chan *response, 1), cancelled: false}
							// Simulate cleanup
							if i%50 == 0 {
								for k := range conn.pending {
									delete(conn.pending, k)
									break
								}
							}
						}
						conn.mu.Unlock()
					}
				}()
			}

			wg.Wait()
		})
	}
}

// BenchmarkAllocateMIDExhaustion benchmarks MID allocation when approaching exhaustion.
func BenchmarkAllocateMIDExhaustion(b *testing.B) {
	tests := []struct {
		name         string
		pendingCount int
	}{
		{"empty", 0},
		{"10_percent_full", 6553},  // ~10% of 65536
		{"50_percent_full", 32768}, // 50% of 65536
		{"90_percent_full", 58982}, // ~90% of 65536
		{"99_percent_full", 64881}, // ~99% of 65536
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			conn := NewConn(&net.TCPConn{})

			// Pre-fill pending map
			conn.mu.Lock()
			for i := 0; i < tt.pendingCount; i++ {
				conn.pending[uint16(i)] = &pendingRequest{respCh: make(chan *response, 1), cancelled: false}
			}
			conn.nextMID = uint16(tt.pendingCount)
			conn.mu.Unlock()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				conn.mu.Lock()
				mid, err := conn.allocateMID()
				if err == nil {
					// Use the MID and immediately free it to maintain constant load
					delete(conn.pending, mid)
				}
				conn.mu.Unlock()
			}
		})
	}
}

// BenchmarkMIDCleanup benchmarks the cleanup of pending MIDs.
func BenchmarkMIDCleanup(b *testing.B) {
	tests := []struct {
		name         string
		pendingCount int
	}{
		{"10_pending", 10},
		{"100_pending", 100},
		{"1000_pending", 1000},
		{"10000_pending", 10000},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				conn := NewConn(&net.TCPConn{})

				// Pre-fill pending map
				for j := 0; j < tt.pendingCount; j++ {
					conn.pending[uint16(j)] = &pendingRequest{respCh: make(chan *response, 1), cancelled: false}
				}

				b.StartTimer()
				// Simulate cleanup by deleting all pending
				for k := range conn.pending {
					delete(conn.pending, k)
				}
			}
		})
	}
}
