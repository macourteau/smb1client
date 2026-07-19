package client

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/macourteau/smb1client/internal/smb1"
)

// TestSynctestExample demonstrates proper usage of synctest for deterministic
// concurrency testing. This test shows how synctest eliminates timing-based
// flakiness and makes tests run instantly instead of waiting for real time.
//
// Key benefits of synctest:
// 1. Tests run in zero real time (simulated time advances instantly)
// 2. Tests are deterministic (no race conditions or timing dependencies)
// 3. No need for sleep-based synchronization
// 4. Context timeouts work correctly without waiting
//
// Example: Without synctest, this test would take 1+ seconds. With synctest,
// it completes instantly.
//
// synctest.Test creates an isolated "bubble" with a fake clock. All goroutines
// and time operations within the bubble use simulated time. t.Run cannot be
// called inside a bubble, so each subtest opens its own.
func TestSynctestExample(t *testing.T) {
	// Test 1: Demonstrate instant time advancement
	t.Run("InstantTimeAdvancement", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()

			// This sleep happens instantly in synctest
			time.Sleep(100 * time.Millisecond)

			elapsed := time.Since(start)
			// In synctest, simulated time advances but real time does not
			// So elapsed will be near zero in real time, but the sleep still works
			if elapsed > 50*time.Millisecond {
				t.Logf("Note: This test runs instantly with synctest (elapsed: %v)", elapsed)
			}
		})
	})

	// Test 2: Demonstrate deterministic goroutine synchronization
	t.Run("DeterministicGoroutines", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var wg sync.WaitGroup
			counter := 0
			mu := sync.Mutex{}

			// Launch multiple goroutines with delays
			for i := 0; i < 5; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					// Each goroutine waits a different amount
					time.Sleep(time.Duration(id*10) * time.Millisecond)
					mu.Lock()
					counter++
					mu.Unlock()
				}(i)
			}

			// Wait for all goroutines - happens instantly
			wg.Wait()

			if counter != 5 {
				t.Errorf("Expected counter = 5, got %d", counter)
			}
		})
	})

	// Test 3: Demonstrate time.After with select
	t.Run("TimeAfterWithSelect", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			done := make(chan struct{})

			go func() {
				// Simulate some work
				time.Sleep(50 * time.Millisecond)
				close(done)
			}()

			// Use time.After for timeout - works correctly with synctest
			select {
			case <-done:
				// Success - goroutine completed
			case <-time.After(1 * time.Second):
				t.Fatal("Operation timed out")
			}
		})
	})

	// Test 4: Demonstrate context with timeout
	t.Run("ContextWithTimeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			mockTCP := newMockConn()
			c := NewConn(mockTCP)
			defer c.Close()

			// Start receive goroutine - it runs in the synctest bubble
			go c.Receive()

			// Create context with 500ms timeout
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			// Send request with context
			var err error
			done := make(chan struct{})

			go func() {
				header := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
				params := []byte{0x00, 0x00}
				data := []byte("request")

				_, err = c.sendRecv(header, params, data, ctx)
				close(done)
			}()

			// Wait a bit for request to be sent (instant in synctest)
			time.Sleep(10 * time.Millisecond)

			// Provide response
			respHeader := smb1.NewHeader(smb1.SMB_COM_NEGOTIATE)
			respHeader.Flags |= smb1.SMB_FLAGS_REPLY
			respHeader.Status = smb1.STATUS_SUCCESS
			respHeader.MID = 0

			mockTCP.addResponse(respHeader, []byte{0x00, 0x00}, []byte("response"))

			// Wait for completion
			<-done

			if err != nil {
				t.Errorf("sendRecv failed: %v", err)
			}
		})
	})

	// Test 5: Demonstrate multiple concurrent operations with timing
	t.Run("ConcurrentOperationsWithTiming", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// Launch multiple operations that complete at different times
			results := make(chan int, 3)

			for i := 0; i < 3; i++ {
				go func(id int) {
					// Each operation takes progressively longer
					time.Sleep(time.Duration(id*100) * time.Millisecond)
					results <- id
				}(i)
			}

			// Collect results - they arrive in order despite timing
			var collected []int
			for i := 0; i < 3; i++ {
				select {
				case r := <-results:
					collected = append(collected, r)
				case <-time.After(1 * time.Second):
					t.Fatal("Timed out waiting for results")
				}
			}

			// With synctest, all operations complete instantly
			if len(collected) != 3 {
				t.Errorf("Expected 3 results, got %d", len(collected))
			}
		})
	})
}

// TestSynctestBestPractices demonstrates best practices for using synctest.
func TestSynctestBestPractices(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Best Practice 1: Always use synctest.Test for tests with goroutines and time
		// This ensures deterministic execution and fast tests.

		// Best Practice 2: Use time.Sleep for coordination, not real delays
		// In synctest, time.Sleep causes simulated time to advance when all
		// goroutines are blocked, making it perfect for synchronization.
		done := make(chan bool)
		go func() {
			time.Sleep(100 * time.Millisecond)
			done <- true
		}()

		select {
		case <-done:
			// Goroutine completed
		case <-time.After(1 * time.Second):
			t.Fatal("Should not timeout")
		}

		// Best Practice 3: Use proper channels for synchronization
		// While time.Sleep works in synctest, channels are still the idiomatic
		// way to coordinate goroutines.
		ready := make(chan struct{})
		go func() {
			// Simulate some setup work
			time.Sleep(10 * time.Millisecond)
			close(ready)
		}()

		<-ready // Wait for goroutine to be ready

		// Best Practice 4: Avoid testing implementation details
		// Test behavior and intent, not internal timing. synctest makes tests
		// deterministic, but the tests should still focus on correctness.
	})
}
