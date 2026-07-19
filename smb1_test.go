package smb1

import (
	"context"
	"sync"
	"testing"
)

// mockLogger is a thread-safe logger for testing
type mockLogger struct {
	mu       sync.Mutex
	errorLog []string
	warnLog  []string
	infoLog  []string
	debugLog []string
}

func (m *mockLogger) Error(format string, v ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorLog = append(m.errorLog, format)
}

func (m *mockLogger) Warn(format string, v ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.warnLog = append(m.warnLog, format)
}

func (m *mockLogger) Info(format string, v ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoLog = append(m.infoLog, format)
}

func (m *mockLogger) Debug(format string, v ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLog = append(m.debugLog, format)
}

func (m *mockLogger) errorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.errorLog)
}

func (m *mockLogger) warnCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.warnLog)
}

func (m *mockLogger) infoCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.infoLog)
}

func (m *mockLogger) debugCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.debugLog)
}

func TestWithLogger(t *testing.T) {
	mock := &mockLogger{}
	ctx := WithLogger(context.Background(), mock)

	logger := LoggerFromContext(ctx)
	if logger == nil {
		t.Fatal("Expected logger to be non-nil")
	}

	// Verify the logger is the one we attached
	if logger != mock {
		t.Fatal("Expected logger to be the same as the one attached")
	}
}

func TestLoggerFromContext_NoLogger(t *testing.T) {
	ctx := context.Background()
	logger := LoggerFromContext(ctx)

	if logger == nil {
		t.Fatal("Expected logger to be non-nil (should return no-op logger)")
	}

	// Verify it's a no-op logger by checking it doesn't panic
	logger.Debug("test debug")
	logger.Info("test info")
	logger.Warn("test warn")
	logger.Error("test error")
}

func TestLoggerFromContext_NilContext(t *testing.T) {
	//lint:ignore SA1012 intentionally testing nil-context handling
	logger := LoggerFromContext(nil)

	if logger == nil {
		t.Fatal("Expected logger to be non-nil (should return no-op logger)")
	}

	// Verify it's a no-op logger by checking it doesn't panic
	logger.Debug("test debug")
	logger.Info("test info")
	logger.Warn("test warn")
	logger.Error("test error")
}

func TestNoopLogger(t *testing.T) {
	// Get noop logger from context without a logger attached
	logger := LoggerFromContext(context.Background())

	// Verify no-op logger doesn't panic
	logger.Debug("test debug")
	logger.Info("test info")
	logger.Warn("test warn")
	logger.Error("test error")
}

func TestMockLogger_AllLevels(t *testing.T) {
	mock := &mockLogger{}
	ctx := WithLogger(context.Background(), mock)

	logger := LoggerFromContext(ctx)

	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	if mock.debugCount() != 1 {
		t.Errorf("Expected 1 debug log, got %d", mock.debugCount())
	}
	if mock.infoCount() != 1 {
		t.Errorf("Expected 1 info log, got %d", mock.infoCount())
	}
	if mock.warnCount() != 1 {
		t.Errorf("Expected 1 warn log, got %d", mock.warnCount())
	}
	if mock.errorCount() != 1 {
		t.Errorf("Expected 1 error log, got %d", mock.errorCount())
	}
}

func TestConcurrentLogging(t *testing.T) {
	mock := &mockLogger{}
	ctx := WithLogger(context.Background(), mock)

	const numGoroutines = 50
	const numIterations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 4) // 4 log levels

	logger := LoggerFromContext(ctx)

	// Test Debug
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				logger.Debug("debug %d-%d", id, j)
			}
		}(i)
	}

	// Test Info
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				logger.Info("info %d-%d", id, j)
			}
		}(i)
	}

	// Test Warn
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				logger.Warn("warn %d-%d", id, j)
			}
		}(i)
	}

	// Test Error
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				logger.Error("error %d-%d", id, j)
			}
		}(i)
	}

	wg.Wait()

	// Verify all logs were captured
	expectedCount := numGoroutines * numIterations
	if mock.debugCount() != expectedCount {
		t.Errorf("Expected %d debug logs, got %d", expectedCount, mock.debugCount())
	}
	if mock.infoCount() != expectedCount {
		t.Errorf("Expected %d info logs, got %d", expectedCount, mock.infoCount())
	}
	if mock.warnCount() != expectedCount {
		t.Errorf("Expected %d warn logs, got %d", expectedCount, mock.warnCount())
	}
	if mock.errorCount() != expectedCount {
		t.Errorf("Expected %d error logs, got %d", expectedCount, mock.errorCount())
	}
}

func TestConcurrentContextCreation(t *testing.T) {
	const numGoroutines = 100
	const numIterations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				mock := &mockLogger{}
				ctx := WithLogger(context.Background(), mock)
				logger := LoggerFromContext(ctx)

				// Use the logger
				logger.Error("test error from goroutine %d iteration %d", id, j)

				// Verify the logger worked
				if mock.errorCount() != 1 {
					t.Errorf("Expected 1 error log, got %d", mock.errorCount())
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestContextChaining(t *testing.T) {
	mock := &mockLogger{}

	// Create a context with a logger
	ctx := WithLogger(context.Background(), mock)

	// Create a child context
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Verify logger is accessible from child context
	logger := LoggerFromContext(childCtx)
	if logger != mock {
		t.Fatal("Expected logger to be accessible from child context")
	}

	logger.Info("test message")
	if mock.infoCount() != 1 {
		t.Errorf("Expected 1 info log, got %d", mock.infoCount())
	}
}
