package logging

import (
	"context"
)

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey int

const (
	// loggerKey is the context key for the logger.
	loggerKey contextKey = 0
)

// Logger is the interface for logging. Applications can provide
// their own logger implementation for custom logging behavior.
type Logger interface {
	// Debug logs a debug message
	Debug(format string, v ...interface{})

	// Info logs an informational message
	Info(format string, v ...interface{})

	// Warn logs a warning message
	Warn(format string, v ...interface{})

	// Error logs an error message
	Error(format string, v ...interface{})
}

// noopLogger is a logger that does nothing.
type noopLogger struct{}

func (l *noopLogger) Debug(format string, v ...interface{}) {}
func (l *noopLogger) Info(format string, v ...interface{})  {}
func (l *noopLogger) Warn(format string, v ...interface{})  {}
func (l *noopLogger) Error(format string, v ...interface{}) {}

// WithLogger returns a new context with the provided logger attached.
// The logger will be used by SMB operations that accept this context.
func WithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// FromContext retrieves the logger from the context.
// If no logger is attached to the context, it returns a no-op logger.
func FromContext(ctx context.Context) Logger {
	if ctx == nil {
		return &noopLogger{}
	}
	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		return logger
	}
	return &noopLogger{}
}
