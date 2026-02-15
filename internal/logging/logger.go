package logging

import (
	"fmt"
	"log"
	"os"
	"sync"
)

// Level represents a log severity level.
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

// String returns the level name.
func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger provides structured, leveled logging.
type Logger struct {
	mu    sync.Mutex
	level Level
	inner *log.Logger
}

var defaultLogger = &Logger{
	level: INFO,
	inner: log.New(os.Stderr, "", log.LstdFlags),
}

// Default returns the package-level default logger.
func Default() *Logger {
	return defaultLogger
}

// SetLevel sets the minimum log level.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Debug logs a message at DEBUG level.
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs a message at INFO level.
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a message at WARN level.
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs a message at ERROR level.
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	l.mu.Lock()
	minLevel := l.level
	l.mu.Unlock()

	if level < minLevel {
		return
	}

	msg := fmt.Sprintf(format, args...)
	l.inner.Printf("[%s] %s", level, msg)
}

// ParseLevel converts a string to a Level.
func ParseLevel(s string) Level {
	switch s {
	case "DEBUG", "debug":
		return DEBUG
	case "INFO", "info":
		return INFO
	case "WARN", "warn":
		return WARN
	case "ERROR", "error":
		return ERROR
	default:
		return INFO
	}
}
