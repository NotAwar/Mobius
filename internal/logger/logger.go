package logger

import (
	"fmt"
	"log/slog"
	"os"
)

// Logger is a minimal interface for logging that both logrus and TUI logger can implement
type Logger interface {
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Warning(args ...interface{})
	Warningf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Trace(args ...interface{})
	Tracef(format string, args ...interface{})
}

// SlogLogger is a Logger implementation using Go's log/slog
type SlogLogger struct {
	logger *slog.Logger
}

// New creates a new logger
func New(debug bool) Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	
	return &SlogLogger{
		logger: slog.New(handler),
	}
}

// Info logs an info message
func (l *SlogLogger) Info(args ...interface{}) {
	l.logger.Info(fmt.Sprint(args...))
}

// Infof logs a formatted info message
func (l *SlogLogger) Infof(format string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

// Warn logs a warning message
func (l *SlogLogger) Warn(args ...interface{}) {
	l.logger.Warn(fmt.Sprint(args...))
}

// Warnf logs a formatted warning message
func (l *SlogLogger) Warnf(format string, args ...interface{}) {
	l.logger.Warn(fmt.Sprintf(format, args...))
}

// Warning logs a warning message (alias for Warn)
func (l *SlogLogger) Warning(args ...interface{}) {
	l.Warn(args...)
}

// Warningf logs a formatted warning message (alias for Warnf)
func (l *SlogLogger) Warningf(format string, args ...interface{}) {
	l.Warnf(format, args...)
}

// Error logs an error message
func (l *SlogLogger) Error(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...))
}

// Errorf logs a formatted error message
func (l *SlogLogger) Errorf(format string, args ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, args...))
}

// Fatal logs a fatal message and exits
func (l *SlogLogger) Fatal(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...))
	os.Exit(1)
}

// Fatalf logs a formatted fatal message and exits
func (l *SlogLogger) Fatalf(format string, args ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// Debug logs a debug message
func (l *SlogLogger) Debug(args ...interface{}) {
	l.logger.Debug(fmt.Sprint(args...))
}

// Debugf logs a formatted debug message
func (l *SlogLogger) Debugf(format string, args ...interface{}) {
	l.logger.Debug(fmt.Sprintf(format, args...))
}

// Trace logs a trace message (mapped to debug)
func (l *SlogLogger) Trace(args ...interface{}) {
	l.Debug(args...)
}

// Tracef logs a formatted trace message (mapped to debug)
func (l *SlogLogger) Tracef(format string, args ...interface{}) {
	l.Debugf(format, args...)
}
