package tui

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
)

// Logger is a logrus-compatible logger that sends output to the TUI
type Logger struct {
	tui   *Program
	level logrus.Level
}

// NewLogger creates a new logger that outputs to the TUI
func NewLogger(tui *Program) *Logger {
	return &Logger{
		tui:   tui,
		level: logrus.InfoLevel,
	}
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level logrus.Level) {
	l.level = level
}

// SetFormatter does nothing but is needed for compatibility
func (l *Logger) SetFormatter(formatter logrus.Formatter) {}

// SetOutput does nothing but is needed for compatibility
func (l *Logger) SetOutput(output io.Writer) {}

// Level returns the current logging level
func (l *Logger) Level() logrus.Level {
	return l.level
}

// Log methods
func (l *Logger) Trace(args ...interface{}) {
	if l.level >= logrus.TraceLevel {
		l.tui.Info(fmt.Sprint(args...))
	}
}

func (l *Logger) Debug(args ...interface{}) {
	if l.level >= logrus.DebugLevel {
		l.tui.Info(fmt.Sprint(args...))
	}
}

func (l *Logger) Info(args ...interface{}) {
	if l.level >= logrus.InfoLevel {
		l.tui.Info(fmt.Sprint(args...))
	}
}

func (l *Logger) Warn(args ...interface{}) {
	if l.level >= logrus.WarnLevel {
		l.tui.Warning(fmt.Sprint(args...))
	}
}

func (l *Logger) Warning(args ...interface{}) {
	if l.level >= logrus.WarnLevel {
		l.tui.Warning(fmt.Sprint(args...))
	}
}

func (l *Logger) Error(args ...interface{}) {
	if l.level >= logrus.ErrorLevel {
		l.tui.Error(fmt.Sprint(args...))
	}
}

func (l *Logger) Fatal(args ...interface{}) {
	l.tui.Error(fmt.Sprint(args...))
	panic(fmt.Sprint(args...))
}

func (l *Logger) Panic(args ...interface{}) {
	l.tui.Error(fmt.Sprint(args...))
	panic(fmt.Sprint(args...))
}

// Formatted methods
func (l *Logger) Tracef(format string, args ...interface{}) {
	if l.level >= logrus.TraceLevel {
		l.tui.Info(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.level >= logrus.DebugLevel {
		l.tui.Info(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Infof(format string, args ...interface{}) {
	if l.level >= logrus.InfoLevel {
		l.tui.Info(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	if l.level >= logrus.WarnLevel {
		l.tui.Warning(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Warningf(format string, args ...interface{}) {
	if l.level >= logrus.WarnLevel {
		l.tui.Warning(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	if l.level >= logrus.ErrorLevel {
		l.tui.Error(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.tui.Error(fmt.Sprintf(format, args...))
	panic(fmt.Sprintf(format, args...))
}

func (l *Logger) Panicf(format string, args ...interface{}) {
	l.tui.Error(fmt.Sprintf(format, args...))
	panic(fmt.Sprintf(format, args...))
}

// WithField methods (simplified - just pass through)
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return logrus.NewEntry(logrus.New()).WithField(key, value)
}

func (l *Logger) WithFields(fields logrus.Fields) *logrus.Entry {
	return logrus.NewEntry(logrus.New()).WithFields(fields)
}

func (l *Logger) WithError(err error) *logrus.Entry {
	return logrus.NewEntry(logrus.New()).WithError(err)
}
