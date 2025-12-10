package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"
)

func printLog(message string, level LogLevel, data interface{}) {
	const skip = 2
	pcs := make([]uintptr, 32)
	for {
		n := runtime.Callers(skip, pcs)
		if n < len(pcs) {
			pcs = pcs[:n]
			break
		}
		pcs = append(pcs, make([]uintptr, len(pcs))...)
	}

	var callStack []FunctionCall
	frames := runtime.CallersFrames(pcs)
	for {
		frame, more := frames.Next()
		if !strings.HasPrefix(frame.File, "/app/") {
			break
		}
		callStack = append(callStack, FunctionCall{
			Function: frame.Function,
			File:     frame.File,
			Line:     frame.Line,
		})
		if !more {
			break
		}
	}

	logEntry := Log{
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
		Data:      data,
		CallStack: callStack,
	}

	entryBytes, err := json.Marshal(logEntry)
	if err != nil {
		fmt.Printf("error marshaling log entry: %v\n", err)
		return
	}

	fmt.Println(string(entryBytes))
}
