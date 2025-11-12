package main

import (
	"time"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelError LogLevel = "error"
)

type Log struct {
	Level     LogLevel       `json:"level"`
	Message   string         `json:"message"`
	Timestamp time.Time      `json:"timestamp"`
	Data      interface{}    `json:"data,omitempty"`
	CallStack []FunctionCall `json:"call_stack,omitempty"`
}

type FunctionCall struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

type SearchRequest struct {
	Search  string `json:"search"`
	Exclude string `json:"exclude"`
	Section string `json:"section"`
}

type SearchResult struct {
	Output interface{} `json:"output"`
	Error  string      `json:"error,omitempty"`
}

type Application struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	Attributes  map[string]string `json:"attributes"`
}
