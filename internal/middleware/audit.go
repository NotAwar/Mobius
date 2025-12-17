package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

// AuditLogger is a middleware that logs all API requests for audit purposes
type AuditLogger struct {
	logger *logrus.Logger
}

// NewAuditLogger creates a new audit logger middleware
func NewAuditLogger(logger *logrus.Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger,
	}
}

// Handler returns the middleware handler function
func (a *AuditLogger) Handler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Continue processing request
		err := c.Next()

		// Log after request completes
		duration := time.Since(start)
		
		logEntry := a.logger.WithFields(logrus.Fields{
			"method":      c.Method(),
			"path":        c.Path(),
			"status":      c.Response().StatusCode(),
			"ip":          c.IP(),
			"user_agent":  c.Get("User-Agent"),
			"request_id":  c.Locals("requestid"),
			"duration_ms": duration.Milliseconds(),
		})

		// Log based on status code
		statusCode := c.Response().StatusCode()
		if statusCode >= 500 {
			logEntry.Error("Request completed with server error")
		} else if statusCode >= 400 {
			logEntry.Warn("Request completed with client error")
		} else {
			logEntry.Info("Request completed successfully")
		}

		return err
	}
}
