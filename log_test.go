package noise

import (
	"testing"

	"github.com/go-i2p/logger"
)

func TestLoggerInitialization(t *testing.T) {
	// Test that the global logger is initialized
	if log == nil {
		t.Errorf("Global logger should not be nil")
	}

	// Test that it's a go-i2p logger instance
	// Since log is already *logger.Logger, we just need to verify it's not nil
	if log == nil {
		t.Errorf("log should be a valid Logger instance")
	}
}

func TestLoggerAccess(t *testing.T) {
	// Test that we can access the logger
	testLogger := logger.GetGoI2PLogger()
	if testLogger == nil {
		t.Errorf("GetGoI2PLogger should not return nil")
	}

	// Test that multiple calls return the same instance (singleton pattern)
	testLogger2 := logger.GetGoI2PLogger()
	if testLogger != testLogger2 {
		t.Errorf("GetGoI2PLogger should return the same instance")
	}

	// Test that our global log variable is the same instance
	if log != testLogger {
		t.Errorf("Global log variable should be the same as GetGoI2PLogger()")
	}
}

func TestLoggerUsage(t *testing.T) {
	// Test that we can use the logger without panics
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Logger usage should not panic: %v", r)
		}
	}()

	// These should not panic
	log.Debug("Test debug message")
	log.Info("Test info message")
	log.Warn("Test warn message")
}
