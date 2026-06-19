package conn

import (
	"context"
	"math"
	"time"

	"github.com/go-i2p/go-noise/internal/baseconfig"
	"github.com/go-i2p/go-noise/mod"
	i2plogger "github.com/go-i2p/logger"
	"github.com/samber/oops"
)

func (nc *Conn) logHandshakeEvent(level, fnName, message string, fields i2plogger.Fields) {
	logFields := i2plogger.Fields{
		"pkg":     "noise",
		"func":    fnName,
		"pattern": nc.config.Pattern,
		"role":    baseconfig.RoleString(nc.config.Initiator),
	}
	if remoteAddr := nc.RemoteAddr(); remoteAddr != nil {
		logFields["remote_addr"] = remoteAddr.String()
	}
	for k, v := range fields {
		logFields[k] = v
	}

	entry := nc.logger.WithFields(logFields)
	switch level {
	case "info":
		entry.Info(message)
	case "warn":
		entry.Warn(message)
	default:
		entry.Debug(message)
	}
}

// retryAttemptFields returns common retry-attempt log metadata.
func (nc *Conn) retryAttemptFields(attempt int) i2plogger.Fields {
	return i2plogger.Fields{
		"attempt":     attempt + 1,
		"max_retries": nc.config.HandshakeRetries,
	}
}

// HandshakeWithRetry performs a handshake with retry logic based on configuration.
// It uses the HandshakeRetries and RetryBackoff fields from ConnConfig to control
// the number of attempts and exponential backoff delay between retries.
// If HandshakeRetries is 0 (the default), this method behaves identically to
// Handshake() — a single attempt with no retries.
// It respects context cancellation between retry attempts.
func (nc *Conn) HandshakeWithRetry(ctx context.Context) error {
	if nc.shouldUseSingleAttempt() {
		return nc.Handshake(ctx)
	}

	return nc.executeRetryLoop(ctx)
}

// shouldUseSingleAttempt determines if only a single handshake attempt should be made.
func (nc *Conn) shouldUseSingleAttempt() bool {
	return nc.config.HandshakeRetries == 0
}

// executeRetryLoop performs the main retry logic with exponential backoff.
func (nc *Conn) executeRetryLoop(ctx context.Context) error {
	maxRetries := nc.config.HandshakeRetries
	attempt := 0

	for {
		err := nc.Handshake(ctx)
		if err == nil {
			nc.logSuccessAfterRetries(attempt)
			return nil
		}

		if !nc.shouldRetry(attempt, maxRetries, err) {
			return nc.wrapRetryError(err, attempt+1)
		}

		if err := nc.waitForRetry(ctx, attempt); err != nil {
			return nc.wrapRetryError(err, attempt+1)
		}

		attempt++
		nc.logRetryAttempt(attempt, err)
	}
}

// logSuccessAfterRetries logs successful handshake completion after retries.
func (nc *Conn) logSuccessAfterRetries(attempt int) {
	if attempt > 0 {
		nc.logHandshakeEvent(
			"info",
			"NoiseConn.logSuccessAfterRetries",
			"handshake succeeded after retries",
			i2plogger.Fields{"attempts": attempt + 1},
		)
	}
}

// shouldRetry determines if a handshake should be retried based on attempt count and error type.
func (nc *Conn) shouldRetry(attempt, maxRetries int, err error) bool {
	// Check maximum retry limit (-1 means infinite retries)
	if maxRetries != -1 && attempt >= maxRetries {
		return false
	}

	// Check if the connection is in a retriable state
	// Only retry from Init state (handshake sets state back to Init on failure)
	return nc.getState() == mod.StateInit
}

// waitForRetry implements exponential backoff delay before retry attempt.
func (nc *Conn) waitForRetry(ctx context.Context, attempt int) error {
	if nc.config.RetryBackoff <= 0 {
		return nil // No delay configured
	}

	// Calculate exponential backoff delay: backoff * (2^attempt)
	// Cap at 30 seconds to prevent excessive delays
	delay := time.Duration(float64(nc.config.RetryBackoff) * math.Pow(2, float64(attempt)))
	maxDelay := 30 * time.Second
	if delay > maxDelay {
		delay = maxDelay
	}

	nc.logHandshakeEvent(
		"debug",
		"NoiseConn.waitForRetry",
		"waiting before handshake retry with exponential backoff",
		func() i2plogger.Fields {
			fields := nc.retryAttemptFields(attempt)
			fields["delay_ms"] = delay.Milliseconds()
			fields["backoff_multiplier"] = math.Pow(2, float64(attempt))
			fields["capped_at_max"] = delay >= maxDelay
			fields["max_delay_ms"] = maxDelay.Milliseconds()
			return fields
		}(),
	)

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// logRetryAttempt logs information about the retry attempt.
func (nc *Conn) logRetryAttempt(attempt int, lastErr error) {
	// Extract error code if available from oops error
	errorCode := "UNKNOWN"
	if oe, ok := lastErr.(interface{ Code() string }); ok {
		errorCode = oe.Code()
	}

	nc.logHandshakeEvent(
		"warn",
		"NoiseConn.logRetryAttempt",
		"handshake failed, retrying with exponential backoff",
		func() i2plogger.Fields {
			fields := nc.retryAttemptFields(attempt)
			fields["last_error"] = lastErr.Error()
			fields["last_error_code"] = errorCode
			return fields
		}(),
	)
}

// wrapRetryError wraps the final error with retry context information.
func (nc *Conn) wrapRetryError(err error, totalAttempts int) error {
	return oops.
		Code("HANDSHAKE_RETRY_FAILED").
		In("noise").
		With("total_attempts", totalAttempts).
		With("max_retries", nc.config.HandshakeRetries).
		With("pattern", nc.config.Pattern).
		With("local_addr", nc.LocalAddr().String()).
		With("remote_addr", nc.RemoteAddr().String()).
		Wrapf(err, "handshake failed after %d attempts", totalAttempts)
}
