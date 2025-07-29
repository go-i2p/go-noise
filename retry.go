package noise

import (
	"context"
	"math"
	"time"

	"github.com/go-i2p/go-noise/internal"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

// HandshakeWithRetry performs a handshake with retry logic based on configuration.
// It implements exponential backoff for retry delays and respects context cancellation.
func (nc *NoiseConn) HandshakeWithRetry(ctx context.Context) error {
	if nc.shouldUseSingleAttempt() {
		return nc.Handshake(ctx)
	}

	return nc.executeRetryLoop(ctx)
}

// shouldUseSingleAttempt determines if only a single handshake attempt should be made.
func (nc *NoiseConn) shouldUseSingleAttempt() bool {
	return nc.config.HandshakeRetries == 0
}

// executeRetryLoop performs the main retry logic with exponential backoff.
func (nc *NoiseConn) executeRetryLoop(ctx context.Context) error {
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
func (nc *NoiseConn) logSuccessAfterRetries(attempt int) {
	if attempt > 0 {
		nc.logger.WithFields(logrus.Fields{
			"attempts": attempt + 1,
			"pattern":  nc.config.Pattern,
		}).Info("Handshake succeeded after retries")
	}
}

// shouldRetry determines if a handshake should be retried based on attempt count and error type.
func (nc *NoiseConn) shouldRetry(attempt, maxRetries int, err error) bool {
	// Check maximum retry limit (-1 means infinite retries)
	if maxRetries != -1 && attempt >= maxRetries {
		return false
	}

	// Check if the connection is in a retriable state
	// Only retry from Init state (handshake sets state back to Init on failure)
	return nc.getState() == internal.StateInit
}

// waitForRetry implements exponential backoff delay before retry attempt.
func (nc *NoiseConn) waitForRetry(ctx context.Context, attempt int) error {
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

	nc.logger.WithFields(logrus.Fields{
		"attempt": attempt + 1,
		"delay":   delay,
		"pattern": nc.config.Pattern,
	}).Debug("Waiting before handshake retry")

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
func (nc *NoiseConn) logRetryAttempt(attempt int, lastErr error) {
	nc.logger.WithFields(logrus.Fields{
		"attempt":    attempt + 1,
		"pattern":    nc.config.Pattern,
		"last_error": lastErr.Error(),
	}).Warn("Handshake failed, retrying")
}

// wrapRetryError wraps the final error with retry context information.
func (nc *NoiseConn) wrapRetryError(err error, totalAttempts int) error {
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
