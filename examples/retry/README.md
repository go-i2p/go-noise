# Handshake Retry Example

This example demonstrates the handshake retry mechanisms implemented in go-noise, which provide robust error recovery for network connections using the Noise Protocol Framework.

## Features Demonstrated

### 1. Retry Configuration
- **HandshakeRetries**: Number of retry attempts (0 = no retries, -1 = infinite)
- **RetryBackoff**: Base delay between attempts with exponential backoff
- **HandshakeTimeout**: Timeout per individual handshake attempt

### 2. Transport Functions with Automatic Retry
- `DialNoiseWithHandshake()` - High-level dial with automatic handshake and retry
- `DialNoiseWithHandshakeContext()` - Context-aware version for cancellation
- `DialNoiseWithPoolAndHandshake()` - Pool-enabled version with retry support

### 3. Exponential Backoff
- Base delay multiplied by 2^attempt for each retry
- Maximum delay capped at 30 seconds
- Context-aware delays that respect cancellation

### 4. Error Handling
- Error context with attempt counts and configuration details
- Comprehensive validation of retry parameters
- State-aware retry logic (only retries from failed handshake state)

## Running the Example

```bash
cd examples/retry
go run main.go
```

## Key Concepts

### Configuration Builder Pattern
```go
config := noise.NewConnConfig("XX", true).
    WithHandshakeRetries(3).              // Try up to 3 times
    WithRetryBackoff(500 * time.Millisecond). // 500ms base delay
    WithHandshakeTimeout(5 * time.Second) // 5s timeout per attempt
```

### High-Level Transport Usage
```go
// Automatic retry with context
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

conn, err := noise.DialNoiseWithHandshakeContext(ctx, "tcp", "server:8080", config)
if err != nil {
    // Error includes retry attempt information
    log.Printf("Connection failed after retries: %v", err)
}
```

### Manual Retry Control
```go
// Create connection and manually control handshake retry
noiseConn, err := noise.NewNoiseConn(underlyingConn, config)
if err != nil {
    return err
}

// Perform handshake with retry logic
err = noiseConn.HandshakeWithRetry(ctx)
```

## Integration with Phase 2 Features

The retry mechanism integrates seamlessly with other Phase 2 features:
- **Connection Pooling**: Pool-enabled transport functions include retry support
- **Connection State Management**: Retries only occur from appropriate connection states
- **Graceful Shutdown**: Retry delays respect shutdown context cancellation

See the main project PLAN.md for detailed implementation notes and integration with other go-noise features.
