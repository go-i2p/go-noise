# Graceful Shutdown Example

This example demonstrates how to use the graceful shutdown functionality in the go-noise library.

## Features

- **ShutdownManager**: Coordinates graceful shutdown across all noise components
- **Context-based cancellation**: Uses context.Context for shutdown signaling
- **Connection draining**: Allows connections to finish current operations before shutdown
- **Timeout handling**: Forceful shutdown after grace period expires
- **Global shutdown**: Global shutdown manager for simple applications

## Key Components

### ShutdownManager

The `ShutdownManager` coordinates graceful shutdown across:
- **NoiseListeners**: Stops accepting new connections
- **NoiseConnections**: Allows in-flight operations to complete
- **Connection Pools**: Cleans up pooled connections
- **Global Resources**: Manages library-wide shutdown

### Integration Points

1. **Automatic Registration**: Transport functions (`DialNoise`, `ListenNoise`) automatically register with global shutdown manager
2. **Manual Registration**: Use `SetShutdownManager()` for custom shutdown coordination
3. **Context Monitoring**: Use `shutdownManager.Context()` to detect shutdown signals

## Usage Patterns

### Basic Global Shutdown

```go
// Initiate graceful shutdown of all components
err := noise.GracefulShutdown()
if err != nil {
    log.Printf("Shutdown error: %v", err)
}
```

### Custom Shutdown Manager

```go
// Create custom shutdown manager with 30 second timeout
sm := noise.NewShutdownManager(30 * time.Second)

// Register components manually
conn.SetShutdownManager(sm)
listener.SetShutdownManager(sm)

// Initiate shutdown
sm.Shutdown()
sm.Wait() // Wait for completion
```

### Context-based Monitoring

```go
func handleConnection(conn net.Conn, sm *noise.ShutdownManager) {
    for {
        select {
        case <-sm.Context().Done():
            // Shutdown signal received
            return
        default:
            // Continue processing
        }
        
        // Set timeouts to check shutdown regularly
        conn.SetReadDeadline(time.Now().Add(1 * time.Second))
        // ... handle connection
    }
}
```

## Signal Handling

The example demonstrates proper signal handling for graceful shutdown:

```go
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

// Wait for signal
<-sigChan

// Initiate graceful shutdown
shutdownManager.Shutdown()
shutdownManager.Wait()
```

## Running the Example

```bash
cd examples/shutdown
go build -o shutdown main.go
./shutdown
```

The server will:
1. Listen on 127.0.0.1:8080
2. Accept noise protocol connections
3. Echo received data back to clients
4. Gracefully shutdown on SIGINT/SIGTERM

Press Ctrl+C to test graceful shutdown behavior.

## Implementation Notes

- **Timeout Configuration**: Default 30 seconds, customizable via `NewShutdownManager(timeout)`
- **Thread Safety**: All operations safe for concurrent use
- **Resource Cleanup**: Automatic cleanup of connections, listeners, and pools
- **Error Handling**: Error context with `samber/oops` integration
