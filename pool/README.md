# Connection Pool

The `pool` package provides connection pooling for the go-noise library. It enables connection reuse for Noise protocol connections.

## Features

- **Interface-Only Design**: Uses `net.Conn`, `net.Addr`, and `net.Listener` interfaces exclusively
- **Connection Lifecycle Management**: Connections expire based on age and idle time
- **Thread-Safe Operations**: All methods safe for concurrent use
- **Usage Statistics**: Pool health and usage monitoring

## Quick Start

```go
package main

import (
    "time"
    "github.com/go-i2p/go-noise/pool"
    "github.com/go-i2p/go-noise"
)

func main() {
    // Create a connection pool
    p := pool.NewConnPool(&pool.PoolConfig{
        MaxSize: 10,                // Max connections per address
        MaxAge:  30 * time.Minute,  // Connection max lifetime
        MaxIdle: 5 * time.Minute,   // Max idle time before cleanup
    })
    defer p.Close()

    // Use with transport functions
    noise.SetGlobalConnPool(p)
    
    // Example config (replace with your actual configuration)
    config := noise.NewConnConfig("XX", true)
    conn, err := noise.DialNoiseWithPool("tcp", "127.0.0.1:8080", config)
    if err != nil {
        panic(err)
    }
    // Connection automatically returned to pool when closed
    defer conn.Close()
}
```

## Configuration

- `MaxSize`: Maximum connections per remote address (default: 10)
- `MaxAge`: Maximum connection lifetime (default: 30 minutes)
- `MaxIdle`: Maximum idle time before cleanup (default: 5 minutes)

## Thread Safety

All pool operations are thread-safe and support concurrent usage. The pool supports concurrent connections.
