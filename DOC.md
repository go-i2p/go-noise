# noise
--
    import "github.com/go-i2p/go-noise"

![noise.svg](noise.svg)

Package noise provides a high-level wrapper around the flynn/noise package
implementing net.Conn, net.Listener, and net.Addr interfaces for the Noise
Protocol Framework. It supports extensible handshake modification for
implementing I2P's NTCP2 and SSU2 transport protocols.

## Usage

#### func  GetGlobalConnPool

```go
func GetGlobalConnPool() *pool.ConnPool
```
GetGlobalConnPool returns the current global connection pool

#### func  GracefulShutdown

```go
func GracefulShutdown() error
```
GracefulShutdown initiates graceful shutdown of all global components. This
includes the global connection pool and all registered connections/listeners.

#### func  SetGlobalConnPool

```go
func SetGlobalConnPool(p *pool.ConnPool)
```
SetGlobalConnPool sets a custom connection pool for transport functions

#### func  SetGlobalShutdownManager

```go
func SetGlobalShutdownManager(sm *ShutdownManager)
```
SetGlobalShutdownManager sets a custom shutdown manager for transport functions.
The previous shutdown manager will be shut down gracefully.

#### type ConnConfig

```go
type ConnConfig struct {
	// Pattern is the Noise protocol pattern (e.g., "Noise_XX_25519_AESGCM_SHA256")
	Pattern string

	// Initiator indicates if this connection is the handshake initiator
	Initiator bool

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// RemoteKey is the remote peer's static public key (32 bytes for Curve25519)
	// Required for some patterns, optional for others
	RemoteKey []byte

	// HandshakeTimeout is the maximum time to wait for handshake completion
	// Default: 30 seconds
	HandshakeTimeout time.Duration

	// ReadTimeout is the timeout for read operations after handshake
	// Default: no timeout (0)
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations after handshake
	// Default: no timeout (0)
	WriteTimeout time.Duration

	// HandshakeRetries is the number of handshake retry attempts
	// Default: 3 attempts (0 = no retries, -1 = infinite retries)
	HandshakeRetries int

	// RetryBackoff is the base delay between retry attempts
	// Actual delay uses exponential backoff: delay = RetryBackoff * (2^attempt)
	// Default: 1 second
	RetryBackoff time.Duration

	// Modifiers is a list of handshake modifiers for obfuscation and padding
	// Modifiers are applied in order during outbound processing and in reverse
	// order during inbound processing. Default: empty (no modifiers)
	Modifiers []handshake.HandshakeModifier
}
```

ConnConfig contains configuration for creating a NoiseConn. It follows the
builder pattern for optional configuration and validation.

#### func  NewConnConfig

```go
func NewConnConfig(pattern string, initiator bool) *ConnConfig
```
NewConnConfig creates a new ConnConfig with sensible defaults.

#### func (*ConnConfig) AddModifier

```go
func (c *ConnConfig) AddModifier(modifier handshake.HandshakeModifier) *ConnConfig
```
AddModifier appends a single modifier to the existing modifier list.

#### func (*ConnConfig) ClearModifiers

```go
func (c *ConnConfig) ClearModifiers() *ConnConfig
```
ClearModifiers removes all modifiers from the configuration.

#### func (*ConnConfig) GetModifierChain

```go
func (c *ConnConfig) GetModifierChain() *handshake.ModifierChain
```
GetModifierChain returns a ModifierChain containing all configured modifiers.
Returns nil if no modifiers are configured.

#### func (*ConnConfig) Validate

```go
func (c *ConnConfig) Validate() error
```
Validate checks if the configuration is valid and complete. Returns an error
with context if validation fails.

#### func (*ConnConfig) WithHandshakeRetries

```go
func (c *ConnConfig) WithHandshakeRetries(retries int) *ConnConfig
```
WithHandshakeRetries sets the number of handshake retry attempts. Use 0 for no
retries, -1 for infinite retries.

#### func (*ConnConfig) WithHandshakeTimeout

```go
func (c *ConnConfig) WithHandshakeTimeout(timeout time.Duration) *ConnConfig
```
WithHandshakeTimeout sets the handshake timeout.

#### func (*ConnConfig) WithModifiers

```go
func (c *ConnConfig) WithModifiers(modifiers ...handshake.HandshakeModifier) *ConnConfig
```
WithModifiers sets the handshake modifiers for obfuscation and padding.
Modifiers are applied in the order provided for outbound data and in reverse
order for inbound data.

#### func (*ConnConfig) WithReadTimeout

```go
func (c *ConnConfig) WithReadTimeout(timeout time.Duration) *ConnConfig
```
WithReadTimeout sets the read timeout for post-handshake operations.

#### func (*ConnConfig) WithRemoteKey

```go
func (c *ConnConfig) WithRemoteKey(key []byte) *ConnConfig
```
WithRemoteKey sets the remote peer's static public key. key must be 32 bytes for
Curve25519.

#### func (*ConnConfig) WithRetryBackoff

```go
func (c *ConnConfig) WithRetryBackoff(backoff time.Duration) *ConnConfig
```
WithRetryBackoff sets the base delay between retry attempts. Actual delay uses
exponential backoff: delay = backoff * (2^attempt).

#### func (*ConnConfig) WithStaticKey

```go
func (c *ConnConfig) WithStaticKey(key []byte) *ConnConfig
```
WithStaticKey sets the static key for this connection. key must be 32 bytes for
Curve25519.

#### func (*ConnConfig) WithWriteTimeout

```go
func (c *ConnConfig) WithWriteTimeout(timeout time.Duration) *ConnConfig
```
WithWriteTimeout sets the write timeout for post-handshake operations.

#### type ListenerConfig

```go
type ListenerConfig struct {
	// Pattern is the Noise protocol pattern (e.g., "Noise_XX_25519_AESGCM_SHA256")
	Pattern string

	// StaticKey is the long-term static key for this listener (32 bytes for Curve25519)
	StaticKey []byte

	// HandshakeTimeout is the maximum time to wait for handshake completion
	// Default: 30 seconds
	HandshakeTimeout time.Duration

	// ReadTimeout is the timeout for read operations after handshake
	// Default: no timeout (0)
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations after handshake
	// Default: no timeout (0)
	WriteTimeout time.Duration
}
```

ListenerConfig contains configuration for creating a NoiseListener. It follows
the builder pattern for optional configuration and validation.

#### func  NewListenerConfig

```go
func NewListenerConfig(pattern string) *ListenerConfig
```
NewListenerConfig creates a new ListenerConfig with sensible defaults.

#### func (*ListenerConfig) Validate

```go
func (lc *ListenerConfig) Validate() error
```
Validate checks if the configuration is valid.

#### func (*ListenerConfig) WithHandshakeTimeout

```go
func (lc *ListenerConfig) WithHandshakeTimeout(timeout time.Duration) *ListenerConfig
```
WithHandshakeTimeout sets the handshake timeout.

#### func (*ListenerConfig) WithReadTimeout

```go
func (lc *ListenerConfig) WithReadTimeout(timeout time.Duration) *ListenerConfig
```
WithReadTimeout sets the read timeout for accepted connections.

#### func (*ListenerConfig) WithStaticKey

```go
func (lc *ListenerConfig) WithStaticKey(key []byte) *ListenerConfig
```
WithStaticKey sets the static key for this listener. key must be 32 bytes for
Curve25519.

#### func (*ListenerConfig) WithWriteTimeout

```go
func (lc *ListenerConfig) WithWriteTimeout(timeout time.Duration) *ListenerConfig
```
WithWriteTimeout sets the write timeout for accepted connections.

#### type NoiseAddr

```go
type NoiseAddr struct {
}
```

NoiseAddr implements net.Addr for Noise Protocol connections. It wraps an
underlying net.Addr and adds Noise-specific addressing information.

#### func  NewNoiseAddr

```go
func NewNoiseAddr(underlying net.Addr, pattern, role string) *NoiseAddr
```
NewNoiseAddr creates a new NoiseAddr wrapping an underlying network address.
pattern should be a valid Noise protocol pattern (e.g.,
"Noise_XX_25519_AESGCM_SHA256"). role should be either "initiator" or
"responder".

#### func (*NoiseAddr) Network

```go
func (na *NoiseAddr) Network() string
```
Network returns the network type, prefixed with "noise+" to indicate Noise
wrapping. For example, "noise+tcp" for Noise over TCP or "noise+udp" for Noise
over UDP.

#### func (*NoiseAddr) Pattern

```go
func (na *NoiseAddr) Pattern() string
```
Pattern returns the Noise protocol pattern.

#### func (*NoiseAddr) Role

```go
func (na *NoiseAddr) Role() string
```
Role returns the role (initiator or responder).

#### func (*NoiseAddr) String

```go
func (na *NoiseAddr) String() string
```
String returns a string representation of the Noise address. Format:
"noise://[pattern]/[role]/[underlying_address]" Example:
"noise://Noise_XX_25519_AESGCM_SHA256/initiator/192.168.1.1:8080"

#### func (*NoiseAddr) Underlying

```go
func (na *NoiseAddr) Underlying() net.Addr
```
Underlying returns the wrapped network address. This allows access to the
original address when needed.

#### type NoiseConn

```go
type NoiseConn struct {
}
```

NoiseConn implements net.Conn with Noise Protocol encryption. It wraps an
underlying net.Conn and provides encrypted communication following the Noise
Protocol Framework specification.

#### func  DialNoise

```go
func DialNoise(network, addr string, config *ConnConfig) (*NoiseConn, error)
```
DialNoise creates a connection to the given address and wraps it with NoiseConn.
This is a convenience function that combines net.Dial and NewNoiseConn. For more
control over the underlying connection, use net.Dial followed by NewNoiseConn.

#### func  DialNoiseWithHandshake

```go
func DialNoiseWithHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error)
```
DialNoiseWithHandshake creates a connection to the given address, wraps it with
NoiseConn, and performs the handshake with retry logic. This is the recommended
high-level function for establishing Noise connections with automatic retry
capabilities.

#### func  DialNoiseWithHandshakeContext

```go
func DialNoiseWithHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error)
```
DialNoiseWithHandshakeContext creates a connection with context support for
cancellation. It combines dialing, NoiseConn creation, and handshake with retry
in a single operation.

#### func  DialNoiseWithPool

```go
func DialNoiseWithPool(network, addr string, config *ConnConfig) (*NoiseConn, error)
```
DialNoiseWithPool creates a connection to the given address, checking the pool
first. If a suitable connection is available in the pool, it will be reused.
Otherwise, a new connection is created. The connection will be automatically
returned to the pool when the NoiseConn is closed.

#### func  DialNoiseWithPoolAndHandshake

```go
func DialNoiseWithPoolAndHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error)
```
DialNoiseWithPoolAndHandshake creates a connection with pool support and
handshake retry. It checks the pool first, creates new if needed, and performs
handshake with retry logic.

#### func  DialNoiseWithPoolAndHandshakeContext

```go
func DialNoiseWithPoolAndHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error)
```
DialNoiseWithPoolAndHandshakeContext combines pool checking, dialing, and
handshake with context.

#### func  NewNoiseConn

```go
func NewNoiseConn(underlying net.Conn, config *ConnConfig) (*NoiseConn, error)
```
NewNoiseConn creates a new NoiseConn wrapping the underlying connection. The
handshake must be completed before using Read/Write operations.

#### func  WrapConn

```go
func WrapConn(conn net.Conn, config *ConnConfig) (*NoiseConn, error)
```
WrapConn wraps an existing net.Conn with NoiseConn. This is an alias for
NewNoiseConn for consistency with the transport API.

#### func (*NoiseConn) Close

```go
func (nc *NoiseConn) Close() error
```
Close closes the connection.

#### func (*NoiseConn) GetConnectionMetrics

```go
func (nc *NoiseConn) GetConnectionMetrics() (bytesRead, bytesWritten int64, handshakeDuration time.Duration)
```
GetConnectionMetrics returns the current connection statistics

#### func (*NoiseConn) GetConnectionState

```go
func (nc *NoiseConn) GetConnectionState() internal.ConnState
```
GetConnectionState returns the current connection state

#### func (*NoiseConn) Handshake

```go
func (nc *NoiseConn) Handshake(ctx context.Context) error
```
Handshake performs the Noise Protocol handshake. This must be called before
using Read/Write operations.

#### func (*NoiseConn) HandshakeWithRetry

```go
func (nc *NoiseConn) HandshakeWithRetry(ctx context.Context) error
```
HandshakeWithRetry performs a handshake with retry logic based on configuration.
It implements exponential backoff for retry delays and respects context
cancellation.

#### func (*NoiseConn) LocalAddr

```go
func (nc *NoiseConn) LocalAddr() net.Addr
```
LocalAddr returns the local network address.

#### func (*NoiseConn) Read

```go
func (nc *NoiseConn) Read(b []byte) (int, error)
```
Read reads data from the connection. If the handshake is not complete, it will
return an error.

#### func (*NoiseConn) RemoteAddr

```go
func (nc *NoiseConn) RemoteAddr() net.Addr
```
RemoteAddr returns the remote network address.

#### func (*NoiseConn) SetDeadline

```go
func (nc *NoiseConn) SetDeadline(t time.Time) error
```
SetDeadline sets the read and write deadlines.

#### func (*NoiseConn) SetReadDeadline

```go
func (nc *NoiseConn) SetReadDeadline(t time.Time) error
```
SetReadDeadline sets the read deadline.

#### func (*NoiseConn) SetShutdownManager

```go
func (nc *NoiseConn) SetShutdownManager(sm *ShutdownManager)
```
SetShutdownManager sets the shutdown manager for this connection. If a shutdown
manager is set, the connection will be automatically registered for graceful
shutdown coordination.

#### func (*NoiseConn) SetWriteDeadline

```go
func (nc *NoiseConn) SetWriteDeadline(t time.Time) error
```
SetWriteDeadline sets the write deadline.

#### func (*NoiseConn) Write

```go
func (nc *NoiseConn) Write(b []byte) (int, error)
```
Write writes data to the connection. If the handshake is not complete, it will
return an error.

#### type NoiseListener

```go
type NoiseListener struct {
}
```

NoiseListener implements net.Listener for accepting Noise Protocol connections.
It wraps an underlying net.Listener and provides encrypted connections following
the Noise Protocol Framework specification.

#### func  ListenNoise

```go
func ListenNoise(network, addr string, config *ListenerConfig) (*NoiseListener, error)
```
ListenNoise creates a listener on the given address and wraps it with
NoiseListener. This is a convenience function that combines net.Listen and
NewNoiseListener. For more control over the underlying listener, use net.Listen
followed by NewNoiseListener.

#### func  NewNoiseListener

```go
func NewNoiseListener(underlying net.Listener, config *ListenerConfig) (*NoiseListener, error)
```
NewNoiseListener creates a new NoiseListener that wraps the underlying listener.
The listener will accept connections and wrap them in NoiseConn instances
configured as responders (non-initiators) using the provided configuration.

#### func  WrapListener

```go
func WrapListener(listener net.Listener, config *ListenerConfig) (*NoiseListener, error)
```
WrapListener wraps an existing net.Listener with NoiseListener. This is an alias
for NewNoiseListener for consistency with the transport API.

#### func (*NoiseListener) Accept

```go
func (nl *NoiseListener) Accept() (net.Conn, error)
```
Accept waits for and returns the next connection to the listener. The returned
connection is wrapped in a NoiseConn configured as a responder.

#### func (*NoiseListener) Addr

```go
func (nl *NoiseListener) Addr() net.Addr
```
Addr returns the listener's network address. This is a NoiseAddr that wraps the
underlying listener's address.

#### func (*NoiseListener) Close

```go
func (nl *NoiseListener) Close() error
```
Close closes the listener and prevents new connections from being accepted. Any
blocked Accept operations will be unblocked and return errors.

#### func (*NoiseListener) SetShutdownManager

```go
func (nl *NoiseListener) SetShutdownManager(sm *ShutdownManager)
```
SetShutdownManager sets the shutdown manager for this listener. If a shutdown
manager is set, the listener will be automatically registered for graceful
shutdown coordination.

#### type ShutdownManager

```go
type ShutdownManager struct {
}
```

ShutdownManager coordinates graceful shutdown of noise components. It provides
context-based cancellation and ensures proper resource cleanup with configurable
timeouts for graceful vs forceful shutdown.

#### func  GetGlobalShutdownManager

```go
func GetGlobalShutdownManager() *ShutdownManager
```
GetGlobalShutdownManager returns the current global shutdown manager.

#### func  NewShutdownManager

```go
func NewShutdownManager(timeout time.Duration) *ShutdownManager
```
NewShutdownManager creates a new shutdown manager with the given timeout. If
timeout is 0, a default of 30 seconds is used.

#### func (*ShutdownManager) Context

```go
func (sm *ShutdownManager) Context() context.Context
```
Context returns the shutdown context for monitoring shutdown signals. Components
can use this context to detect when shutdown has been initiated.

#### func (*ShutdownManager) RegisterConnection

```go
func (sm *ShutdownManager) RegisterConnection(conn *NoiseConn)
```
RegisterConnection adds a connection to be managed during shutdown. The
connection will be gracefully closed during shutdown.

#### func (*ShutdownManager) RegisterListener

```go
func (sm *ShutdownManager) RegisterListener(listener *NoiseListener)
```
RegisterListener adds a listener to be managed during shutdown. The listener
will be gracefully closed during shutdown.

#### func (*ShutdownManager) Shutdown

```go
func (sm *ShutdownManager) Shutdown() error
```
Shutdown initiates graceful shutdown of all managed components. It closes
listeners first, waits for connections to drain, then forcefully closes
remaining connections after the timeout period.

#### func (*ShutdownManager) UnregisterConnection

```go
func (sm *ShutdownManager) UnregisterConnection(conn *NoiseConn)
```
UnregisterConnection removes a connection from shutdown management. This should
be called when a connection is closed normally.

#### func (*ShutdownManager) UnregisterListener

```go
func (sm *ShutdownManager) UnregisterListener(listener *NoiseListener)
```
UnregisterListener removes a listener from shutdown management. This should be
called when a listener is closed normally.

#### func (*ShutdownManager) Wait

```go
func (sm *ShutdownManager) Wait()
```
Wait blocks until shutdown is complete. This can be used to wait for shutdown to
finish after calling Shutdown().



noise 

github.com/go-i2p/go-noise

[go-i2p template file](/template.md)
