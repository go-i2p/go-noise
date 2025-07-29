# internal
--
    import "github.com/go-i2p/go-noise/internal"

![internal.svg](internal.svg)



## Usage

#### func  RandomBytes

```go
func RandomBytes(n int) ([]byte, error)
```
RandomBytes generates cryptographically secure random bytes

#### func  SecureZero

```go
func SecureZero(b []byte)
```
SecureZero securely zeroes out the given byte slice

#### func  ValidateKeySize

```go
func ValidateKeySize(key []byte, expectedSize int) bool
```
ValidateKeySize validates that a key has the expected size

#### type ConnState

```go
type ConnState int
```

ConnState represents the internal state of a NoiseConn

```go
const (
	// StateInit represents a newly created connection
	StateInit ConnState = iota
	// StateHandshaking represents a connection performing handshake
	StateHandshaking
	// StateEstablished represents a connection with completed handshake
	StateEstablished
	// StateClosed represents a closed connection
	StateClosed
)
```

#### func (ConnState) String

```go
func (s ConnState) String() string
```
String returns the string representation of the connection state

#### type ConnectionMetrics

```go
type ConnectionMetrics struct {
	HandshakeStarted time.Time
	HandshakeEnded   time.Time
	BytesRead        int64
	BytesWritten     int64
	Created          time.Time
}
```

ConnectionMetrics holds connection performance metrics

#### func  NewConnectionMetrics

```go
func NewConnectionMetrics() *ConnectionMetrics
```
NewConnectionMetrics creates a new ConnectionMetrics instance

#### func (*ConnectionMetrics) AddBytesRead

```go
func (m *ConnectionMetrics) AddBytesRead(n int64)
```
AddBytesRead increments the bytes read counter

#### func (*ConnectionMetrics) AddBytesWritten

```go
func (m *ConnectionMetrics) AddBytesWritten(n int64)
```
AddBytesWritten increments the bytes written counter

#### func (*ConnectionMetrics) GetStats

```go
func (m *ConnectionMetrics) GetStats() (bytesRead, bytesWritten int64, duration time.Duration)
```
GetStats returns current connection statistics

#### func (*ConnectionMetrics) HandshakeDuration

```go
func (m *ConnectionMetrics) HandshakeDuration() time.Duration
```
HandshakeDuration returns the duration of the handshake process

#### func (*ConnectionMetrics) SetHandshakeEnd

```go
func (m *ConnectionMetrics) SetHandshakeEnd()
```
SetHandshakeEnd records the handshake completion time

#### func (*ConnectionMetrics) SetHandshakeStart

```go
func (m *ConnectionMetrics) SetHandshakeStart()
```
SetHandshakeStart records the handshake start time



internal 

github.com/go-i2p/go-noise/internal

[go-i2p template file](/template.md)
