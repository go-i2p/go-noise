# shared
--
    import "github.com/go-i2p/go-noise/examples/ntcp2-shared"

![shared.svg](shared.svg)

Package shared provides NTCP2-specific utilities for go-noise examples

## Usage

#### func  ParseNTCP2Keys

```go
func ParseNTCP2Keys(args *NTCP2Args) (routerHash, remoteRouterHash, destHash, staticKey []byte, err error)
```
ParseNTCP2Keys handles parsing of NTCP2-specific cryptographic material

#### func  PrintNTCP2Usage

```go
func PrintNTCP2Usage(appName, description string)
```
PrintNTCP2Usage displays usage information for an NTCP2 example

#### func  RunNTCP2Demo

```go
func RunNTCP2Demo()
```
RunNTCP2Demo executes demonstration mode for NTCP2

#### func  RunNTCP2Generate

```go
func RunNTCP2Generate()
```
RunNTCP2Generate generates and displays NTCP2 cryptographic material

#### type NTCP2Args

```go
type NTCP2Args struct {
	// Network configuration
	ServerAddr string
	ClientAddr string

	// NTCP2-specific material
	RouterHash       string
	RemoteRouterHash string
	DestinationHash  string

	// Cryptographic keys (Curve25519)
	StaticKey string

	// Timeouts
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration

	// NTCP2 features
	EnableAESObfuscation bool
	EnableSipHashLength  bool
	MaxFrameSize         int

	// Operation modes
	Demo     bool
	Generate bool
	Verbose  bool
}
```

NTCP2Args holds NTCP2-specific command-line arguments

#### func  ParseNTCP2Args

```go
func ParseNTCP2Args(appName string) (*NTCP2Args, error)
```
ParseNTCP2Args parses NTCP2-specific command-line arguments

#### func (*NTCP2Args) ValidateArgs

```go
func (args *NTCP2Args) ValidateArgs() error
```
ValidateNTCP2Args performs validation on parsed NTCP2 arguments



shared 

github.com/go-i2p/go-noise/examples/ntcp2-shared

[go-i2p template file](/template.md)
