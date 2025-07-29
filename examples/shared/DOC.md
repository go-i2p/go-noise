# shared
--
    import "github.com/go-i2p/go-noise/examples/shared"

![shared.svg](shared.svg)

Package shared provides common utilities for go-noise examples


Package shared provides common utilities for go-noise examples

Package shared provides common utilities for go-noise examples

Package shared provides common utilities for go-noise examples

## Usage

```go
var PatternsRequiringLocalKey = map[string]bool{
	"K": true, "X": true,
	"XK": true, "XX": true,
	"KN": true, "KK": true, "KX": true,
	"IK": true, "IX": true,
}
```
PatternsRequiringLocalKey returns patterns that require a static key for the
local party

```go
var PatternsRequiringRemoteKey = map[string]bool{
	"K": true, "NK": true,
	"XK": true, "KN": true, "KK": true, "KX": true,
	"IK": true, "IN": true,
}
```
PatternsRequiringRemoteKey returns patterns that require a remote static key

```go
var SupportedPatterns = []string{

	"N", "K", "X",

	"NN", "NK", "NX",
	"XN", "XK", "XX",
	"KN", "KK", "KX",
	"IN", "IK", "IX",
}
```
SupportedPatterns lists all standard Noise Protocol patterns

#### func  GenerateKeyPair

```go
func GenerateKeyPair() (localKey, remoteKey []byte, err error)
```
GenerateKeyPair generates a pair of keys for testing (static key and remote key)

#### func  GenerateRandomKey

```go
func GenerateRandomKey() ([]byte, error)
```
GenerateRandomKey generates a random 32-byte Curve25519 private key for testing

#### func  GetPatternRequirements

```go
func GetPatternRequirements(pattern string) (needsLocal, needsRemote bool)
```
GetPatternRequirements returns the key requirements for a pattern

#### func  KeyToHex

```go
func KeyToHex(key []byte) string
```
KeyToHex converts a 32-byte key to a hex string for display/storage

#### func  ParseKeyFromHex

```go
func ParseKeyFromHex(keyStr string) ([]byte, error)
```
ParseKeyFromHex parses a hexadecimal string into a 32-byte key

#### func  ParseKeys

```go
func ParseKeys(args *CommonArgs) (staticKey, remoteKey []byte, err error)
```
ParseKeys parses cryptographic keys based on pattern requirements for general
Noise examples

#### func  PrintKeys

```go
func PrintKeys(localKey, remoteKey []byte)
```
PrintKeys displays keys in a user-friendly format

#### func  PrintUsage

```go
func PrintUsage(appName, description string)
```
PrintUsage displays usage information for a Noise example

#### func  RequiresLocalStaticKey

```go
func RequiresLocalStaticKey(pattern string) bool
```
RequiresLocalStaticKey returns true if the pattern requires a local static key

#### func  RequiresRemoteStaticKey

```go
func RequiresRemoteStaticKey(pattern string) bool
```
RequiresRemoteStaticKey returns true if the pattern requires a remote static key

#### func  RunDemo

```go
func RunDemo()
```
RunDemo executes demonstration mode showing supported patterns and
configurations

#### func  RunGenerate

```go
func RunGenerate()
```
RunGenerate generates and displays cryptographic keys for testing

#### func  ValidatePattern

```go
func ValidatePattern(pattern string) error
```
ValidatePattern checks if a pattern is supported

#### type CommonArgs

```go
type CommonArgs struct {
	// Network configuration
	ServerAddr string
	ClientAddr string
	Pattern    string

	// Cryptographic material
	StaticKey string
	RemoteKey string

	// Timeouts
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration

	// Operation modes
	Demo     bool
	Generate bool
	Verbose  bool
}
```

CommonArgs holds common command-line arguments for Noise examples

#### func  ParseCommonArgs

```go
func ParseCommonArgs(appName string) (*CommonArgs, error)
```
ParseCommonArgs parses standard command-line arguments for Noise examples

#### func (*CommonArgs) ValidateArgs

```go
func (args *CommonArgs) ValidateArgs() error
```
ValidateArgs performs validation on parsed arguments



shared 

github.com/go-i2p/go-noise/examples/shared

[go-i2p template file](/template.md)
