# handshake
--
    import "github.com/go-i2p/go-noise/handshake"

![handshake.svg](handshake.svg)



## Usage

#### type HandshakeModifier

```go
type HandshakeModifier interface {
	// ModifyOutbound modifies data being sent during handshake
	ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error)

	// ModifyInbound modifies data being received during handshake
	ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error)

	// Name returns the modifier name for logging and debugging
	Name() string
}
```

HandshakeModifier defines the interface for modifying handshake data for
obfuscation and padding purposes. Modifiers can be chained to create complex
transformations while maintaining Noise protocol security.

#### type HandshakePhase

```go
type HandshakePhase int
```

HandshakePhase represents the phase of the handshake process

```go
const (
	// PhaseInitial represents the initial phase of the handshake
	PhaseInitial HandshakePhase = iota
	// PhaseExchange represents the message exchange phase
	PhaseExchange
	// PhaseFinal represents the final phase of the handshake
	PhaseFinal
)
```

#### func (HandshakePhase) String

```go
func (p HandshakePhase) String() string
```
String returns the string representation of the handshake phase

#### type ModifierChain

```go
type ModifierChain struct {
}
```

ModifierChain represents a chain of HandshakeModifier instances that are applied
in sequence. The chain ensures that modifiers are applied in the correct order
and provides error handling for the entire chain. Moved from: handshake/chain.go

#### func  NewModifierChain

```go
func NewModifierChain(name string, modifiers ...HandshakeModifier) *ModifierChain
```
NewModifierChain creates a new modifier chain with the given modifiers.
Modifiers are applied in the order they are provided.

#### func (*ModifierChain) Count

```go
func (mc *ModifierChain) Count() int
```
Count returns the number of modifiers in the chain.

#### func (*ModifierChain) IsEmpty

```go
func (mc *ModifierChain) IsEmpty() bool
```
IsEmpty returns true if the chain contains no modifiers.

#### func (*ModifierChain) ModifierNames

```go
func (mc *ModifierChain) ModifierNames() []string
```
ModifierNames returns the names of all modifiers in the chain.

#### func (*ModifierChain) ModifyInbound

```go
func (mc *ModifierChain) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error)
```
ModifyInbound applies all modifiers in the chain to inbound data. Modifiers are
applied in reverse order to undo the transformations applied during outbound
processing.

#### func (*ModifierChain) ModifyOutbound

```go
func (mc *ModifierChain) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error)
```
ModifyOutbound applies all modifiers in the chain to outbound data. Modifiers
are applied in the order they were added to the chain.

#### func (*ModifierChain) Name

```go
func (mc *ModifierChain) Name() string
```
Name returns the name of the modifier chain for logging and debugging.

#### type PaddingModifier

```go
type PaddingModifier struct {
}
```

PaddingModifier implements padding-based obfuscation by adding random padding to
handshake messages and removing it during processing. Moved from:
handshake/modifiers.go

#### func  NewPaddingModifier

```go
func NewPaddingModifier(name string, minPadding, maxPadding int) (*PaddingModifier, error)
```
NewPaddingModifier creates a new padding modifier with the specified minimum and
maximum padding sizes.

#### func (*PaddingModifier) ModifyInbound

```go
func (pm *PaddingModifier) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error)
```
ModifyInbound removes padding from inbound handshake data.

#### func (*PaddingModifier) ModifyOutbound

```go
func (pm *PaddingModifier) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error)
```
ModifyOutbound adds padding to outbound handshake data. Padding format:
[original_length:4][original_data][padding_data]

#### func (*PaddingModifier) Name

```go
func (pm *PaddingModifier) Name() string
```
Name returns the name of the padding modifier for logging and debugging.

#### type XORModifier

```go
type XORModifier struct {
}
```

XORModifier implements a simple XOR-based obfuscation modifier. It XORs
handshake data with a configurable key pattern to provide basic obfuscation
without compromising Noise protocol security. Moved from: handshake/modifiers.go

#### func  NewXORModifier

```go
func NewXORModifier(name string, xorKey []byte) *XORModifier
```
NewXORModifier creates a new XOR modifier with the specified key. The key is
repeated as needed to match the data length.

#### func (*XORModifier) ModifyInbound

```go
func (xm *XORModifier) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error)
```
ModifyInbound removes XOR obfuscation from inbound handshake data. Since XOR is
symmetric, this performs the same operation as ModifyOutbound.

#### func (*XORModifier) ModifyOutbound

```go
func (xm *XORModifier) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error)
```
ModifyOutbound applies XOR obfuscation to outbound handshake data.

#### func (*XORModifier) Name

```go
func (xm *XORModifier) Name() string
```
Name returns the name of the XOR modifier for logging and debugging.



handshake 

github.com/go-i2p/go-noise/handshake

[go-i2p template file](/template.md)
