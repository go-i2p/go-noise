package handshake

// XORModifier implements a simple XOR-based obfuscation modifier.
// It XORs handshake data with a configurable key pattern to provide
// basic obfuscation without compromising Noise protocol security.
// Moved from: handshake/modifiers.go
type XORModifier struct {
	name    string
	xorKey  []byte
	keySize int
}

// NewXORModifier creates a new XOR modifier with the specified key.
// The key is repeated as needed to match the data length.
func NewXORModifier(name string, xorKey []byte) *XORModifier {
	if len(xorKey) == 0 {
		xorKey = []byte{0xAA} // Default pattern if no key provided
	}

	// Make a copy to prevent external modification
	key := make([]byte, len(xorKey))
	copy(key, xorKey)

	return &XORModifier{
		name:    name,
		xorKey:  key,
		keySize: len(key),
	}
}

// ModifyOutbound applies XOR obfuscation to outbound handshake data.
func (xm *XORModifier) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ xm.xorKey[i%xm.keySize]
	}

	return result, nil
}

// ModifyInbound removes XOR obfuscation from inbound handshake data.
// Since XOR is symmetric, this performs the same operation as ModifyOutbound.
func (xm *XORModifier) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error) {
	return xm.ModifyOutbound(phase, data)
}

// Name returns the name of the XOR modifier for logging and debugging.
func (xm *XORModifier) Name() string {
	return xm.name
}
