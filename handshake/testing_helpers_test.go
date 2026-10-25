package handshake

import (
	"errors"
	"testing"

	"github.com/go-i2p/crypto/rand"
)

// assertModifierRoundTrip verifies that outbound+inbound modification
// through a chain recovers the original data.
func assertModifierRoundTrip(t *testing.T, chain *ModifierChain, phase HandshakePhase, originalData []byte) {
	t.Helper()
	outbound, err := chain.ModifyOutbound(phase, originalData)
	if err != nil {
		t.Errorf("ModifyOutbound() error = %v", err)
	}
	if string(outbound) == string(originalData) {
		t.Error("Outbound data should be transformed, but it's unchanged")
	}
	recovered, err := chain.ModifyInbound(phase, outbound)
	if err != nil {
		t.Errorf("ModifyInbound() error = %v", err)
	}
	if string(recovered) != string(originalData) {
		t.Errorf("Round-trip failed: got %v, want %v", string(recovered), string(originalData))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-local modifier implementations.
//
// The package previously shipped [XORModifier] and [GenericPaddingModifier] as
// production types. Both were removed as spec-noncompliant:
//
//   - ntcp2.md §"Additions to the Framework" enumerates exactly five NTCP2
//     extensions (AES obfuscation, cleartext/AEAD padding, 2-byte frame length,
//     SipHash length obfuscation, payload format). None is a whole-message XOR,
//     and the only XOR the spec defines is the SipHash-derived frame-length mask
//     (§"SipHash obfuscated length").
//   - The generic padding modifier framed data as "[4-byte big-endian length]
//     [data][padding]", a layout no I2P specification defines; ntcp2.md
//     §"Session Request" gives message 1 the layout AES(X) ‖ AEAD ‖ padding with
//     no length prefix ("Message 1 and 2 AEAD frames are fixed length").
//
// The modifier-chain tests below still need concrete, reversible transforms to
// exercise chaining, ordering, and close propagation, so those fixtures live here
// as test-only types rather than in the shipped API.
// ─────────────────────────────────────────────────────────────────────────────

// xorModifier XORs every byte with a repeating key. Involutive, so the same
// transform both applies and removes it.
type xorModifier struct {
	name    string
	key     []byte
	closed  bool
	closeFn func() error
}

func newTestXORModifier(name string, key []byte) (*xorModifier, error) {
	if len(key) == 0 {
		return nil, errors.New("xor key must not be empty")
	}
	return &xorModifier{name: name, key: append([]byte(nil), key...)}, nil
}

func (xm *xorModifier) ModifyOutbound(_ HandshakePhase, data []byte) ([]byte, error) {
	return xm.xor(data), nil
}

func (xm *xorModifier) ModifyInbound(_ HandshakePhase, data []byte) ([]byte, error) {
	return xm.xor(data), nil
}

func (xm *xorModifier) xor(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ xm.key[i%len(xm.key)]
	}
	return out
}

func (xm *xorModifier) Name() string { return xm.name }

func (xm *xorModifier) Close() error {
	xm.closed = true
	if xm.closeFn != nil {
		return xm.closeFn()
	}
	return nil
}

// paddingModifier appends a fixed-size random pad plus a one-byte length suffix,
// and strips it on the inbound side.
type paddingModifier struct {
	name    string
	min     int
	max     int
	closed  bool
	closeFn func() error
}

func newTestPaddingModifier(name string, minPadding, maxPadding int) (*paddingModifier, error) {
	if minPadding < 0 || maxPadding < minPadding {
		return nil, errors.New("invalid padding range")
	}
	return &paddingModifier{name: name, min: minPadding, max: maxPadding}, nil
}

func (pm *paddingModifier) ModifyOutbound(_ HandshakePhase, data []byte) ([]byte, error) {
	n := pm.min
	if pm.max > pm.min {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		n = pm.min + int(b[0])%(pm.max-pm.min+1)
	}
	pad := make([]byte, n)
	if _, err := rand.Read(pad); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(data)+n+1)
	out = append(out, data...)
	out = append(out, pad...)
	out = append(out, byte(n))
	return out, nil
}

func (pm *paddingModifier) ModifyInbound(_ HandshakePhase, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	n := int(data[len(data)-1])
	if n+1 > len(data) {
		return nil, errors.New("padding length exceeds data")
	}
	return append([]byte(nil), data[:len(data)-n-1]...), nil
}

func (pm *paddingModifier) Name() string { return pm.name }

func (pm *paddingModifier) Close() error {
	pm.closed = true
	if pm.closeFn != nil {
		return pm.closeFn()
	}
	return nil
}
