package handshake

import "testing"

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
