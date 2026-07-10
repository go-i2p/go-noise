package baseconfig

import (
	"testing"
	"time"
)

func TestRoleString(t *testing.T) {
	if got := RoleString(true); got != "initiator" {
		t.Errorf("RoleString(true) = %q, want %q", got, "initiator")
	}
	if got := RoleString(false); got != "responder" {
		t.Errorf("RoleString(false) = %q, want %q", got, "responder")
	}
}

func TestSetHandshakeTimeout(t *testing.T) {
	base := &BaseHandshakeConfig{}
	SetHandshakeTimeout(base, 45*time.Second)
	if base.HandshakeTimeout != 45*time.Second {
		t.Errorf("HandshakeTimeout = %v, want %v", base.HandshakeTimeout, 45*time.Second)
	}
}

func TestSetReadTimeout(t *testing.T) {
	base := &BaseHandshakeConfig{}
	SetReadTimeout(base, 10*time.Second)
	if base.ReadTimeout != 10*time.Second {
		t.Errorf("ReadTimeout = %v, want %v", base.ReadTimeout, 10*time.Second)
	}
}

func TestSetWriteTimeout(t *testing.T) {
	base := &BaseHandshakeConfig{}
	SetWriteTimeout(base, 15*time.Second)
	if base.WriteTimeout != 15*time.Second {
		t.Errorf("WriteTimeout = %v, want %v", base.WriteTimeout, 15*time.Second)
	}
}

func TestSetHandshakeRetries(t *testing.T) {
	base := &BaseHandshakeConfig{}
	SetHandshakeRetries(base, 5)
	if base.HandshakeRetries != 5 {
		t.Errorf("HandshakeRetries = %d, want %d", base.HandshakeRetries, 5)
	}

	// -1 (infinite retries) is a documented valid value.
	SetHandshakeRetries(base, -1)
	if base.HandshakeRetries != -1 {
		t.Errorf("HandshakeRetries = %d, want %d", base.HandshakeRetries, -1)
	}
}

func TestSetRetryBackoff(t *testing.T) {
	base := &BaseHandshakeConfig{}
	SetRetryBackoff(base, 2*time.Second)
	if base.RetryBackoff != 2*time.Second {
		t.Errorf("RetryBackoff = %v, want %v", base.RetryBackoff, 2*time.Second)
	}
}

// TestDefaultHandshakeTimeout guards against an accidental change to the
// shared default used by every Noise config type's constructor.
func TestDefaultHandshakeTimeout(t *testing.T) {
	if DefaultHandshakeTimeout != 30*time.Second {
		t.Errorf("DefaultHandshakeTimeout = %v, want %v", DefaultHandshakeTimeout, 30*time.Second)
	}
}
