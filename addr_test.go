package noise

import (
	"net"
	"testing"
)

func TestNewNoiseAddr(t *testing.T) {
	tests := []struct {
		name       string
		underlying net.Addr
		pattern    string
		role       string
	}{
		{
			name:       "TCP underlying address",
			underlying: &mockNetAddr{network: "tcp", address: "192.168.1.1:8080"},
			pattern:    "XX",
			role:       "initiator",
		},
		{
			name:       "UDP underlying address",
			underlying: &mockNetAddr{network: "udp", address: "10.0.0.1:9000"},
			pattern:    "NN",
			role:       "responder",
		},
		{
			name:       "Unix socket address",
			underlying: &mockNetAddr{network: "unix", address: "/tmp/socket"},
			pattern:    "IK",
			role:       "initiator",
		},
		{
			name:       "Nil underlying address",
			underlying: nil,
			pattern:    "XX",
			role:       "responder",
		},
		{
			name:       "Empty pattern",
			underlying: &mockNetAddr{network: "tcp", address: "127.0.0.1:8000"},
			pattern:    "",
			role:       "initiator",
		},
		{
			name:       "Empty role",
			underlying: &mockNetAddr{network: "tcp", address: "127.0.0.1:8000"},
			pattern:    "XX",
			role:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := NewNoiseAddr(tt.underlying, tt.pattern, tt.role)

			if addr == nil {
				t.Errorf("NewNoiseAddr should not return nil")
				return
			}

			if addr.underlying != tt.underlying {
				t.Errorf("Underlying address not set correctly")
			}

			if addr.pattern != tt.pattern {
				t.Errorf("Expected pattern %s, got %s", tt.pattern, addr.pattern)
			}

			if addr.role != tt.role {
				t.Errorf("Expected role %s, got %s", tt.role, addr.role)
			}
		})
	}
}

func TestNoiseAddrNetwork(t *testing.T) {
	tests := []struct {
		name            string
		underlying      net.Addr
		expectedNetwork string
	}{
		{
			name:            "TCP network",
			underlying:      &mockNetAddr{network: "tcp", address: "192.168.1.1:8080"},
			expectedNetwork: "noise+tcp",
		},
		{
			name:            "UDP network",
			underlying:      &mockNetAddr{network: "udp", address: "10.0.0.1:9000"},
			expectedNetwork: "noise+udp",
		},
		{
			name:            "Unix network",
			underlying:      &mockNetAddr{network: "unix", address: "/tmp/socket"},
			expectedNetwork: "noise+unix",
		},
		{
			name:            "Custom network",
			underlying:      &mockNetAddr{network: "custom", address: "address"},
			expectedNetwork: "noise+custom",
		},
		{
			name:            "Nil underlying",
			underlying:      nil,
			expectedNetwork: "noise",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := NewNoiseAddr(tt.underlying, "XX", "initiator")

			network := addr.Network()
			if network != tt.expectedNetwork {
				t.Errorf("Expected network %s, got %s", tt.expectedNetwork, network)
			}
		})
	}
}

func TestNoiseAddrString(t *testing.T) {
	tests := []struct {
		name           string
		underlying     net.Addr
		pattern        string
		role           string
		expectedString string
	}{
		{
			name:           "Complete address with TCP",
			underlying:     &mockNetAddr{network: "tcp", address: "192.168.1.1:8080"},
			pattern:        "XX",
			role:           "initiator",
			expectedString: "noise://XX/initiator/192.168.1.1:8080",
		},
		{
			name:           "Complete address with UDP",
			underlying:     &mockNetAddr{network: "udp", address: "10.0.0.1:9000"},
			pattern:        "NN",
			role:           "responder",
			expectedString: "noise://NN/responder/10.0.0.1:9000",
		},
		{
			name:           "Full pattern name",
			underlying:     &mockNetAddr{network: "tcp", address: "127.0.0.1:8000"},
			pattern:        "Noise_XX_25519_AESGCM_SHA256",
			role:           "initiator",
			expectedString: "noise://Noise_XX_25519_AESGCM_SHA256/initiator/127.0.0.1:8000",
		},
		{
			name:           "Unix socket",
			underlying:     &mockNetAddr{network: "unix", address: "/tmp/noise.sock"},
			pattern:        "IK",
			role:           "responder",
			expectedString: "noise://IK/responder//tmp/noise.sock",
		},
		{
			name:           "Nil underlying address",
			underlying:     nil,
			pattern:        "XX",
			role:           "initiator",
			expectedString: "noise://XX/initiator",
		},
		{
			name:           "Empty pattern",
			underlying:     &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"},
			pattern:        "",
			role:           "initiator",
			expectedString: "noise:///initiator/127.0.0.1:8080",
		},
		{
			name:           "Empty role",
			underlying:     &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"},
			pattern:        "XX",
			role:           "",
			expectedString: "noise://XX//127.0.0.1:8080",
		},
		{
			name:           "Empty pattern and role with nil underlying",
			underlying:     nil,
			pattern:        "",
			role:           "",
			expectedString: "noise:///",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := NewNoiseAddr(tt.underlying, tt.pattern, tt.role)

			addrString := addr.String()
			if addrString != tt.expectedString {
				t.Errorf("Expected string %s, got %s", tt.expectedString, addrString)
			}
		})
	}
}

func TestNoiseAddrPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{
			name:    "XX pattern",
			pattern: "XX",
		},
		{
			name:    "Full pattern name",
			pattern: "Noise_XX_25519_AESGCM_SHA256",
		},
		{
			name:    "NN pattern",
			pattern: "NN",
		},
		{
			name:    "Empty pattern",
			pattern: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underlying := &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"}
			addr := NewNoiseAddr(underlying, tt.pattern, "initiator")

			pattern := addr.Pattern()
			if pattern != tt.pattern {
				t.Errorf("Expected pattern %s, got %s", tt.pattern, pattern)
			}
		})
	}
}

func TestNoiseAddrRole(t *testing.T) {
	tests := []struct {
		name string
		role string
	}{
		{
			name: "Initiator role",
			role: "initiator",
		},
		{
			name: "Responder role",
			role: "responder",
		},
		{
			name: "Custom role",
			role: "custom_role",
		},
		{
			name: "Empty role",
			role: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underlying := &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"}
			addr := NewNoiseAddr(underlying, "XX", tt.role)

			role := addr.Role()
			if role != tt.role {
				t.Errorf("Expected role %s, got %s", tt.role, role)
			}
		})
	}
}

func TestNoiseAddrUnderlying(t *testing.T) {
	tests := []struct {
		name       string
		underlying net.Addr
	}{
		{
			name:       "TCP address",
			underlying: &mockNetAddr{network: "tcp", address: "192.168.1.1:8080"},
		},
		{
			name:       "UDP address",
			underlying: &mockNetAddr{network: "udp", address: "10.0.0.1:9000"},
		},
		{
			name:       "Unix address",
			underlying: &mockNetAddr{network: "unix", address: "/tmp/socket"},
		},
		{
			name:       "Nil address",
			underlying: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := NewNoiseAddr(tt.underlying, "XX", "initiator")

			underlying := addr.Underlying()
			if underlying != tt.underlying {
				t.Errorf("Expected underlying address %v, got %v", tt.underlying, underlying)
			}
		})
	}
}

// TestNoiseAddrNetAddrInterface verifies that NoiseAddr implements net.Addr
func TestNoiseAddrNetAddrInterface(t *testing.T) {
	var _ net.Addr = (*NoiseAddr)(nil)
}

// TestNoiseAddrConcurrency tests concurrent access to NoiseAddr methods
func TestNoiseAddrConcurrency(t *testing.T) {
	underlying := &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"}
	addr := NewNoiseAddr(underlying, "XX", "initiator")

	// Run concurrent access to all methods
	done := make(chan bool, 4)

	go func() {
		for i := 0; i < 100; i++ {
			_ = addr.Network()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = addr.String()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = addr.Pattern()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = addr.Role()
		}
		done <- true
	}()

	// Wait for all goroutines to complete
	for i := 0; i < 4; i++ {
		<-done
	}

	// Test should complete without race conditions or panics
}

// TestNoiseAddrEquality tests address comparison scenarios
func TestNoiseAddrEquality(t *testing.T) {
	underlying1 := &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"}
	underlying2 := &mockNetAddr{network: "tcp", address: "127.0.0.1:8080"}

	addr1 := NewNoiseAddr(underlying1, "XX", "initiator")
	addr2 := NewNoiseAddr(underlying2, "XX", "initiator")
	addr3 := NewNoiseAddr(underlying1, "NN", "initiator")
	addr4 := NewNoiseAddr(underlying1, "XX", "responder")

	// Test string representation equality
	if addr1.String() != addr2.String() {
		t.Errorf("Addresses with same values should have same string representation")
	}

	if addr1.String() == addr3.String() {
		t.Errorf("Addresses with different patterns should have different string representation")
	}

	if addr1.String() == addr4.String() {
		t.Errorf("Addresses with different roles should have different string representation")
	}

	// Test network equality
	if addr1.Network() != addr2.Network() {
		t.Errorf("Addresses with same underlying network should have same network")
	}
}
