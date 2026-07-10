package wire

import (
	"testing"
)

func TestNewHeaderProtectorManager_InvalidIntroKey(t *testing.T) {
	short := make([]byte, HeaderKeySize-1)
	if _, err := NewHeaderProtectorManager(short, fixedKey(1), true); err == nil {
		t.Error("expected error for short introKey")
	}
}

func TestNewHeaderProtectorManager_NilRemoteIntroKeyAllowed(t *testing.T) {
	// remoteIntroKey may be nil (e.g. for listeners that haven't learned the
	// peer's intro key yet).
	hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hpm == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestHeaderProtectorManager_GetProtectorForType_SessionRequest(t *testing.T) {
	t.Run("initiator requires remote intro key", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeSessionRequest); err == nil {
			t.Error("expected error: initiator missing remote intro key")
		}
	})

	t.Run("initiator with remote intro key succeeds", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeSessionRequest); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("responder uses local intro key", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeSessionRequest); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestHeaderProtectorManager_GetProtectorForType_TokenRequest(t *testing.T) {
	// TokenRequest shares keysForIntroProtected with SessionRequest.
	hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := hpm.GetProtectorForType(HeaderTypeTokenRequest); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHeaderProtectorManager_GetProtectorForType_HolePunch(t *testing.T) {
	t.Run("missing remote intro key fails", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeHolePunch); err == nil {
			t.Error("expected error: HolePunch requires remote intro key")
		}
	})

	t.Run("with remote intro key succeeds", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeHolePunch); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestHeaderProtectorManager_GetProtectorForType_Retry(t *testing.T) {
	t.Run("initiator requires remote intro key", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeRetry); err == nil {
			t.Error("expected error: initiator missing remote intro key for Retry")
		}
	})

	t.Run("responder uses local intro key for both", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeRetry); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestHeaderProtectorManager_GetProtectorForType_SessionCreated(t *testing.T) {
	t.Run("missing SessCreateHeader KDF key fails", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeSessionCreated); err == nil {
			t.Error("expected error: SessionCreated requires SessCreateHeader KDF key")
		}
	})

	t.Run("with SessCreateHeader key succeeds", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := hpm.SetSessCreateHeaderKey(fixedKey(9)); err != nil {
			t.Fatalf("SetSessCreateHeaderKey error = %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeSessionCreated); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestHeaderProtectorManager_GetProtectorForType_SessionConfirmed(t *testing.T) {
	t.Run("missing SessionConfirmed KDF key fails", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeSessionConfirmed); err == nil {
			t.Error("expected error: SessionConfirmed requires KDF key")
		}
	})

	t.Run("initiator missing remote intro key (bik) fails", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = hpm.SetSessionConfirmedHeaderKey(fixedKey(9))
		if _, err := hpm.GetProtectorForType(HeaderTypeSessionConfirmed); err == nil {
			t.Error("expected error: initiator missing remote intro key (bik)")
		}
	})

	t.Run("with all required keys succeeds (initiator)", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := hpm.SetSessionConfirmedHeaderKey(fixedKey(9)); err != nil {
			t.Fatalf("SetSessionConfirmedHeaderKey error = %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeSessionConfirmed); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("with all required keys succeeds (responder)", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := hpm.SetSessionConfirmedHeaderKey(fixedKey(9)); err != nil {
			t.Fatalf("SetSessionConfirmedHeaderKey error = %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeSessionConfirmed); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestHeaderProtectorManager_GetProtectorForType_Data(t *testing.T) {
	t.Run("missing remote intro key fails", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeData); err == nil {
			t.Error("expected error: Data requires remote intro key for k_header_1")
		}
	})

	t.Run("missing send KDF key fails", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeData); err == nil {
			t.Error("expected error: Data requires send k_header_2")
		}
	})

	t.Run("with all keys succeeds", func(t *testing.T) {
		hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := hpm.SetKDFKeys(fixedKey(3), fixedKey(4)); err != nil {
			t.Fatalf("SetKDFKeys error = %v", err)
		}
		if _, err := hpm.GetProtectorForType(HeaderTypeData); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestHeaderProtectorManager_GetProtectorForType_PeerTest_NotSupported(t *testing.T) {
	hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := hpm.GetProtectorForType(HeaderTypePeerTest); err == nil {
		t.Error("expected PeerTest to be unsupported via GetProtectorForType")
	}
}

func TestHeaderProtectorManager_GetProtectorForType_UnknownType(t *testing.T) {
	hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := hpm.GetProtectorForType(HeaderType(999)); err == nil {
		t.Error("expected error for unknown header type")
	}
}

func TestHeaderProtectorManager_SetKDFKeys_InvalidSizes(t *testing.T) {
	hpm, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	short := make([]byte, HeaderKeySize-1)
	if err := hpm.SetKDFKeys(short, fixedKey(2)); err == nil {
		t.Error("expected error for short sendKH2")
	}
	if err := hpm.SetKDFKeys(fixedKey(1), short); err == nil {
		t.Error("expected error for short recvKH2")
	}
}

func TestHeaderProtectorManager_SetRemoteIntroKey_InvalidSize(t *testing.T) {
	hpm, err := NewHeaderProtectorManager(fixedKey(1), nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	short := make([]byte, HeaderKeySize-1)
	if err := hpm.SetRemoteIntroKey(short); err == nil {
		t.Error("expected error for short remote intro key")
	}
	if err := hpm.SetRemoteIntroKey(fixedKey(5)); err != nil {
		t.Errorf("unexpected error for valid key: %v", err)
	}
}

func TestHeaderProtectorManager_EncryptOutboundHeader_And_DecryptInboundHeader(t *testing.T) {
	// Two managers representing initiator and responder, mirroring keys so
	// an outbound Data packet encrypted by one is decryptable by the other.
	initiator, err := NewHeaderProtectorManager(fixedKey(1), fixedKey(2), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := initiator.SetKDFKeys(fixedKey(3), fixedKey(4)); err != nil {
		t.Fatalf("SetKDFKeys error = %v", err)
	}

	responder, err := NewHeaderProtectorManager(fixedKey(2), fixedKey(1), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Responder's inbound (recv) keys must mirror initiator's outbound (send) keys.
	if err := responder.SetKDFKeys(fixedKey(4), fixedKey(3)); err != nil {
		t.Fatalf("SetKDFKeys error = %v", err)
	}

	packet := buildProtectablePacket(ShortHeaderSize + 24)
	original := append([]byte{}, packet...)

	if err := initiator.EncryptOutboundHeader(packet, HeaderTypeData); err != nil {
		t.Fatalf("EncryptOutboundHeader error = %v", err)
	}

	if err := responder.DecryptInboundHeader(packet, HeaderTypeData); err != nil {
		t.Fatalf("DecryptInboundHeader error = %v", err)
	}

	for i := 0; i < ShortHeaderSize; i++ {
		if packet[i] != original[i] {
			t.Fatalf("byte %d: got %#x, want %#x (round-trip mismatch)", i, packet[i], original[i])
		}
	}
}
