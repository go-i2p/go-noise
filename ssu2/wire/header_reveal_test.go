package wire

import (
	"encoding/binary"
	"slices"
	"testing"
)

// Finding 012 addendum: a datagram a listener cannot deobfuscate is dropped with
// no trace, so a session's first data packet — which can arrive before the
// listener has that session's data-phase protector — was lost. The listener can
// still attribute such a datagram, because header protection splits its masks by
// key: bytes 0-7 (the destination connection ID) are masked with k_header_1,
// which for an inbound Data packet is the receiver's own introduction key. Only
// bytes 8-15 need the secret KDF-derived k_header_2.

// TestRevealDestConnID_RecoversConnIDWithIntroKeyOnly builds a Data datagram the
// way a peer would protect it (k_header_1 = OUR intro key, k_header_2 = a secret
// neither party's listener holds yet) and shows the destination connection ID is
// recoverable from the intro key alone.
func TestRevealDestConnID_RecoversConnIDWithIntroKeyOnly(t *testing.T) {
	const ourIntroKey = 0x5A
	ourIntro := fixedKey(ourIntroKey)
	secretKHeader2 := fixedKey(0x77) // recvDataHeader2: unknown to the listener

	sender := mustProtector(t, ourIntro, secretKHeader2, HeaderTypeData)

	datagram := buildProtectablePacket(ShortHeaderSize + 24 + 32)
	const wantConnID = uint64(0xDEADBEEF12345678)
	binary.BigEndian.PutUint64(datagram[0:8], wantConnID)
	datagram[12] = byte(MessageTypeData)

	if err := sender.EncryptHeader(datagram); err != nil {
		t.Fatalf("EncryptHeader error = %v", err)
	}
	if got := binary.BigEndian.Uint64(datagram[0:8]); got == wantConnID {
		t.Fatal("test is vacuous: header protection did not mask the destination connection ID")
	}

	// The listener's protector is built from its intro key alone, exactly as
	// initHeaderProtection builds it.
	listener, err := NewHeaderProtectorFromIntroKey(ourIntro, HeaderTypeSessionRequest)
	if err != nil {
		t.Fatalf("NewHeaderProtectorFromIntroKey error = %v", err)
	}

	got, ok := listener.RevealDestConnID(datagram)
	if !ok {
		t.Fatal("RevealDestConnID could not attribute the datagram from the intro key alone")
	}
	if got != wantConnID {
		t.Fatalf("revealed conn ID = %#x, want %#x", got, wantConnID)
	}
}

// TestRevealDestConnID_DoesNotMutateBuffer matters because the retained bytes are
// replayed later: header deobfuscation rewrites the datagram in place and has no
// integrity check of its own, so a reveal that also un-masked would leave the
// buffer half-transformed and the replay would double-unmask.
func TestRevealDestConnID_DoesNotMutateBuffer(t *testing.T) {
	ourIntro := fixedKey(0x11)
	sender := mustProtector(t, ourIntro, fixedKey(0x22), HeaderTypeData)

	datagram := buildProtectablePacket(ShortHeaderSize + 24 + 16)
	binary.BigEndian.PutUint64(datagram[0:8], 0x0102030405060708)
	datagram[12] = byte(MessageTypeData)
	if err := sender.EncryptHeader(datagram); err != nil {
		t.Fatalf("EncryptHeader error = %v", err)
	}

	before := slices.Clone(datagram)
	listener, err := NewHeaderProtectorFromIntroKey(ourIntro, HeaderTypeSessionRequest)
	if err != nil {
		t.Fatalf("NewHeaderProtectorFromIntroKey error = %v", err)
	}

	// Reveal twice: an idempotent read is what lets the cascade call this on the
	// caller's buffer without a defensive copy first.
	for range 2 {
		if _, ok := listener.RevealDestConnID(datagram); !ok {
			t.Fatal("RevealDestConnID failed")
		}
		if !slices.Equal(datagram, before) {
			t.Fatal("RevealDestConnID modified the datagram; the retained copy would be corrupted")
		}
	}
}

// TestRevealDestConnID_RejectsTooShort guards the buffer against a flood of
// undersized datagrams: without the 24-byte header-protection sample there is
// nothing to derive a mask from, and no attribution should be claimed.
func TestRevealDestConnID_RejectsTooShort(t *testing.T) {
	listener, err := NewHeaderProtectorFromIntroKey(fixedKey(0x33), HeaderTypeSessionRequest)
	if err != nil {
		t.Fatalf("NewHeaderProtectorFromIntroKey error = %v", err)
	}
	if _, ok := listener.RevealDestConnID(make([]byte, ShortHeaderSize+23)); ok {
		t.Fatal("a datagram without a full header-protection sample must not be attributed")
	}
}

// TestRevealDestConnID_WrongIntroKeyYieldsDifferentConnID shows attribution is
// key-scoped: a datagram addressed to a different listener's session does not
// resolve to that session's ID, so the cascade cannot be tricked into retaining
// traffic for a session it does not own.
func TestRevealDestConnID_WrongIntroKeyYieldsDifferentConnID(t *testing.T) {
	const wantConnID = uint64(0xCAFEBABE)
	sender := mustProtector(t, fixedKey(0x44), fixedKey(0x55), HeaderTypeData)

	datagram := buildProtectablePacket(ShortHeaderSize + 24 + 16)
	binary.BigEndian.PutUint64(datagram[0:8], wantConnID)
	datagram[12] = byte(MessageTypeData)
	if err := sender.EncryptHeader(datagram); err != nil {
		t.Fatalf("EncryptHeader error = %v", err)
	}

	other, err := NewHeaderProtectorFromIntroKey(fixedKey(0x99), HeaderTypeSessionRequest)
	if err != nil {
		t.Fatalf("NewHeaderProtectorFromIntroKey error = %v", err)
	}
	if got, ok := other.RevealDestConnID(datagram); !ok {
		t.Fatal("RevealDestConnID should still return a value for a foreign key")
	} else if got == wantConnID {
		t.Fatal("a foreign intro key must not resolve the real destination connection ID")
	}
}

// mustProtector builds a HeaderProtector for the tests in this file.
func mustProtector(t *testing.T, kHeader1, kHeader2 []byte, headerType HeaderType) *HeaderProtector {
	t.Helper()
	hp, err := NewHeaderProtector(kHeader1, kHeader2, headerType)
	if err != nil {
		t.Fatalf("NewHeaderProtector error = %v", err)
	}
	return hp
}
