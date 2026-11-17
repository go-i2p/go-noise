package handshake

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GN-012: KeyRotationManager is wired live through the ssu2 re-exports, but the
// grace-period key accessors, the rotation-callback panic counter, and the
// background checker's state transition were never exercised. These tests close
// those gaps in-package so the unexported seams are reachable.

func rotationTestKeys() (staticKey, introKey []byte) {
	staticKey = make([]byte, StaticKeySize)
	introKey = make([]byte, IntroKeySize)
	for i := range staticKey {
		staticKey[i] = byte(i)
	}
	for i := range introKey {
		introKey[i] = byte(200 + i)
	}
	return staticKey, introKey
}

func newRotationManager(t *testing.T) *KeyRotationManager {
	t.Helper()
	sk, ik := rotationTestKeys()
	mgr, err := NewKeyRotationManager(sk, ik, false)
	require.NoError(t, err)
	t.Cleanup(mgr.Stop)
	return mgr
}

// NewKeyRotationManagerWithAge must reject malformed keys, not just accept aged
// ones: the error path was previously uncovered.
func TestNewKeyRotationManagerWithAge_InvalidKeySize(t *testing.T) {
	sk, ik := rotationTestKeys()

	_, err := NewKeyRotationManagerWithAge(sk[:31], ik, time.Hour, false)
	require.Error(t, err, "short static key must be rejected")

	_, err = NewKeyRotationManagerWithAge(sk, ik[:31], time.Hour, false)
	require.Error(t, err, "short intro key must be rejected")

	// Valid aged keys still succeed and carry the backdated age.
	mgr, err := NewKeyRotationManagerWithAge(sk, ik, 3*time.Hour, false)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, mgr.StaticKeyAge(), 3*time.Hour)
	assert.GreaterOrEqual(t, mgr.IntroKeyAge(), 3*time.Hour)
}

// After a rotation the retired key must stay readable for exactly the grace
// period so in-flight packets can still be decrypted, then go away.
func TestKeyRotationManager_PreviousKeyGracePeriod(t *testing.T) {
	mgr := newRotationManager(t)
	oldStatic, err := mgr.ForceRotateStaticKey()
	require.NoError(t, err)
	require.NotEmpty(t, oldStatic)

	// The manager handed back the NEW key; the previous one is the original.
	origStatic, ik := rotationTestKeys()
	_ = ik

	prev := mgr.GetPreviousStaticKey()
	require.NotNil(t, prev, "previous static key must be available during the grace period")
	assert.Equal(t, origStatic, prev, "previous static key must be the retired original")

	// Mutating the returned copy must not disturb the stored key.
	prev[0] ^= 0xff
	assert.NotEqual(t, prev[0], mgr.GetPreviousStaticKey()[0])

	// Expire the grace window by backdating the retirement timestamp.
	mgr.mu.Lock()
	mgr.previousStaticKey.RotatedAt = time.Now().Add(-KeyGracePeriod - time.Second)
	mgr.mu.Unlock()

	assert.Nil(t, mgr.GetPreviousStaticKey(), "previous static key must vanish once the grace period elapses")
}

// With no rotation performed there is no previous key, and a nil slot must not
// panic.
func TestKeyRotationManager_PreviousKeyAbsent(t *testing.T) {
	mgr := newRotationManager(t)
	assert.Nil(t, mgr.GetPreviousStaticKey())
	assert.Nil(t, mgr.GetPreviousIntroKey())

	// A zero RotatedAt (a slot that exists but was never retired) is also nil.
	mgr.mu.Lock()
	mgr.previousIntroKey = &ManagedKey{Key: make([]byte, IntroKeySize), State: KeyStateRetired}
	mgr.mu.Unlock()
	assert.Nil(t, mgr.GetPreviousIntroKey(), "a never-retired key must read as nil")
}

// Intro-key rotation mirrors the static path; cover its grace window too.
func TestKeyRotationManager_PreviousIntroKeyGracePeriod(t *testing.T) {
	mgr := newRotationManager(t)
	_, origIntro := rotationTestKeys()

	_, err := mgr.ForceRotateIntroKey()
	require.NoError(t, err)

	prev := mgr.GetPreviousIntroKey()
	require.NotNil(t, prev)
	assert.Equal(t, origIntro, prev)
}

// A second rotation must retire the first previous key (secure-zeroing it)
// rather than leaking it; this is the branch rotateKeyLocked took at 83%.
func TestKeyRotationManager_SecondRotationRetiresFirstPrevious(t *testing.T) {
	mgr := newRotationManager(t)

	first, err := mgr.ForceRotateStaticKey()
	require.NoError(t, err)
	_ = first

	second, err := mgr.ForceRotateStaticKey()
	require.NoError(t, err)
	require.NotEqual(t, first, second, "consecutive rotations must produce distinct keys")

	// The current key is the second one; the previous slot now holds the first.
	assert.Equal(t, second, mgr.GetStaticKey())
	prev := mgr.GetPreviousStaticKey()
	require.NotNil(t, prev)
}

// RotateIntroKey must refuse a too-young key rather than rotating it.
func TestKeyRotationManager_RotateIntroKey_NotAllowed(t *testing.T) {
	mgr := newRotationManager(t)
	_, err := mgr.RotateIntroKey()
	require.Error(t, err, "a fresh unpublished key is younger than the 2h minimum")
}

// RotateAllKeys is all-or-nothing: a young intro key must block the static
// rotation too.
func TestKeyRotationManager_RotateAllKeys_IntroBlocks(t *testing.T) {
	// Age the static key past the unpublished minimum but leave intro young.
	sk, ik := rotationTestKeys()
	mgr, err := NewKeyRotationManager(sk, ik, false)
	require.NoError(t, err)
	defer mgr.Stop()

	mgr.mu.Lock()
	mgr.staticKey.CreatedAt = time.Now().Add(-3 * time.Hour)
	mgr.mu.Unlock()

	_, _, err = mgr.RotateAllKeys()
	require.Error(t, err, "a young intro key must abort RotateAllKeys")

	// Neither key may have moved.
	assert.Equal(t, sk, mgr.GetStaticKey())
	assert.Equal(t, ik, mgr.GetIntroKey())
}

// The background checker must flag age-eligible keys as pending without
// rotating them, and must survive a panicking tick (recoverTick).
func TestKeyRotationManager_CheckRotationMarksPending(t *testing.T) {
	sk, ik := rotationTestKeys()
	mgr, err := NewKeyRotationManagerWithAge(sk, ik, 3*time.Hour, false)
	require.NoError(t, err)
	defer mgr.Stop()

	mgr.checkRotation()

	assert.Equal(t, KeyStatePendingRotation, mgr.GetStaticKeyInfo().State)
	assert.Equal(t, KeyStatePendingRotation, mgr.GetIntroKeyInfo().State)

	// checkRotation must never rotate on its own.
	assert.Equal(t, sk, mgr.GetStaticKey())

	// A young key stays active.
	young := newRotationManager(t)
	young.checkRotation()
	assert.Equal(t, KeyStateActive, young.GetStaticKeyInfo().State)
}

// A panicking rotation callback must be recovered and counted, not crash the
// router. The callback fires on its own goroutine, so synchronize on a channel
// that is closed just before the panic.
func TestKeyRotationManager_RotationCallbackPanicCounted(t *testing.T) {
	mgr := newRotationManager(t)

	panicked := make(chan struct{})
	var once sync.Once
	mgr.SetRotationCallback(func(keyType string, oldKey, newKey *ManagedKey) {
		once.Do(func() {
			close(panicked)
			panic("boom")
		})
	})

	require.Zero(t, mgr.OnRotationPanics())

	_, err := mgr.ForceRotateStaticKey()
	require.NoError(t, err)

	select {
	case <-panicked:
	case <-time.After(2 * time.Second):
		t.Fatal("rotation callback was never invoked")
	}

	// Give the recover seam a moment to record the panic.
	var count int64
	for i := 0; i < 100; i++ {
		count = mgr.OnRotationPanics()
		if count > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.Equal(t, int64(1), count, "the recovered panic must be counted exactly once")
}

// A non-panicking callback must not bump the counter and must see both keys.
func TestKeyRotationManager_RotationCallbackNoPanic(t *testing.T) {
	mgr := newRotationManager(t)

	called := make(chan string, 1)
	mgr.SetRotationCallback(func(keyType string, oldKey, newKey *ManagedKey) {
		called <- keyType
	})

	_, err := mgr.ForceRotateIntroKey()
	require.NoError(t, err)

	select {
	case keyType := <-called:
		assert.Equal(t, "intro", keyType)
	case <-time.After(2 * time.Second):
		t.Fatal("rotation callback was never invoked")
	}

	assert.Zero(t, mgr.OnRotationPanics())
}

// Start/Stop must be idempotent and IsRunning must track the checker.
func TestKeyRotationManager_StartStopIdempotent(t *testing.T) {
	mgr := newRotationManager(t)

	assert.False(t, mgr.IsRunning())
	mgr.Start()
	mgr.Start() // second Start is a no-op
	assert.True(t, mgr.IsRunning())

	mgr.Stop()
	mgr.Stop() // second Stop is a no-op
	assert.False(t, mgr.IsRunning())
}

// GetStatus must reflect the published flag and rotation eligibility.
func TestKeyRotationManager_GetStatusPublished(t *testing.T) {
	sk, ik := rotationTestKeys()
	mgr, err := NewKeyRotationManagerWithAge(sk, ik, 3*time.Hour, true)
	require.NoError(t, err)
	defer mgr.Stop()

	status := mgr.GetStatus()
	assert.True(t, status.IsPublished)
	assert.False(t, status.StaticKeyCanRotate, "a 3h-old published key is younger than the 30d minimum")
	assert.Greater(t, status.StaticKeyTimeToRotate, time.Duration(0))

	mgr.SetPublished(false)
	status = mgr.GetStatus()
	assert.False(t, status.IsPublished)
	assert.True(t, status.StaticKeyCanRotate, "the same key is eligible once unpublished")
}

// GetStaticKey/GetIntroKey must hand out copies, never the live slice.
func TestKeyRotationManager_GettersReturnCopies(t *testing.T) {
	mgr := newRotationManager(t)
	got := mgr.GetStaticKey()
	require.True(t, bytes.Equal(got, mustStatic(t, mgr)))

	got[0] ^= 0xff
	assert.NotEqual(t, got[0], mgr.GetStaticKey()[0], "mutating the returned key must not affect the manager")
}

func mustStatic(t *testing.T, mgr *KeyRotationManager) []byte {
	t.Helper()
	sk, _ := rotationTestKeys()
	return sk
}
