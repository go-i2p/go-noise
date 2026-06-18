package handshake

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/internal/securemem"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

type KeyRotationCallback func(keyType string, oldKey, newKey *ManagedKey)

// KeyRotationManager manages SSU2 key lifecycle and rotation.
// It tracks static keys and introduction keys, ensuring they meet
// the minimum age requirements before rotation per the SSU2 specification.
type KeyRotationManager struct {
	mu sync.RWMutex

	// staticKey is the current static key for Noise XK handshakes.
	staticKey *ManagedKey

	// introKey is the current introduction key for header encryption.
	introKey *ManagedKey

	// previousStaticKey is the retired static key kept during the grace
	// period for decrypting in-flight packets.
	previousStaticKey *ManagedKey

	// previousIntroKey is the retired intro key kept during the grace period.
	previousIntroKey *ManagedKey

	// onRotation is called when a key rotation occurs.
	onRotation KeyRotationCallback

	// stopCh signals the background checker to stop.
	stopCh chan struct{}

	// running indicates if the background checker is active.
	running bool

	// clock allows time mocking for testing.
	clock func() time.Time
}

// NewKeyRotationManager creates a new key rotation manager.
// staticKey and introKey are the initial keys (32 bytes each).
// isPublished indicates if these keys are published in router addresses.
func NewKeyRotationManager(staticKey, introKey []byte, isPublished bool) (*KeyRotationManager, error) {
	flog("NewKeyRotationManager", logger.Fields{"isPublished": isPublished}).Debug("Creating new KeyRotationManager")
	if len(staticKey) != StaticKeySize {
		return nil, oops.
			In("handshake").
			With("expected", StaticKeySize).
			With("actual", len(staticKey)).
			Errorf("static key must be exactly %d bytes", StaticKeySize)
	}

	if len(introKey) != IntroKeySize {
		return nil, oops.
			In("handshake").
			With("expected", IntroKeySize).
			With("actual", len(introKey)).
			Errorf("intro key must be exactly %d bytes", IntroKeySize)
	}

	now := time.Now()

	// Create managed keys with defensive copies
	sk := make([]byte, StaticKeySize)
	copy(sk, staticKey)
	ik := make([]byte, IntroKeySize)
	copy(ik, introKey)

	return &KeyRotationManager{
		staticKey: &ManagedKey{
			Key:         sk,
			CreatedAt:   now,
			State:       KeyStateActive,
			IsPublished: isPublished,
		},
		introKey: &ManagedKey{
			Key:         ik,
			CreatedAt:   now,
			State:       KeyStateActive,
			IsPublished: isPublished,
		},
		stopCh: make(chan struct{}),
		clock:  time.Now,
	}, nil
}

// NewKeyRotationManagerWithAge creates a manager with keys that have a specified age.
// This is useful for restoring keys from persistent storage.
func NewKeyRotationManagerWithAge(
	staticKey, introKey []byte,
	keyAge time.Duration,
	isPublished bool,
) (*KeyRotationManager, error) {
	flog("NewKeyRotationManagerWithAge", logger.Fields{"keyAge": keyAge, "isPublished": isPublished}).Debug("NewKeyRotationManagerWithAge: creating manager with pre-aged keys")
	mgr, err := NewKeyRotationManager(staticKey, introKey, isPublished)
	if err != nil {
		return nil, err
	}

	// Backdate the creation time
	createdAt := time.Now().Add(-keyAge)
	mgr.staticKey.CreatedAt = createdAt
	mgr.introKey.CreatedAt = createdAt

	return mgr, nil
}

// SetRotationCallback sets the callback to be invoked on key rotations.
func (krm *KeyRotationManager) SetRotationCallback(cb KeyRotationCallback) {
	krm.mu.Lock()
	defer krm.mu.Unlock()
	krm.onRotation = cb
}

// GetStaticKey returns a copy of the current static key.
func (krm *KeyRotationManager) GetStaticKey() []byte {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	key := make([]byte, len(krm.staticKey.Key))
	copy(key, krm.staticKey.Key)
	return key
}

// GetIntroKey returns a copy of the current introduction key.
func (krm *KeyRotationManager) GetIntroKey() []byte {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	key := make([]byte, len(krm.introKey.Key))
	copy(key, krm.introKey.Key)
	return key
}

// getPreviousKey returns a copy of a previous managed key if it is still
// within the grace period after rotation. Returns nil otherwise.
// Caller must NOT hold krm.mu.
func (krm *KeyRotationManager) getPreviousKey(mk *ManagedKey) []byte {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if mk == nil || mk.RotatedAt.IsZero() {
		return nil
	}
	if time.Since(mk.RotatedAt) > KeyGracePeriod {
		return nil
	}
	key := make([]byte, len(mk.Key))
	copy(key, mk.Key)
	return key
}

// GetPreviousStaticKey returns a copy of the previous static key if it is
// still within the grace period after rotation. Returns nil if no previous
// key exists or the grace period has elapsed.
func (krm *KeyRotationManager) GetPreviousStaticKey() []byte {
	return krm.getPreviousKey(krm.previousStaticKey)
}

// GetPreviousIntroKey returns a copy of the previous intro key if it is
// still within the grace period after rotation. Returns nil otherwise.
func (krm *KeyRotationManager) GetPreviousIntroKey() []byte {
	return krm.getPreviousKey(krm.previousIntroKey)
}

// GetStaticKeyInfo returns rotation metadata for the static key.
func (krm *KeyRotationManager) GetStaticKeyInfo() ManagedKey {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	// Return a copy without the actual key bytes for safety
	return ManagedKey{
		CreatedAt:   krm.staticKey.CreatedAt,
		State:       krm.staticKey.State,
		IsPublished: krm.staticKey.IsPublished,
		RotatedAt:   krm.staticKey.RotatedAt,
	}
}

// GetIntroKeyInfo returns rotation metadata for the introduction key.
func (krm *KeyRotationManager) GetIntroKeyInfo() ManagedKey {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	return ManagedKey{
		CreatedAt:   krm.introKey.CreatedAt,
		State:       krm.introKey.State,
		IsPublished: krm.introKey.IsPublished,
		RotatedAt:   krm.introKey.RotatedAt,
	}
}

// CanRotateStaticKey returns true if the static key can be rotated.
func (krm *KeyRotationManager) CanRotateStaticKey() bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return krm.staticKey.CanRotate()
}

// CanRotateIntroKey returns true if the introduction key can be rotated.
func (krm *KeyRotationManager) CanRotateIntroKey() bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return krm.introKey.CanRotate()
}

// StaticKeyAge returns the age of the current static key.
func (krm *KeyRotationManager) StaticKeyAge() time.Duration {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return time.Since(krm.staticKey.CreatedAt)
}

// IntroKeyAge returns the age of the current introduction key.
func (krm *KeyRotationManager) IntroKeyAge() time.Duration {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return time.Since(krm.introKey.CreatedAt)
}

// SetPublished updates the published status of both keys.
// This affects the minimum age before rotation.
func (krm *KeyRotationManager) SetPublished(isPublished bool) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	krm.staticKey.IsPublished = isPublished
	krm.introKey.IsPublished = isPublished
}

// checkRotationAllowed verifies that the managed key is eligible for rotation.
// Returns an error with diagnostic context if the minimum age has not elapsed.
func checkRotationAllowed(key *ManagedKey, keyName string) error {
	if key.CanRotate() {
		return nil
	}
	remaining := key.TimeUntilRotation()
	return oops.
		In("handshake").
		With("key_age", key.Age()).
		With("min_age", key.MinAge()).
		With("remaining", remaining).
		Errorf("%s key cannot be rotated yet, %v remaining", keyName, remaining)
}

// RotateStaticKey generates a new static key if rotation is allowed.
// Returns the new key bytes or an error if rotation is not permitted.
func (krm *KeyRotationManager) RotateStaticKey() ([]byte, error) {
	flog("RotateStaticKey").Debug("Rotating static key")
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if err := checkRotationAllowed(krm.staticKey, "static"); err != nil {
		return nil, err
	}

	return krm.rotateStaticKeyLocked()
}

// ForceRotateStaticKey rotates the static key regardless of age.
// Use with caution - this bypasses security requirements.
func (krm *KeyRotationManager) ForceRotateStaticKey() ([]byte, error) {
	flog("ForceRotateStaticKey").Warn("Force rotating static key (bypassing age check)")
	krm.mu.Lock()
	defer krm.mu.Unlock()

	return krm.rotateStaticKeyLocked()
}

// rotateKeyLocked generates a new key, retires the old one, and schedules
// secure zeroing after the grace period. Caller must hold the write lock.
func (krm *KeyRotationManager) rotateKeyLocked(keyName string, keySize int, current, previous **ManagedKey) ([]byte, error) {
	flog("rotateKeyLocked", logger.Fields{"key": keyName}).Debug("performing key rotation")
	newKey := make([]byte, keySize)
	if _, err := rand.Read(newKey); err != nil {
		return nil, oops.Wrapf(err, "failed to generate new %s key", keyName)
	}

	now := krm.clock()

	oldKey := *current
	oldKey.State = KeyStateRetired
	oldKey.RotatedAt = now

	*current = &ManagedKey{
		Key:         newKey,
		CreatedAt:   now,
		State:       KeyStateActive,
		IsPublished: oldKey.IsPublished,
	}
	oldKey.Successor = *current

	if *previous != nil {
		securemem.SecureZero((*previous).Key)
	}
	*previous = oldKey

	go func(key *ManagedKey, stop <-chan struct{}) {
		t := time.NewTimer(KeyGracePeriod)
		defer t.Stop()
		select {
		case <-t.C:
		case <-stop:
		}
		securemem.SecureZero(key.Key)
	}(oldKey, krm.stopCh)

	if krm.onRotation != nil {
		cb := krm.onRotation
		captured := *current
		go func() {
			defer func() {
				if r := recover(); r != nil {
					flog("rotateKeyLocked", logger.Fields{"key":   keyName, "panic": r}).Error("onRotation callback panicked")
				}
			}()
			cb(keyName, oldKey, captured)
		}()
	}

	result := make([]byte, keySize)
	copy(result, newKey)
	return result, nil
}

// rotateStaticKeyLocked performs the actual static key rotation.
// Caller must hold the write lock.
func (krm *KeyRotationManager) rotateStaticKeyLocked() ([]byte, error) {
	return krm.rotateKeyLocked("static", StaticKeySize, &krm.staticKey, &krm.previousStaticKey)
}

// RotateIntroKey generates a new introduction key if rotation is allowed.
// Returns the new key bytes or an error if rotation is not permitted.
func (krm *KeyRotationManager) RotateIntroKey() ([]byte, error) {
	flog("RotateIntroKey").Debug("Rotating intro key")
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if err := checkRotationAllowed(krm.introKey, "intro"); err != nil {
		return nil, err
	}

	return krm.rotateIntroKeyLocked()
}

// ForceRotateIntroKey rotates the introduction key regardless of age.
// Use with caution - this bypasses security requirements.
func (krm *KeyRotationManager) ForceRotateIntroKey() ([]byte, error) {
	flog("ForceRotateIntroKey").Warn("Force rotating intro key (bypassing age check)")
	krm.mu.Lock()
	defer krm.mu.Unlock()

	return krm.rotateIntroKeyLocked()
}

// rotateIntroKeyLocked performs the actual intro key rotation.
// Caller must hold the write lock.
func (krm *KeyRotationManager) rotateIntroKeyLocked() ([]byte, error) {
	return krm.rotateKeyLocked("intro", IntroKeySize, &krm.introKey, &krm.previousIntroKey)
}

// RotateAllKeys rotates both static and introduction keys if allowed.
// Returns the new keys or an error. Partial rotation is not performed -
// if either key cannot be rotated, neither is rotated.
func (krm *KeyRotationManager) RotateAllKeys() (staticKey, introKey []byte, err error) {
	flog("RotateAllKeys").Debug("Rotating all keys")
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if !krm.staticKey.CanRotate() {
		return nil, nil, oops.
			In("handshake").
			Errorf("static key cannot be rotated yet")
	}
	if !krm.introKey.CanRotate() {
		return nil, nil, oops.
			In("handshake").
			Errorf("intro key cannot be rotated yet")
	}

	staticKey, err = krm.rotateStaticKeyLocked()
	if err != nil {
		return nil, nil, err
	}

	introKey, err = krm.rotateIntroKeyLocked()
	if err != nil {
		return nil, nil, err
	}

	return staticKey, introKey, nil
}

// Start begins background key rotation checking.
// Keys that meet rotation requirements will trigger the rotation callback
// but will NOT be automatically rotated - the callback should handle rotation.
func (krm *KeyRotationManager) Start() {
	flog("Start").Debug("Starting key rotation checker")
	krm.mu.Lock()
	if krm.running {
		krm.mu.Unlock()
		return
	}
	krm.running = true
	krm.stopCh = make(chan struct{})
	krm.mu.Unlock()

	go krm.runRotationChecker()
}

// Stop halts the background key rotation checker.
func (krm *KeyRotationManager) Stop() {
	flog("Stop").Debug("Stopping key rotation checker")
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if !krm.running {
		return
	}
	krm.running = false
	close(krm.stopCh)
}

// IsRunning returns true if the background checker is active.
func (krm *KeyRotationManager) IsRunning() bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return krm.running
}

// runRotationChecker periodically checks if keys can be rotated.
func (krm *KeyRotationManager) runRotationChecker() {
	ticker := time.NewTicker(KeyRotationCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-krm.stopCh:
			return
		case <-ticker.C:
			krm.checkRotation()
		}
	}
}

// checkRotation checks if any keys can be rotated and updates their state.
func (krm *KeyRotationManager) checkRotation() {
	flog("checkRotation").Debug("checkRotation: checking if key rotation is needed")
	krm.mu.Lock()
	defer krm.mu.Unlock()

	// Check static key
	if krm.staticKey.State == KeyStateActive && krm.staticKey.CanRotate() {
		krm.staticKey.State = KeyStatePendingRotation
	}

	// Check intro key
	if krm.introKey.State == KeyStateActive && krm.introKey.CanRotate() {
		krm.introKey.State = KeyStatePendingRotation
	}
}

// GetStatus returns a summary of the key rotation state.
func (krm *KeyRotationManager) GetStatus() KeyRotationStatus {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	return KeyRotationStatus{
		StaticKeyAge:          time.Since(krm.staticKey.CreatedAt),
		StaticKeyState:        krm.staticKey.State,
		StaticKeyCanRotate:    krm.staticKey.CanRotate(),
		StaticKeyTimeToRotate: krm.staticKey.TimeUntilRotation(),
		IntroKeyAge:           time.Since(krm.introKey.CreatedAt),
		IntroKeyState:         krm.introKey.State,
		IntroKeyCanRotate:     krm.introKey.CanRotate(),
		IntroKeyTimeToRotate:  krm.introKey.TimeUntilRotation(),
		IsPublished:           krm.staticKey.IsPublished,
		IsRunning:             krm.running,
	}
}

// KeyRotationStatus contains a snapshot of the rotation manager state.
type KeyRotationStatus struct {
	StaticKeyAge          time.Duration
	StaticKeyState        KeyState
	StaticKeyCanRotate    bool
	StaticKeyTimeToRotate time.Duration
	IntroKeyAge           time.Duration
	IntroKeyState         KeyState
	IntroKeyCanRotate     bool
	IntroKeyTimeToRotate  time.Duration
	IsPublished           bool
	IsRunning             bool
}

// GenerateNewStaticKey generates a new random 32-byte static key.
