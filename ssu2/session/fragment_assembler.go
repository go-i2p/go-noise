package session

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/go-noise/internal/eviction"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// maxFragmentsPerConn limits the number of in-progress fragment reassemblies
// to prevent memory exhaustion from fragmentation attacks. An attacker could
// send unique MessageIDs to force unbounded growth of the fragments map.
const maxFragmentsPerConn = 512

// maxI2NPMessageSize is the maximum size of a reassembled I2NP message (64 KB).
// Per the I2NP protocol specification, messages must not exceed this size.
// Reassembled messages exceeding this limit are dropped to enforce spec compliance.
const maxI2NPMessageSize = 65536

// FragmentSet represents a message being reassembled from fragments.
type FragmentSet struct {
	MessageID       uint32           // I2NP message identifier
	I2NPType        uint8            // I2NP message type from First Fragment
	ShortExpiration uint32           // I2NP short expiration from First Fragment
	Fragments       map[uint8][]byte // Fragment number -> data
	ReceivedSize    uint32           // Bytes received so far
	HasLast         bool             // Whether we've received the last fragment
	HasFirst        bool             // Whether we've received the first fragment
	LastFragNum     uint8            // Fragment number of the last fragment
	CreatedAt       time.Time        // When first fragment arrived
	LastUpdate      time.Time        // Last fragment received time
}

// cleanupStaleFragments removes fragment sets that have exceeded the timeout.
func (h *DataHandler) cleanupStaleFragments() {
	log.WithFields(logger.Fields{"pkg": "session", "func": "cleanupStaleFragments", "timeout": h.fragmentTimeout}).Debug("scanning for stale fragments")
	h.mutex.Lock()
	defer h.mutex.Unlock()

	now := time.Now()
	for id, fs := range h.fragments {
		if now.Sub(fs.LastUpdate) > h.fragmentTimeout {
			h.incrementStat(&h.stats.MessagesDropped)
			delete(h.fragments, id)
		}
	}
}

// evictOldestFragment removes the oldest in-progress fragment reassembly
// when the fragments map reaches maxFragmentsPerConn. Called with mutex held.
func (h *DataHandler) evictOldestFragment() {
	if len(h.fragments) == 0 {
		return
	}

	oldestID, oldestTime, _ := eviction.EvictOldestByTime(h.fragments, func(fs *FragmentSet) time.Time {
		return fs.CreatedAt
	})

	log.WithFields(logger.Fields{
		"pkg":        "session",
		"func":       "evictOldestFragment",
		"message_id": oldestID,
		"age":        time.Since(oldestTime),
	}).Warn("evicting oldest fragment set due to capacity limit")

	h.incrementStat(&h.stats.MessagesDropped)
}

// handleFirstFragment processes the first fragment of a message.
// SSU2 spec format: I2NP type(1) + messageID(4) + shortExpiration(4) + data
func (h *DataHandler) handleFirstFragment(data []byte) error {
	if len(data) < 9 {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("first fragment too short: %d bytes, need at least 9", len(data))
	}

	i2npType := data[0]
	messageID := binary.BigEndian.Uint32(data[1:5])
	shortExpiration := binary.BigEndian.Uint32(data[5:9])
	fragmentData := data[9:]

	log.WithFields(logger.Fields{
		"pkg":        "ssu2",
		"func":       "handleFirstFragment",
		"i2np_type":  i2npType,
		"message_id": messageID,
		"short_exp":  shortExpiration,
		"frag_len":   len(fragmentData),
	}).Debug("parsed header")

	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Check if we already have this message ID from an early FollowOnFragment
	if existing, exists := h.fragments[messageID]; exists {
		if existing.HasFirst {
			// Duplicate FirstFragment — ignore silently
			return nil
		}
		// Populate missing metadata from this FirstFragment
		existing.I2NPType = i2npType
		existing.ShortExpiration = shortExpiration
		existing.HasFirst = true
		// If an early FollowOnFragment with fragNum==0 arrived before this
		// FirstFragment, its bytes were already counted in ReceivedSize.
		// Subtract them before overwriting Fragments[0] to avoid double-counting.
		if oldFrag, hadFrag0 := existing.Fragments[0]; hadFrag0 {
			existing.ReceivedSize -= uint32(len(oldFrag))
		}
		existing.Fragments[0] = make([]byte, len(fragmentData))
		copy(existing.Fragments[0], fragmentData)
		existing.ReceivedSize += uint32(len(fragmentData))
		existing.LastUpdate = time.Now()
		h.incrementStat(&h.stats.FragmentsReceived)

		// Attempt reassembly now that we have the first fragment
		if existing.HasLast {
			if err := h.reassembleMessage(messageID); err != nil {
				return err
			}
		}
		return nil
	}

	// Enforce capacity limit: evict oldest if at maximum
	if len(h.fragments) >= maxFragmentsPerConn {
		h.evictOldestFragment()
	}

	// Create new fragment set
	fragmentSet := &FragmentSet{
		MessageID:       messageID,
		I2NPType:        i2npType,
		ShortExpiration: shortExpiration,
		Fragments:       make(map[uint8][]byte),
		ReceivedSize:    uint32(len(fragmentData)),
		CreatedAt:       time.Now(),
		LastUpdate:      time.Now(),
		HasFirst:        true,
	}

	// Store first fragment (fragment number 0)
	fragmentSet.Fragments[0] = make([]byte, len(fragmentData))
	copy(fragmentSet.Fragments[0], fragmentData)

	// Check per-set size bound immediately (M-3): if a single first fragment
	// is already oversized, reject it. Though rare, this provides defense-in-depth.
	if fragmentSet.ReceivedSize > maxI2NPMessageSize {
		h.incrementStat(&h.stats.MessagesDropped)
		return nil
	}

	h.fragments[messageID] = fragmentSet
	h.incrementStat(&h.stats.FragmentsReceived)

	return nil
}

// handleFollowOnFragment processes subsequent fragments of a message.
// SSU2 spec format: FragmentInfo(1) + MessageID(4) + Data
// FragmentInfo: (fragNum << 1) | isLast
func (h *DataHandler) handleFollowOnFragment(data []byte) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "handleFollowOnFragment", "dataLen": len(data)}).Debug("processing follow-on fragment")

	// Early validation: ensure minimum frame size
	if len(data) < 5 {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("follow-on fragment too short: %d bytes, need at least 5", len(data))
	}

	// Parse fragment header before acquiring lock
	fragInfo := data[0]
	fragmentNum := fragInfo >> 1
	isLast := (fragInfo & 0x01) != 0
	messageID := binary.BigEndian.Uint32(data[1:5])
	fragmentData := data[5:]

	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Find or create fragment set
	fragmentSet, exists := h.fragments[messageID]
	if !exists {
		// Enforce capacity limit: evict oldest if at maximum
		if len(h.fragments) >= maxFragmentsPerConn {
			h.evictOldestFragment()
		}

		// Buffer early FollowOnFragment before its FirstFragment arrives
		now := time.Now()
		fragmentSet = &FragmentSet{
			MessageID:  messageID,
			Fragments:  make(map[uint8][]byte),
			CreatedAt:  now,
			LastUpdate: now,
		}
		h.fragments[messageID] = fragmentSet
	}

	// Check for duplicate fragment
	if _, exists := fragmentSet.Fragments[fragmentNum]; exists {
		// Duplicate fragment - ignore silently
		return nil
	}

	// Store fragment
	fragmentSet.Fragments[fragmentNum] = make([]byte, len(fragmentData))
	copy(fragmentSet.Fragments[fragmentNum], fragmentData)
	fragmentSet.ReceivedSize += uint32(len(fragmentData))
	fragmentSet.LastUpdate = time.Now()
	h.incrementStat(&h.stats.FragmentsReceived)

	// Tighten per-set memory bound: drop immediately if exceeded (M-3).
	// Per-set bound is now the reassembled message limit (64 KB) rather than
	// only checked at reassembly time. This prevents an attacker from flooding
	// a single MessageID with large fragments to exhaust per-connection memory.
	if fragmentSet.ReceivedSize > maxI2NPMessageSize {
		log.WithFields(logger.Fields{
			"pkg":           "session",
			"func":          "handleFollowOnFragment",
			"message_id":    messageID,
			"received_size": fragmentSet.ReceivedSize,
			"max_size":      maxI2NPMessageSize,
		}).Warn("dropping oversized reassembled message (exceeds 64 KB limit)")
		delete(h.fragments, messageID)
		h.incrementStat(&h.stats.MessagesDropped)
		return nil
	}

	if isLast {
		fragmentSet.HasLast = true
		fragmentSet.LastFragNum = fragmentNum
	}

	// Attempt reassembly if we have both first and last fragments and all preceding ones
	if fragmentSet.HasFirst && fragmentSet.HasLast {
		if err := h.reassembleMessage(messageID); err != nil {
			return err
		}
	}

	return nil
}

// reassembleMessage combines all fragments into a complete message.
// Must be called with mutex held.
func (h *DataHandler) reassembleMessage(messageID uint32) error {
	fragmentSet := h.fragments[messageID]
	if fragmentSet == nil {
		return oops.Errorf("fragment set not found for message ID %d", messageID)
	}

	// Check we have all fragments from 0 through LastFragNum
	if !fragmentSet.HasFirst || !fragmentSet.HasLast {
		return nil // Not ready yet
	}
	for i := uint8(0); i <= fragmentSet.LastFragNum; i++ {
		if _, exists := fragmentSet.Fragments[i]; !exists {
			return nil // Missing fragment, wait for it
		}
	}

	// Reassemble fragments in order, prepending the I2NP short header
	// (type + messageID + shortExpiration) so the delivered message matches
	// the format produced by handleI2NPMessage (G-3).
	header := make([]byte, 9)
	header[0] = fragmentSet.I2NPType
	binary.BigEndian.PutUint32(header[1:5], fragmentSet.MessageID)
	binary.BigEndian.PutUint32(header[5:9], fragmentSet.ShortExpiration)

	message := make([]byte, 0, int(fragmentSet.ReceivedSize)+9)
	message = append(message, header...)
	for i := uint8(0); i <= fragmentSet.LastFragNum; i++ {
		message = append(message, fragmentSet.Fragments[i]...)
	}

	// Validate reassembled message size against I2NP maximum
	if len(message) > maxI2NPMessageSize {
		h.incrementStat(&h.stats.MessagesDropped)
		delete(h.fragments, messageID)
		log.WithFields(logger.Fields{
			"pkg":        "ssu2",
			"func":       "reassembleMessage",
			"message_id": messageID,
			"size":       len(message),
			"max_size":   maxI2NPMessageSize,
		}).Warn("dropping oversized reassembled message")
		return nil // Silent drop, not an error
	}

	log.WithFields(logger.Fields{
		"pkg":        "ssu2",
		"func":       "reassembleMessage",
		"message_id": messageID,
		"total_len":  len(message),
		"num_frags":  fragmentSet.LastFragNum + 1,
	}).Debug("reassembled")

	// Queue complete message
	select {
	case h.messageQueue <- message:
		h.incrementStat(&h.stats.MessagesReassembled)
		delete(h.fragments, messageID)
		return nil
	default:
		h.incrementStat(&h.stats.MessagesDropped)
		delete(h.fragments, messageID)
		return oops.Errorf("message queue full, dropping reassembled message")
	}
}

// CleanupExpiredFragments removes fragment sets that haven't been updated
// within the specified timeout. Should be called periodically.
func (h *DataHandler) CleanupExpiredFragments(timeout time.Duration) int {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	now := time.Now()
	removed := 0

	for messageID, fragmentSet := range h.fragments {
		if now.Sub(fragmentSet.LastUpdate) > timeout {
			delete(h.fragments, messageID)
			h.incrementStat(&h.stats.MessagesDropped)
			removed++
		}
	}

	return removed
}

// GetFragmentCount returns the number of incomplete fragment sets.
func (h *DataHandler) GetFragmentCount() int {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return len(h.fragments)
}
