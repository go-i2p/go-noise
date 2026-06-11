package session

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DataHandler manages Data message processing for SSU2 connections.
// It handles I2NP message extraction, fragmentation/reassembly, and
// maintains a queue of complete messages ready for the application layer.
//
// Data messages (Type 6) can contain:
// - BlockTypeI2NPMessage (Type 3): Complete I2NP messages
// - BlockTypeFirstFragment (Type 4): First fragment of large message
// - BlockTypeFollowOnFragment (Type 5): Subsequent fragments
// - All other 17 block types (DateTime, ACK, Relay*, PeerTest, etc.)
type DataHandler struct {
	// messageQueue holds complete I2NP messages ready for delivery
	messageQueue chan []byte

	// fragments tracks partial messages being reassembled
	fragments map[uint32]*FragmentSet

	// mutex protects fragments map
	mutex sync.RWMutex

	// stats tracks message processing statistics
	stats DataHandlerStats

	// blockRouter routes non-I2NP blocks to registered handlers
	blockRouter *BlockRouter

	// callbackMu protects concurrent access to callbacks.
	callbackMu sync.RWMutex

	// callbacks for specific block types
	callbacks DataHandlerCallbacks

	// fragmentTimeout is the duration after which incomplete fragment sets
	// are discarded. Per the spec, fragments should be cleaned up after a timeout.
	fragmentTimeout time.Duration

	// stopReaper signals the reaper goroutine to exit
	stopReaper chan struct{}

	// reaperWG tracks the reaper goroutine so Close() waits for it to exit.
	// BUG-RL-4: previously the goroutine was untracked — CloseWithReason could
	// return while the reaper still accessed DataHandler.fragments.
	reaperWG sync.WaitGroup
}

// DataHandlerCallbacks defines optional callbacks for block types
// that need external handling.
type DataHandlerCallbacks struct {
	// OnTermination is called when a Termination block is received.
	// validDataReceived is the number of valid data packets received (8-byte uint64);
	// reason is the termination code; additionalData is the remaining bytes per SSU2 spec.
	OnTermination func(validDataReceived uint64, reason uint8, additionalData []byte)

	// OnNewToken is called when a NewToken block is received
	OnNewToken func(token []byte)

	// OnRelayRequest is called when a RelayRequest block is received
	OnRelayRequest func(block *SSU2Block) error

	// OnRelayResponse is called when a RelayResponse block is received
	OnRelayResponse func(block *SSU2Block) error

	// OnRelayIntro is called when a RelayIntro block is received
	OnRelayIntro func(block *SSU2Block) error

	// OnRelayTagRequest is called when a RelayTagRequest block is received
	OnRelayTagRequest func(block *SSU2Block) error

	// OnRelayTag is called when a RelayTag block is received
	OnRelayTag func(block *SSU2Block) error

	// OnPeerTest is called when a PeerTest block is received
	OnPeerTest func(block *SSU2Block) error

	// OnPathChallenge is called when a PathChallenge block is received
	OnPathChallenge func(data []byte) error

	// OnPathResponse is called when a PathResponse block is received
	OnPathResponse func(data []byte) error

	// OnRouterInfo is called when a RouterInfo block is received
	OnRouterInfo func(data []byte) error

	// OnOptions is called when an Options block is received
	OnOptions func(data []byte) error

	// OnAddress is called when an Address block is received
	OnAddress func(data []byte) error

	// OnACK is called when an ACK block is received
	OnACK func(block *SSU2Block) error

	// OnDateTime is called when a DateTime block is received
	OnDateTime func(timestamp uint32) error

	// OnNextNonce is called when a NextNonce block is received.
	// The newNonce is the 8-byte value signaling the peer's next send nonce.
	OnNextNonce func(newNonce uint64) error

	// OnFirstPacketNumber is called when a FirstPacketNumber block is received.
	// packetNumber is the initial packet number for the data phase.
	OnFirstPacketNumber func(packetNumber uint32) error

	// OnCongestion is called when a Congestion block is received.
	// flags is the congestion flag byte per spec: bit 0 = request immediate ACK, bit 1 = ECN.
	OnCongestion func(flags uint8) error

	// VerifyPeerTestSignature is called to verify a PeerTest block's signature
	// before dispatching to OnPeerTest. Per SSU2 spec §Peer Test, signatures
	// MUST be verified before acting on the message (G-2). If nil, blocks with
	// mandatory signatures (messages 1-4) are rejected.
	VerifyPeerTestSignature func(block *PeerTestBlock) error

	// VerifyRelayRequestSignature is called to verify a RelayRequest block's
	// signature before dispatching to OnRelayRequest. Per SSU2 spec §Relay
	// Request, signatures MUST be verified (G-2). If nil, blocks are rejected.
	VerifyRelayRequestSignature func(block *RelayRequestBlock) error

	// VerifyRelayResponseSignature is called to verify a RelayResponse block's
	// signature before dispatching to OnRelayResponse. Per SSU2 spec §Relay
	// Response, signatures MUST be verified for code 0 and code >= 64 (G-2).
	// If nil, signed responses are rejected.
	VerifyRelayResponseSignature func(block *RelayResponseBlock) error

	// VerifyRelayIntroSignature is called to verify a RelayIntro block's
	// signature before dispatching to OnRelayIntro. Per SSU2 spec §Relay
	// Intro, signatures MUST be verified (G-2). If nil, blocks are rejected.
	VerifyRelayIntroSignature func(block *RelayIntroBlock) error
}

// DataHandlerStats tracks statistics for monitoring and debugging.
type DataHandlerStats struct {
	MessagesReceived    uint64 // Complete messages received
	FragmentsReceived   uint64 // Total fragments received
	MessagesReassembled uint64 // Messages successfully reassembled
	MessagesDropped     uint64 // Messages dropped (timeout, errors)
	BlocksProcessed     uint64 // Total blocks processed
	UnknownBlocks       uint64 // Unknown block types received
}

// NewDataHandler creates a new Data message handler.
// queueSize determines how many complete messages can be buffered.
func NewDataHandler(queueSize int) *DataHandler {
	log.WithFields(logger.Fields{"pkg": "session", "func": "NewDataHandler", "queueSize": queueSize}).Debug("creating data handler")
	if queueSize <= 0 {
		queueSize = 100 // Default queue size
	}

	return &DataHandler{
		messageQueue:    make(chan []byte, queueSize),
		fragments:       make(map[uint32]*FragmentSet),
		blockRouter:     NewBlockRouter(),
		fragmentTimeout: 10 * time.Second,
		stopReaper:      make(chan struct{}),
	}
}

// newDataHandlerFromConfig creates a DataHandler using SSU2Config values.
func newDataHandlerFromConfig(config *SSU2Config) *DataHandler {
	log.WithFields(logger.Fields{"pkg": "session", "func": "newDataHandlerFromConfig"}).Debug("creating data handler from config")
	dh := NewDataHandler(100)
	if config != nil && config.FragmentTimeout > 0 {
		dh.fragmentTimeout = config.FragmentTimeout
	}
	return dh
}

// StartReaper launches a background goroutine that periodically removes
// incomplete fragment sets older than fragmentTimeout.
func (h *DataHandler) StartReaper() {
	log.WithFields(logger.Fields{"pkg": "session", "func": "StartReaper", "fragmentTimeout": h.fragmentTimeout}).Debug("launching fragment cleanup goroutine")
	h.reaperWG.Add(1)
	go func() {
		defer h.reaperWG.Done()
		ticker := time.NewTicker(h.fragmentTimeout / 2)
		defer ticker.Stop()
		for {
			select {
			case <-h.stopReaper:
				return
			case <-ticker.C:
				h.cleanupStaleFragments()
			}
		}
	}()
}

// Close stops the fragment reaper goroutine and waits for it to exit.
func (h *DataHandler) Close() {
	log.WithFields(logger.Fields{"pkg": "session", "func": "Close"}).Debug("stopping DataHandler reaper")
	select {
	case <-h.stopReaper:
	default:
		close(h.stopReaper)
	}
	// BUG-RL-4: wait for the reaper goroutine to exit before returning so
	// that CloseWithReason does not return while the goroutine still
	// accesses DataHandler.fragments.
	h.reaperWG.Wait()
}

// SetCallbacks sets the callback handlers for block types.
func (h *DataHandler) SetCallbacks(callbacks DataHandlerCallbacks) {
	log.WithFields(logger.Fields{"pkg": "session", "func": "SetCallbacks"}).Debug("updating DataHandler callbacks")
	h.callbackMu.Lock()
	defer h.callbackMu.Unlock()
	h.callbacks = callbacks
}

// getCallbacks returns a snapshot of the current callbacks.
// Callers should use the snapshot rather than reading h.callbacks directly
// to avoid races with SetCallbacks.
func (h *DataHandler) getCallbacks() DataHandlerCallbacks {
	log.WithFields(logger.Fields{"pkg": "session", "func": "getCallbacks"}).Debug("retrieving current callbacks")
	h.callbackMu.RLock()
	defer h.callbackMu.RUnlock()
	return h.callbacks
}

// GetBlockRouter returns the block router for registering external handlers.
func (h *DataHandler) GetBlockRouter() *BlockRouter {
	log.WithFields(logger.Fields{"pkg": "session", "func": "GetBlockRouter"}).Debug("returning block router")
	return h.blockRouter
}

// ProcessDataPacket processes a Data packet and extracts I2NP messages.
// Returns extracted blocks and any error encountered.
// All 20 SSU2 block types are explicitly handled.
func (h *DataHandler) ProcessDataPacket(packet *SSU2Packet) ([]*SSU2Block, error) {
	if packet.MessageType != MessageTypeData {
		return nil, oops.Errorf("expected Data packet (type %d), got type %d",
			MessageTypeData, packet.MessageType)
	}

	// Deserialize blocks from payload
	blocks, err := DeserializeBlocks(packet.Payload)
	if err != nil {
		h.incrementStat(&h.stats.MessagesDropped)
		return nil, oops.Wrapf(err, "failed to deserialize blocks from Data packet")
	}

	// Validate block ordering per spec:
	// - Padding, if present, must be the last block.
	// - Termination, if present, must be the last block except for Padding.
	if err := validateBlockOrdering(blocks); err != nil {
		log.WithFields(logger.Fields{"pkg": "session", "func": "ProcessDataPacket", "error": err}).Warn("Invalid block ordering")
	}

	// Process each block
	for _, block := range blocks {
		h.incrementStat(&h.stats.BlocksProcessed)
		if err := h.processBlock(block); err != nil {
			return blocks, err
		}
	}

	return blocks, nil
}

// processBlock routes a single block to its appropriate handler.
// For critical message blocks (I2NP, fragments), errors are returned.
// For non-critical blocks, errors are logged and processing continues.
func (h *DataHandler) processBlock(block *SSU2Block) error {
	switch block.Type {
	case BlockTypeI2NPMessage:
		log.WithFields(logger.Fields{"pkg": "session", "func": "processBlock", "data_len": len(block.Data)}).Debug("processing I2NPMessage block")
		return h.handleI2NPMessage(block.Data)
	case BlockTypeFirstFragment:
		log.WithFields(logger.Fields{"pkg": "session", "func": "processBlock", "data_len": len(block.Data)}).Debug("processing FirstFragment block")
		return h.handleFirstFragment(block.Data)
	case BlockTypeFollowOnFragment:
		log.WithFields(logger.Fields{"pkg": "session", "func": "processBlock", "data_len": len(block.Data)}).Debug("processing FollowOnFragment block")
		return h.handleFollowOnFragment(block.Data)
	case BlockTypePadding:
		return nil
	default:
		h.dispatchNonCriticalBlock(block)
		return nil
	}
}

// dispatchNonCriticalBlock handles blocks where errors are logged, not propagated.
func (h *DataHandler) dispatchNonCriticalBlock(block *SSU2Block) {
	var err error
	switch block.Type {
	case BlockTypeTermination:
		err = h.handleTermination(block.Data)
	case BlockTypeNewToken:
		err = h.handleNewToken(block.Data)
	case BlockTypeRelayRequest:
		err = h.handleRelayRequest(block)
	case BlockTypeRelayResponse:
		err = h.handleRelayResponse(block)
	case BlockTypeRelayIntro:
		err = h.handleRelayIntro(block)
	case BlockTypeRelayTagRequest:
		err = h.handleRelayTagRequest(block)
	case BlockTypeRelayTag:
		err = h.handleRelayTag(block)
	case BlockTypePeerTest:
		err = h.handlePeerTest(block)
	case BlockTypePathChallenge:
		err = h.handlePathChallenge(block.Data)
	case BlockTypePathResponse:
		err = h.handlePathResponse(block.Data)
	case BlockTypeDateTime:
		err = h.handleDateTime(block.Data)
	case BlockTypeOptions:
		err = h.handleOptions(block.Data)
	case BlockTypeRouterInfo:
		err = h.handleRouterInfo(block.Data)
	case BlockTypeAddress:
		err = h.handleAddress(block.Data)
	case BlockTypeACK:
		err = h.handleACK(block)
	case BlockTypeNextNonce:
		err = h.handleNextNonce(block.Data)
	case BlockTypeFirstPacketNumber:
		err = h.handleFirstPacketNumber(block.Data)
	case BlockTypeCongestion:
		err = h.handleCongestion(block.Data)
	default:
		h.incrementStat(&h.stats.UnknownBlocks)
		log.WithFields(logger.Fields{
			"pkg":        "ssu2",
			"func":       "dispatchNonCriticalBlock",
			"blockType":  block.Type,
			"dataLength": len(block.Data),
		}).Warn("Received unknown block type")
		return
	}
	if err != nil {
		log.WithFields(logger.Fields{
			"pkg":       "ssu2",
			"func":      "dispatchNonCriticalBlock",
			"blockType": block.Type,
			"error":     err,
		}).Debug("Error handling block")
	}
}

// GetMessage retrieves the next complete I2NP message from the queue.
// Returns nil if no messages are available (non-blocking).
func (h *DataHandler) GetMessage() []byte {
	select {
	case msg := <-h.messageQueue:
		return msg
	default:
		return nil
	}
}

// GetMessageBlocking waits for the next message with optional timeout.
// Returns nil if timeout expires.
func (h *DataHandler) GetMessageBlocking(timeout time.Duration) []byte {
	if timeout <= 0 {
		// Block indefinitely
		return <-h.messageQueue
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case msg := <-h.messageQueue:
		return msg
	case <-timer.C:
		return nil
	}
}

// HasMessages returns true if messages are available in the queue.
func (h *DataHandler) HasMessages() bool {
	return len(h.messageQueue) > 0
}

// MessageChan returns the receive-only channel for complete I2NP messages.
// Used by SSU2Conn.Read to block until a message is available.
func (h *DataHandler) MessageChan() <-chan []byte {
	return h.messageQueue
}

// GetStats returns a copy of current statistics.
func (h *DataHandler) GetStats() DataHandlerStats {
	return DataHandlerStats{
		MessagesReceived:    atomic.LoadUint64(&h.stats.MessagesReceived),
		FragmentsReceived:   atomic.LoadUint64(&h.stats.FragmentsReceived),
		MessagesReassembled: atomic.LoadUint64(&h.stats.MessagesReassembled),
		MessagesDropped:     atomic.LoadUint64(&h.stats.MessagesDropped),
		BlocksProcessed:     atomic.LoadUint64(&h.stats.BlocksProcessed),
		UnknownBlocks:       atomic.LoadUint64(&h.stats.UnknownBlocks),
	}
}

// Clear removes all queued messages and fragments.
func (h *DataHandler) Clear() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Drain message queue
	for {
		select {
		case <-h.messageQueue:
		default:
			goto done
		}
	}
done:

	// Clear fragments
	h.fragments = make(map[uint32]*FragmentSet)
}

// incrementStat atomically increments a statistic counter.
func (h *DataHandler) incrementStat(stat *uint64) {
	atomic.AddUint64(stat, 1)
}

// validateBlockOrdering checks that Padding and Termination blocks are in valid positions.
// Per spec: Padding must be the last block; Termination must be the last block except for Padding.
func validateBlockOrdering(blocks []*SSU2Block) error {
	log.WithFields(logger.Fields{"pkg": "session", "func": "validateBlockOrdering", "blockCount": len(blocks)}).Debug("checking block order")
	n := len(blocks)
	for i, block := range blocks {
		if block.Type == BlockTypePadding && i != n-1 {
			return oops.Errorf("Padding block at position %d but must be last (total %d blocks)", i, n)
		}
		if block.Type == BlockTypeTermination && i < n-1 {
			// Termination may be followed only by Padding
			for _, after := range blocks[i+1:] {
				if after.Type != BlockTypePadding {
					return oops.Errorf("Termination block at position %d followed by non-Padding block type %d", i, after.Type)
				}
			}
		}
	}
	return nil
}
