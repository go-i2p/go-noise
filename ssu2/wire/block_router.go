package wire

import (
	"sync"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// BlockRouter routes SSU2 blocks to registered handlers.
// It provides a centralized mechanism for block dispatch with logging.
type BlockRouter struct {
	// handlers maps block type to handler
	handlers map[uint8]BlockHandler

	// defaultHandler is called for unregistered block types
	defaultHandler BlockHandler

	// mu protects handlers map
	mu sync.RWMutex

	// stats tracks routing statistics
	stats BlockRouterStats
}

// BlockRouterStats tracks block routing statistics.
type BlockRouterStats struct {
	mu sync.Mutex

	// BlocksRouted tracks count per block type
	BlocksRouted map[uint8]uint64

	// UnknownBlocks counts blocks with no registered handler
	UnknownBlocks uint64

	// RoutingErrors counts handler errors
	RoutingErrors uint64
}

// NewBlockRouter creates a new block router.
func NewBlockRouter() *BlockRouter {
	flog("NewBlockRouter").Debug("NewBlockRouter: creating new block router")
	return &BlockRouter{
		handlers: make(map[uint8]BlockHandler),
		stats: BlockRouterStats{
			BlocksRouted: make(map[uint8]uint64),
		},
	}
}

// RegisterHandler registers a handler for specific block types.
// If a handler is already registered for a type, it will be replaced.
func (r *BlockRouter) RegisterHandler(handler BlockHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, blockType := range handler.SupportedTypes() {
		r.handlers[blockType] = handler
		flog("RegisterHandler", logger.Fields{"blockType": blockType}).Debug("Registered block handler")
	}
}

// RegisterHandlerFunc registers a simple function handler for specific block types.
func (r *BlockRouter) RegisterHandlerFunc(blockTypes []uint8, fn BlockHandlerFunc) {
	flog("RegisterHandlerFunc", logger.Fields{"blockTypes": blockTypes}).Debug("RegisterHandlerFunc: registering function handler")
	handler := &funcBlockHandler{
		fn:    fn,
		types: blockTypes,
	}
	r.RegisterHandler(handler)
}

// SetDefaultHandler sets a handler for unregistered block types.
func (r *BlockRouter) SetDefaultHandler(handler BlockHandler) {
	flog("SetDefaultHandler").Debug("SetDefaultHandler: setting default block handler")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultHandler = handler
}

// RouteBlock routes a block to the appropriate handler.
// Returns an error if the handler returns an error.
// Blocks without registered handlers are logged and skipped.
func (r *BlockRouter) RouteBlock(block *SSU2Block) error {
	if block == nil {
		return oops.Errorf("cannot route nil block")
	}

	r.mu.RLock()
	handler, exists := r.handlers[block.Type]
	defaultHandler := r.defaultHandler
	r.mu.RUnlock()

	// Track stats
	r.stats.mu.Lock()
	r.stats.BlocksRouted[block.Type]++
	r.stats.mu.Unlock()

	if exists {
		handled, err := handler.HandleBlock(block)
		if err != nil {
			r.stats.mu.Lock()
			r.stats.RoutingErrors++
			r.stats.mu.Unlock()
			return oops.Wrapf(err, "handler error for block type %d", block.Type)
		}
		if handled {
			return nil
		}
	}

	// Try default handler
	if defaultHandler != nil {
		handled, err := defaultHandler.HandleBlock(block)
		if err != nil {
			r.stats.mu.Lock()
			r.stats.RoutingErrors++
			r.stats.mu.Unlock()
			return oops.Wrapf(err, "default handler error for block type %d", block.Type)
		}
		if handled {
			return nil
		}
	}

	// No handler - log and continue
	r.stats.mu.Lock()
	r.stats.UnknownBlocks++
	r.stats.mu.Unlock()

	if exists {
		// A registered handler was tried but returned handled==false; this is
		// a legitimate outcome (e.g. handler ignores empty Data), not an error.
		flog("RouteBlock", logger.Fields{"blockType": block.Type, "blockName": BlockTypeName(block.Type), "dataLength": len(block.Data)}).Debug("Registered handler declined block (handled=false)")
	} else {
		flog("RouteBlock", logger.Fields{"blockType": block.Type, "blockName": BlockTypeName(block.Type), "dataLength": len(block.Data)}).Warn("No handler registered for block type")
	}

	return nil
}

// RouteBlocks routes multiple blocks to their handlers.
// Continues routing even if some blocks fail.
// Returns the first error encountered.
func (r *BlockRouter) RouteBlocks(blocks []*SSU2Block) error {
	flog("RouteBlocks", logger.Fields{"blockCount": len(blocks)}).Debug("RouteBlocks: routing multiple blocks")
	var firstErr error
	for _, block := range blocks {
		if err := r.RouteBlock(block); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Continue routing remaining blocks
		}
	}
	return firstErr
}

// GetStats returns a copy of routing statistics.
func (r *BlockRouter) GetStats() BlockRouterStats {
	r.stats.mu.Lock()
	defer r.stats.mu.Unlock()

	// Deep copy the map
	blocksRouted := make(map[uint8]uint64, len(r.stats.BlocksRouted))
	for k, v := range r.stats.BlocksRouted {
		blocksRouted[k] = v
	}

	return BlockRouterStats{
		BlocksRouted:  blocksRouted,
		UnknownBlocks: r.stats.UnknownBlocks,
		RoutingErrors: r.stats.RoutingErrors,
	}
}

// HasHandler returns true if a handler is registered for the block type.
func (r *BlockRouter) HasHandler(blockType uint8) bool {
	flog("HasHandler", logger.Fields{"blockType": blockType}).Debug("HasHandler: checking for registered handler")
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.handlers[blockType]
	return exists
}

// funcBlockHandler wraps a function as a BlockHandler.
type funcBlockHandler struct {
	fn    BlockHandlerFunc
	types []uint8
}

func (h *funcBlockHandler) HandleBlock(block *SSU2Block) (bool, error) {
	return h.fn(block)
}

func (h *funcBlockHandler) SupportedTypes() []uint8 {
	return h.types
}

// BlockTypeName returns a human-readable name for a block type.
// This is useful for logging and debugging.
func BlockTypeName(blockType uint8) string {
	// Preserve legacy router-facing behavior: these internal/specialized block
	// types were historically reported as Unknown by BlockTypeName.
	switch blockType {
	case BlockTypeNextNonce, BlockTypeReserved14, BlockTypeFirstPacketNumber, BlockTypeCongestion:
		return "Unknown"
	}
	return GetBlockTypeName(blockType)
}

// AllBlockTypes returns all defined SSU2 block types.
// Useful for validation and testing.
func AllBlockTypes() []uint8 {
	return []uint8{
		BlockTypeDateTime,          // 0
		BlockTypeOptions,           // 1
		BlockTypeRouterInfo,        // 2
		BlockTypeI2NPMessage,       // 3
		BlockTypeFirstFragment,     // 4
		BlockTypeFollowOnFragment,  // 5
		BlockTypeTermination,       // 6
		BlockTypeRelayRequest,      // 7
		BlockTypeRelayResponse,     // 8
		BlockTypeRelayIntro,        // 9
		BlockTypePeerTest,          // 10
		BlockTypeNextNonce,         // 11
		BlockTypeACK,               // 12
		BlockTypeAddress,           // 13
		BlockTypeRelayTagRequest,   // 15 (note: 14 is undefined)
		BlockTypeRelayTag,          // 16
		BlockTypeNewToken,          // 17
		BlockTypePathChallenge,     // 18
		BlockTypePathResponse,      // 19
		BlockTypeFirstPacketNumber, // 20
		BlockTypeCongestion,        // 21
		BlockTypePadding,           // 254
	}
}

// BlockTypeCategory returns the category of a block type for routing purposes.
type BlockTypeCategory int

const (
	// CategoryMessage blocks contain I2NP messages or fragments
	CategoryMessage BlockTypeCategory = iota
	// CategoryRelay blocks are for relay/introduction operations
	CategoryRelay
	// CategoryPeerTest blocks are for peer testing
	CategoryPeerTest
	// CategoryPath blocks are for path validation
	CategoryPath
	// CategorySession blocks are for session management
	CategorySession
	// CategoryMetadata blocks contain connection metadata
	CategoryMetadata
	// CategoryUnknown for undefined block types
	CategoryUnknown
)

// GetBlockCategory returns the category for a block type.
func GetBlockCategory(blockType uint8) BlockTypeCategory {
	switch blockType {
	case BlockTypeI2NPMessage, BlockTypeFirstFragment, BlockTypeFollowOnFragment:
		return CategoryMessage
	case BlockTypeRelayRequest, BlockTypeRelayResponse, BlockTypeRelayIntro,
		BlockTypeRelayTagRequest, BlockTypeRelayTag:
		return CategoryRelay
	case BlockTypePeerTest:
		return CategoryPeerTest
	case BlockTypePathChallenge, BlockTypePathResponse:
		return CategoryPath
	case BlockTypeTermination, BlockTypeNewToken:
		return CategorySession
	case BlockTypeDateTime, BlockTypeOptions, BlockTypeRouterInfo,
		BlockTypeACK, BlockTypeAddress, BlockTypePadding:
		return CategoryMetadata
	default:
		return CategoryUnknown
	}
}
