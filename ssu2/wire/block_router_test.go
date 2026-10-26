package wire

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllBlockTypes verifies AllBlockTypes returns all defined types.
func TestAllBlockTypes(t *testing.T) {
	allTypes := AllBlockTypes()
	assert.Len(t, allTypes, 22) // 22: types 0-10, 12-13, 15-21, 254 (skip 14)

	// Verify specific types are included
	typeSet := make(map[uint8]bool)
	for _, bt := range allTypes {
		typeSet[bt] = true
	}

	assert.True(t, typeSet[BlockTypeDateTime])
	assert.True(t, typeSet[BlockTypeOptions])
	assert.True(t, typeSet[BlockTypeRouterInfo])
	assert.True(t, typeSet[BlockTypeI2NPMessage])
	assert.True(t, typeSet[BlockTypeFirstFragment])
	assert.True(t, typeSet[BlockTypeFollowOnFragment])
	assert.True(t, typeSet[BlockTypeTermination])
	assert.True(t, typeSet[BlockTypeRelayRequest])
	assert.True(t, typeSet[BlockTypeRelayResponse])
	assert.True(t, typeSet[BlockTypeRelayIntro])
	assert.True(t, typeSet[BlockTypePeerTest])
	assert.True(t, typeSet[BlockTypeNextNonce])
	assert.True(t, typeSet[BlockTypeACK])
	assert.True(t, typeSet[BlockTypeAddress])
	assert.True(t, typeSet[BlockTypeRelayTagRequest])
	assert.True(t, typeSet[BlockTypeRelayTag])
	assert.True(t, typeSet[BlockTypeNewToken])
	assert.True(t, typeSet[BlockTypePathChallenge])
	assert.True(t, typeSet[BlockTypePathResponse])
	assert.True(t, typeSet[BlockTypeFirstPacketNumber])
	assert.True(t, typeSet[BlockTypeCongestion])
	assert.True(t, typeSet[BlockTypePadding])
}

// TestGetBlockCategory verifies block categorization.
func TestGetBlockCategory(t *testing.T) {
	tests := []struct {
		blockType uint8
		expected  BlockTypeCategory
	}{
		// Message blocks
		{BlockTypeI2NPMessage, CategoryMessage},
		{BlockTypeFirstFragment, CategoryMessage},
		{BlockTypeFollowOnFragment, CategoryMessage},
		// Relay blocks
		{BlockTypeRelayRequest, CategoryRelay},
		{BlockTypeRelayResponse, CategoryRelay},
		{BlockTypeRelayIntro, CategoryRelay},
		{BlockTypeRelayTagRequest, CategoryRelay},
		{BlockTypeRelayTag, CategoryRelay},
		// Peer test
		{BlockTypePeerTest, CategoryPeerTest},
		// Path validation
		{BlockTypePathChallenge, CategoryPath},
		{BlockTypePathResponse, CategoryPath},
		// Session
		{BlockTypeTermination, CategorySession},
		{BlockTypeNewToken, CategorySession},
		// Metadata
		{BlockTypeDateTime, CategoryMetadata},
		{BlockTypeOptions, CategoryMetadata},
		{BlockTypeRouterInfo, CategoryMetadata},
		{BlockTypeACK, CategoryMetadata},
		{BlockTypeAddress, CategoryMetadata},
		{BlockTypePadding, CategoryMetadata},
		// Unknown
		{255, CategoryUnknown},
		{11, CategoryUnknown},
	}

	for _, tc := range tests {
		t.Run(GetBlockTypeName(tc.blockType), func(t *testing.T) {
			category := GetBlockCategory(tc.blockType)
			assert.Equal(t, tc.expected, category)
		})
	}
}

// TestNewBlockRouter verifies router creation.
func TestNewBlockRouter(t *testing.T) {
	router := NewBlockRouter()
	require.NotNil(t, router)
	assert.NotNil(t, router.handlers)
	assert.NotNil(t, router.stats.BlocksRouted)
}

// mockBlockHandler is a test helper.
type mockBlockHandler struct {
	handledBlocks  []*SSU2Block
	supportedTypes []uint8
	returnError    error
	mu             sync.Mutex
}

func (h *mockBlockHandler) HandleBlock(block *SSU2Block) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handledBlocks = append(h.handledBlocks, block)
	return true, h.returnError
}

func (h *mockBlockHandler) SupportedTypes() []uint8 {
	return h.supportedTypes
}

func (h *mockBlockHandler) getHandledCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.handledBlocks)
}

// TestBlockRouter_RegisterHandler verifies handler registration.
func TestBlockRouter_RegisterHandler(t *testing.T) {
	router := NewBlockRouter()

	handler := &mockBlockHandler{
		supportedTypes: []uint8{BlockTypeDateTime, BlockTypeOptions},
	}

	router.RegisterHandler(handler)

	assert.True(t, router.HasHandler(BlockTypeDateTime))
	assert.True(t, router.HasHandler(BlockTypeOptions))
	assert.False(t, router.HasHandler(BlockTypePadding))
}

// TestBlockRouter_RegisterHandlerFunc verifies function handler registration.
func TestBlockRouter_RegisterHandlerFunc(t *testing.T) {
	router := NewBlockRouter()

	called := false
	router.RegisterHandlerFunc([]uint8{BlockTypePadding}, func(block *SSU2Block) (bool, error) {
		called = true
		return true, nil
	})

	block := NewSSU2Block(BlockTypePadding, []byte{0x00})
	err := router.RouteBlock(block)

	assert.NoError(t, err)
	assert.True(t, called)
}

// TestBlockRouter_RouteBlock verifies block routing.
func TestBlockRouter_RouteBlock(t *testing.T) {
	router := NewBlockRouter()

	handler := &mockBlockHandler{
		supportedTypes: []uint8{BlockTypeDateTime},
	}
	router.RegisterHandler(handler)

	block := NewSSU2Block(BlockTypeDateTime, []byte{0x00, 0x00, 0x00, 0x01})
	err := router.RouteBlock(block)

	assert.NoError(t, err)
	assert.Equal(t, 1, handler.getHandledCount())
}

// TestBlockRouter_RouteNilBlock verifies error for nil block.
func TestBlockRouter_RouteNilBlock(t *testing.T) {
	router := NewBlockRouter()
	err := router.RouteBlock(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil block")
}

// TestBlockRouter_UnknownBlockLogged verifies unknown blocks are tracked.
func TestBlockRouter_UnknownBlockLogged(t *testing.T) {
	router := NewBlockRouter()

	// Route a block with no handler
	block := NewSSU2Block(255, []byte{0x01, 0x02})
	err := router.RouteBlock(block)

	assert.NoError(t, err) // Should not error, just log
	stats := router.GetStats()
	assert.Equal(t, uint64(1), stats.UnknownBlocks)
}

// TestBlockRouter_DefaultHandler verifies default handler fallback.
func TestBlockRouter_DefaultHandler(t *testing.T) {
	router := NewBlockRouter()

	defaultHandler := &mockBlockHandler{
		supportedTypes: []uint8{}, // Empty - this is the default handler
	}
	router.SetDefaultHandler(defaultHandler)

	// Route a block with no specific handler
	block := NewSSU2Block(255, []byte{0x01, 0x02})
	err := router.RouteBlock(block)

	assert.NoError(t, err)
	assert.Equal(t, 1, defaultHandler.getHandledCount())

	stats := router.GetStats()
	// Default handler was used, so unknown count should be 0
	assert.Equal(t, uint64(0), stats.UnknownBlocks)
}

// TestBlockRouter_RouteBlocks verifies batch block routing.
func TestBlockRouter_RouteBlocks(t *testing.T) {
	router := NewBlockRouter()

	handler := &mockBlockHandler{
		supportedTypes: []uint8{BlockTypeDateTime, BlockTypeOptions},
	}
	router.RegisterHandler(handler)

	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, []byte{0x00, 0x00, 0x00, 0x01}),
		NewSSU2Block(BlockTypeOptions, make([]byte, 15)),
		NewSSU2Block(BlockTypeDateTime, []byte{0x00, 0x00, 0x00, 0x02}),
	}

	err := router.RouteBlocks(blocks)

	assert.NoError(t, err)
	assert.Equal(t, 3, handler.getHandledCount())
}

// TestBlockRouter_GetStats verifies statistics tracking.
func TestBlockRouter_GetStats(t *testing.T) {
	router := NewBlockRouter()

	handler := &mockBlockHandler{
		supportedTypes: []uint8{BlockTypeDateTime},
	}
	router.RegisterHandler(handler)

	// Route some blocks
	for i := 0; i < 5; i++ {
		block := NewSSU2Block(BlockTypeDateTime, []byte{0x00, 0x00, 0x00, byte(i)})
		_ = router.RouteBlock(block)
	}

	// Route unknown blocks
	for i := 0; i < 3; i++ {
		block := NewSSU2Block(255, []byte{byte(i)})
		_ = router.RouteBlock(block)
	}

	stats := router.GetStats()
	assert.Equal(t, uint64(5), stats.BlocksRouted[BlockTypeDateTime])
	assert.Equal(t, uint64(3), stats.BlocksRouted[255])
	assert.Equal(t, uint64(3), stats.UnknownBlocks)
	assert.Equal(t, uint64(0), stats.RoutingErrors)
}

// TestBlockRouter_ConcurrentAccess verifies thread safety.
func TestBlockRouter_ConcurrentAccess(t *testing.T) {
	router := NewBlockRouter()

	handler := &mockBlockHandler{
		supportedTypes: []uint8{BlockTypeDateTime},
	}
	router.RegisterHandler(handler)

	var wg sync.WaitGroup
	const numGoroutines = 10
	const blocksPerGoroutine = 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < blocksPerGoroutine; j++ {
				block := NewSSU2Block(BlockTypeDateTime, []byte{0x00, 0x00, 0x00, 0x01})
				_ = router.RouteBlock(block)
			}
		}()
	}

	wg.Wait()

	stats := router.GetStats()
	assert.Equal(t, uint64(numGoroutines*blocksPerGoroutine), stats.BlocksRouted[BlockTypeDateTime])
}
