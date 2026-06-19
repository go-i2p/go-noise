package session

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDataHandler(t *testing.T) {
	tests := []struct {
		name      string
		queueSize int
		expected  int
	}{
		{
			name:      "default queue size",
			queueSize: 0,
			expected:  100,
		},
		{
			name:      "negative queue size uses default",
			queueSize: -5,
			expected:  100,
		},
		{
			name:      "custom queue size",
			queueSize: 50,
			expected:  50,
		},
		{
			name:      "large queue size",
			queueSize: 1000,
			expected:  1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewDataHandler(tt.queueSize)
			require.NotNil(t, handler)
			assert.NotNil(t, handler.messageQueue)
			assert.NotNil(t, handler.fragments)
			assert.Equal(t, tt.expected, cap(handler.messageQueue))
			assert.Equal(t, 0, len(handler.fragments))
		})
	}
}

func TestDataHandler_ProcessDataPacket_InvalidType(t *testing.T) {
	handler := NewDataHandler(10)

	// Create packet with wrong message type
	packet := &SSU2Packet{
		MessageType: MessageTypeSessionRequest, // Wrong type
		Payload:     []byte{},
	}

	blocks, err := handler.ProcessDataPacket(packet)
	assert.Error(t, err)
	assert.Nil(t, blocks)
	assert.Contains(t, err.Error(), "expected Data packet")
}

func TestDataHandler_ProcessDataPacket_MalformedBlocks(t *testing.T) {
	handler := NewDataHandler(10)

	// Create packet with invalid block data
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     []byte{0xFF, 0xFF}, // Invalid TLV data
	}

	blocks, err := handler.ProcessDataPacket(packet)
	assert.Error(t, err)
	assert.Nil(t, blocks)
	assert.Contains(t, err.Error(), "failed to deserialize blocks")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_ProcessDataPacket_I2NPMessage(t *testing.T) {
	handler := NewDataHandler(10)

	// Create I2NP message block
	i2npData := []byte("Test I2NP Message Data")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)

	// Serialize blocks
	blocks := []*SSU2Block{block}
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)

	// Create Data packet
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	returnedBlocks, err := handler.ProcessDataPacket(packet)
	require.NoError(t, err)
	assert.Len(t, returnedBlocks, 1)

	// Verify message was queued
	assert.True(t, handler.HasMessages())
	msg := handler.GetMessage()
	require.NotNil(t, msg)
	assert.Equal(t, i2npData, msg)

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesReceived)
	assert.Equal(t, uint64(0), stats.MessagesDropped)
}

func TestDataHandler_ProcessDataPacket_EmptyI2NPMessage(t *testing.T) {
	handler := NewDataHandler(10)

	// Create empty I2NP message block
	block := NewSSU2Block(BlockTypeI2NPMessage, []byte{})

	// Serialize blocks
	blocks := []*SSU2Block{block}
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)

	// Create Data packet
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	returnedBlocks, err := handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.NotNil(t, returnedBlocks) // Blocks are returned even on error
	assert.Contains(t, err.Error(), "I2NP message block is empty")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(0), stats.MessagesReceived)
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_ProcessDataPacket_MultipleBlocks(t *testing.T) {
	handler := NewDataHandler(10)

	// Create multiple I2NP message blocks
	i2npData1 := []byte("Message 1")
	i2npData2 := []byte("Message 2")
	i2npData3 := []byte("Message 3")

	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeI2NPMessage, i2npData1),
		NewSSU2Block(BlockTypeI2NPMessage, i2npData2),
		NewSSU2Block(BlockTypeI2NPMessage, i2npData3),
	}

	// Serialize blocks
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)

	// Create Data packet
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	returnedBlocks, err := handler.ProcessDataPacket(packet)
	require.NoError(t, err)
	assert.Len(t, returnedBlocks, 3)

	// Verify all messages were queued
	msg1 := handler.GetMessage()
	msg2 := handler.GetMessage()
	msg3 := handler.GetMessage()

	require.NotNil(t, msg1)
	require.NotNil(t, msg2)
	require.NotNil(t, msg3)

	assert.Equal(t, i2npData1, msg1)
	assert.Equal(t, i2npData2, msg2)
	assert.Equal(t, i2npData3, msg3)

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(3), stats.MessagesReceived)
}

func TestDataHandler_ProcessDataPacket_MixedBlocks(t *testing.T) {
	handler := NewDataHandler(10)

	// Create mixed block types
	i2npData := []byte("I2NP Message")
	dateTimeData := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // 7-byte timestamp (minimum)
	paddingData := make([]byte, 16)

	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, dateTimeData),
		NewSSU2Block(BlockTypeI2NPMessage, i2npData),
		NewSSU2Block(BlockTypePadding, paddingData),
	}

	// Serialize blocks
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)

	// Create Data packet
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	returnedBlocks, err := handler.ProcessDataPacket(packet)
	require.NoError(t, err)
	assert.Len(t, returnedBlocks, 3)

	// Only I2NP message should be queued
	assert.True(t, handler.HasMessages())
	msg := handler.GetMessage()
	require.NotNil(t, msg)
	assert.Equal(t, i2npData, msg)

	// No more messages
	assert.False(t, handler.HasMessages())
}

func TestDataHandler_FirstFragment(t *testing.T) {
	handler := NewDataHandler(10)

	// Create first fragment
	messageID := uint32(12345)
	fragmentData := []byte("First fragment data")

	// Build first fragment block data per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	blockData := make([]byte, 9+len(fragmentData))
	blockData[0] = 11 // I2NP type (e.g., DatabaseStore)
	binary.BigEndian.PutUint32(blockData[1:5], messageID)
	binary.BigEndian.PutUint32(blockData[5:9], uint32(time.Now().Unix())) // shortExpiration
	copy(blockData[9:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Verify fragment set created
	assert.Equal(t, 1, handler.GetFragmentCount())

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.FragmentsReceived)
	assert.Equal(t, uint64(0), stats.MessagesReassembled)

	// No complete message yet
	assert.False(t, handler.HasMessages())
}

func TestDataHandler_FirstFragment_TooShort(t *testing.T) {
	handler := NewDataHandler(10)

	// Create invalid first fragment (too short - need at least 9 bytes)
	blockData := []byte{0x00, 0x01, 0x02, 0x03, 0x04} // Only 5 bytes

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet should fail
	_, err = handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "first fragment too short")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_FirstFragment_Duplicate(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	fragmentData := []byte("First fragment data")

	// Build first fragment block data per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	blockData := make([]byte, 9+len(fragmentData))
	blockData[0] = 11 // I2NP type
	binary.BigEndian.PutUint32(blockData[1:5], messageID)
	binary.BigEndian.PutUint32(blockData[5:9], uint32(time.Now().Unix()))
	copy(blockData[9:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process first fragment
	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Process duplicate first fragment — retransmissions are silently accepted
	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Verify stats - duplicate first fragment is not counted as dropped
	stats := handler.GetStats()
	assert.Equal(t, uint64(0), stats.MessagesDropped)
}

func TestDataHandler_FollowOnFragment(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	firstData := []byte("First fragment data")
	secondData := []byte("Second fragment data")

	// Send first fragment per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	firstBlockData := make([]byte, 9+len(firstData))
	firstBlockData[0] = 11 // I2NP type
	binary.BigEndian.PutUint32(firstBlockData[1:5], messageID)
	binary.BigEndian.PutUint32(firstBlockData[5:9], uint32(time.Now().Unix()))
	copy(firstBlockData[9:], firstData)

	firstBlock := NewSSU2Block(BlockTypeFirstFragment, firstBlockData)
	payload1, err := SerializeBlocks([]*SSU2Block{firstBlock})
	require.NoError(t, err)

	packet1 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload1,
	}

	_, err = handler.ProcessDataPacket(packet1)
	require.NoError(t, err)
	assert.Equal(t, 1, handler.GetFragmentCount())

	// Send follow-on fragment per spec: FragInfo(1) + MessageID(4) + Data
	followOnBlockData := make([]byte, 5+len(secondData))
	followOnBlockData[0] = (1 << 1) | 0x01 // fragNum=1, isLast=true
	binary.BigEndian.PutUint32(followOnBlockData[1:5], messageID)
	copy(followOnBlockData[5:], secondData)

	followOnBlock := NewSSU2Block(BlockTypeFollowOnFragment, followOnBlockData)
	payload2, err := SerializeBlocks([]*SSU2Block{followOnBlock})
	require.NoError(t, err)

	packet2 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload2,
	}

	_, err = handler.ProcessDataPacket(packet2)
	require.NoError(t, err)

	// Message should be complete and queued
	if !handler.HasMessages() {
		t.Logf("Fragment count: %d, Received size: %d", handler.GetFragmentCount(), uint32(len(firstData)+len(secondData)))
	}
	assert.True(t, handler.HasMessages())
	msg := handler.GetMessage()
	require.NotNil(t, msg)

	// Verify reassembled message has 9-byte I2NP short header prepended (G-3)
	var expected []byte
	expected = append(expected, firstBlockData[:9]...)
	expected = append(expected, firstData...)
	expected = append(expected, secondData...)
	assert.Equal(t, expected, msg)

	// Fragment set should be cleaned up
	assert.Equal(t, 0, handler.GetFragmentCount())

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(2), stats.FragmentsReceived)
	assert.Equal(t, uint64(1), stats.MessagesReassembled)
}

func TestDataHandler_FollowOnFragment_TooShort(t *testing.T) {
	handler := NewDataHandler(10)

	// Create invalid follow-on fragment (too short - need at least 5 bytes)
	blockData := []byte{0x00, 0x01} // Only 2 bytes

	block := NewSSU2Block(BlockTypeFollowOnFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet should fail
	_, err = handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "follow-on fragment too short")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_FollowOnFragment_UnknownMessageID(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(99999)
	fragmentData := []byte("Fragment data")

	// Build follow-on fragment without first fragment per spec: FragInfo(1) + MessageID(4) + Data
	blockData := make([]byte, 5+len(fragmentData))
	blockData[0] = (1 << 1) // fragNum=1, isLast=false
	binary.BigEndian.PutUint32(blockData[1:5], messageID)
	copy(blockData[5:], fragmentData)

	block := NewSSU2Block(BlockTypeFollowOnFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet should succeed — early FollowOnFragments are buffered
	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Verify fragment was buffered
	assert.Equal(t, 1, handler.GetFragmentCount())
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.FragmentsReceived)
}

func TestDataHandler_FollowOnFragment_Duplicate(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	firstData := []byte("First fragment data")

	// Send first fragment per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	firstBlockData := make([]byte, 9+len(firstData))
	firstBlockData[0] = 11 // I2NP type
	binary.BigEndian.PutUint32(firstBlockData[1:5], messageID)
	binary.BigEndian.PutUint32(firstBlockData[5:9], uint32(time.Now().Unix()))
	copy(firstBlockData[9:], firstData)

	firstBlock := NewSSU2Block(BlockTypeFirstFragment, firstBlockData)
	payload1, err := SerializeBlocks([]*SSU2Block{firstBlock})
	require.NoError(t, err)

	packet1 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload1,
	}

	_, err = handler.ProcessDataPacket(packet1)
	require.NoError(t, err)

	// Send same follow-on fragment twice per spec: FragInfo(1) + MessageID(4) + Data
	fragmentData := []byte("Follow-on data")
	followOnBlockData := make([]byte, 5+len(fragmentData))
	followOnBlockData[0] = (1 << 1) // fragNum=1, isLast=false
	binary.BigEndian.PutUint32(followOnBlockData[1:5], messageID)
	copy(followOnBlockData[5:], fragmentData)

	followOnBlock := NewSSU2Block(BlockTypeFollowOnFragment, followOnBlockData)
	payload2, err := SerializeBlocks([]*SSU2Block{followOnBlock})
	require.NoError(t, err)

	packet2 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload2,
	}

	// First follow-on should succeed
	_, err = handler.ProcessDataPacket(packet2)
	require.NoError(t, err)

	// Second should succeed silently (duplicate handling)
	_, err = handler.ProcessDataPacket(packet2)
	require.NoError(t, err)

	// Verify fragment count unchanged
	assert.Equal(t, 1, handler.GetFragmentCount())
}

func TestDataHandler_FragmentReassembly_MultiFragment(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	firstData := []byte("First")
	secondData := []byte("Second-Extra")

	// Send first fragment per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	firstBlockData := make([]byte, 9+len(firstData))
	firstBlockData[0] = 11 // I2NP type
	binary.BigEndian.PutUint32(firstBlockData[1:5], messageID)
	binary.BigEndian.PutUint32(firstBlockData[5:9], uint32(time.Now().Unix()))
	copy(firstBlockData[9:], firstData)

	firstBlock := NewSSU2Block(BlockTypeFirstFragment, firstBlockData)
	payload1, err := SerializeBlocks([]*SSU2Block{firstBlock})
	require.NoError(t, err)

	packet1 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload1,
	}

	_, err = handler.ProcessDataPacket(packet1)
	require.NoError(t, err)

	// Send follow-on fragment per spec: FragInfo(1) + MessageID(4) + Data
	followOnBlockData := make([]byte, 5+len(secondData))
	followOnBlockData[0] = (1 << 1) | 0x01 // fragNum=1, isLast=true
	binary.BigEndian.PutUint32(followOnBlockData[1:5], messageID)
	copy(followOnBlockData[5:], secondData)

	followOnBlock := NewSSU2Block(BlockTypeFollowOnFragment, followOnBlockData)
	payload2, err := SerializeBlocks([]*SSU2Block{followOnBlock})
	require.NoError(t, err)

	packet2 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload2,
	}

	// Process - should trigger reassembly and succeed
	_, err = handler.ProcessDataPacket(packet2)
	require.NoError(t, err)

	// Fragment set should be cleaned up
	assert.Equal(t, 0, handler.GetFragmentCount())

	// Verify the reassembled message has 9-byte I2NP short header prepended (G-3)
	assert.True(t, handler.HasMessages())
	msg := handler.GetMessage()
	var expected []byte
	expected = append(expected, firstBlockData[:9]...)
	expected = append(expected, firstData...)
	expected = append(expected, secondData...)
	assert.Equal(t, expected, msg)

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesReassembled)
}

// TestDataHandler_FragmentReassembly_OversizedMessage verifies that reassembled
// messages exceeding the maximum I2NP message size (64 KB) are dropped rather
// than queued. This is a regression test for AUDIT.md MED-2: oversized message
// detection and rejection.
func TestDataHandler_FragmentReassembly_OversizedMessage(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(99999)

	// Build a message that will exceed 64 KB when reassembled (with 9-byte I2NP header)
	// We need: 9 (header) + first fragment size + follow-on fragment sizes > 65536
	// We'll create multiple fragments that together exceed the limit.

	// First fragment: 40KB of data
	firstData := make([]byte, 40*1024)
	firstBlockData := make([]byte, 9+len(firstData))
	firstBlockData[0] = 42 // I2NP type
	binary.BigEndian.PutUint32(firstBlockData[1:5], messageID)
	binary.BigEndian.PutUint32(firstBlockData[5:9], uint32(time.Now().Unix()))
	copy(firstBlockData[9:], firstData)

	firstBlock := NewSSU2Block(BlockTypeFirstFragment, firstBlockData)
	payload1, err := SerializeBlocks([]*SSU2Block{firstBlock})
	require.NoError(t, err)

	packet1 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload1,
	}

	_, err = handler.ProcessDataPacket(packet1)
	require.NoError(t, err)

	// Second fragment: 26KB of data (total: 9 + 40K + 26K = 66,073 > 65,536)
	secondData := make([]byte, 26*1024)
	followOnBlockData := make([]byte, 5+len(secondData))
	followOnBlockData[0] = (1 << 1) | 0x01 // fragNum=1, isLast=true
	binary.BigEndian.PutUint32(followOnBlockData[1:5], messageID)
	copy(followOnBlockData[5:], secondData)

	followOnBlock := NewSSU2Block(BlockTypeFollowOnFragment, followOnBlockData)
	payload2, err := SerializeBlocks([]*SSU2Block{followOnBlock})
	require.NoError(t, err)

	packet2 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload2,
	}

	// Process - should attempt reassembly, detect oversized message, and drop it
	_, err = handler.ProcessDataPacket(packet2)
	require.NoError(t, err) // No error returned; message silently dropped

	// Fragment set should be cleaned up (deleted after size check)
	assert.Equal(t, 0, handler.GetFragmentCount())

	// No message should be queued
	assert.False(t, handler.HasMessages())
	msg := handler.GetMessage()
	assert.Nil(t, msg)

	// Verify stats: message should be counted as dropped
	stats := handler.GetStats()
	assert.Equal(t, uint64(0), stats.MessagesReassembled, "oversized message should not be reassembled")
	assert.Equal(t, uint64(1), stats.MessagesDropped, "oversized message should be counted as dropped")
}

func TestDataHandler_GetMessage_NonBlocking(t *testing.T) {
	handler := NewDataHandler(10)

	// Queue a message
	i2npData := []byte("Test message")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Get message (non-blocking)
	msg := handler.GetMessage()
	require.NotNil(t, msg)
	assert.Equal(t, i2npData, msg)

	// No more messages
	msg = handler.GetMessage()
	assert.Nil(t, msg)
}

func TestDataHandler_GetMessageBlocking_WithTimeout(t *testing.T) {
	handler := NewDataHandler(10)

	// Test timeout with no messages
	start := time.Now()
	msg := handler.GetMessageBlocking(50 * time.Millisecond)
	elapsed := time.Since(start)

	assert.Nil(t, msg)
	assert.True(t, elapsed >= 50*time.Millisecond, "should wait at least 50ms")
	assert.True(t, elapsed < 100*time.Millisecond, "should not wait much longer than 50ms")
}

func TestDataHandler_GetMessageBlocking_WithMessage(t *testing.T) {
	handler := NewDataHandler(10)

	// Queue a message in a goroutine after a delay
	i2npData := []byte("Delayed message")
	go func() {
		time.Sleep(20 * time.Millisecond)
		block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}
		handler.ProcessDataPacket(packet)
	}()

	// Get message with timeout
	start := time.Now()
	msg := handler.GetMessageBlocking(100 * time.Millisecond)
	elapsed := time.Since(start)

	require.NotNil(t, msg)
	assert.Equal(t, i2npData, msg)
	assert.True(t, elapsed >= 20*time.Millisecond, "should wait at least 20ms")
	assert.True(t, elapsed < 50*time.Millisecond, "should not wait much longer than message arrival")
}

func TestDataHandler_HasMessages(t *testing.T) {
	handler := NewDataHandler(10)

	// Initially no messages
	assert.False(t, handler.HasMessages())

	// Queue a message
	i2npData := []byte("Test message")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Should have messages now
	assert.True(t, handler.HasMessages())

	// Retrieve message
	handler.GetMessage()

	// No more messages
	assert.False(t, handler.HasMessages())
}

func TestDataHandler_CleanupExpiredFragments(t *testing.T) {
	handler := NewDataHandler(10)

	messageID1 := uint32(12345)
	messageID2 := uint32(67890)
	fragmentData := []byte("Fragment data")

	// Create two fragment sets per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	for _, msgID := range []uint32{messageID1, messageID2} {
		blockData := make([]byte, 9+len(fragmentData))
		blockData[0] = 11 // I2NP type
		binary.BigEndian.PutUint32(blockData[1:5], msgID)
		binary.BigEndian.PutUint32(blockData[5:9], uint32(time.Now().Unix()))
		copy(blockData[9:], fragmentData)

		block := NewSSU2Block(BlockTypeFirstFragment, blockData)
		payload, err := SerializeBlocks([]*SSU2Block{block})
		require.NoError(t, err)

		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err = handler.ProcessDataPacket(packet)
		require.NoError(t, err)
	}

	// Both fragment sets should exist
	assert.Equal(t, 2, handler.GetFragmentCount())

	// Wait a bit and cleanup with short timeout
	time.Sleep(10 * time.Millisecond)
	removed := handler.CleanupExpiredFragments(5 * time.Millisecond)

	// Both should be removed
	assert.Equal(t, 2, removed)
	assert.Equal(t, 0, handler.GetFragmentCount())

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(2), stats.MessagesDropped) // 2 from cleanup
}

func TestDataHandler_CleanupExpiredFragments_NoExpired(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	fragmentData := []byte("Fragment data")

	// Create fragment set per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	blockData := make([]byte, 9+len(fragmentData))
	blockData[0] = 11 // I2NP type
	binary.BigEndian.PutUint32(blockData[1:5], messageID)
	binary.BigEndian.PutUint32(blockData[5:9], uint32(time.Now().Unix()))
	copy(blockData[9:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Fragment set should exist
	assert.Equal(t, 1, handler.GetFragmentCount())

	// Cleanup with long timeout - nothing should be removed
	removed := handler.CleanupExpiredFragments(1 * time.Hour)
	assert.Equal(t, 0, removed)
	assert.Equal(t, 1, handler.GetFragmentCount())
}

func TestDataHandler_GetStats(t *testing.T) {
	handler := NewDataHandler(10)

	// Initial stats should be zero
	stats := handler.GetStats()
	assert.Equal(t, uint64(0), stats.MessagesReceived)
	assert.Equal(t, uint64(0), stats.FragmentsReceived)
	assert.Equal(t, uint64(0), stats.MessagesReassembled)
	assert.Equal(t, uint64(0), stats.MessagesDropped)

	// Process some messages
	i2npData := []byte("Test message")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Check updated stats
	stats = handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesReceived)
}

func TestDataHandler_GetFragmentCount(t *testing.T) {
	handler := NewDataHandler(10)

	// Initially zero
	assert.Equal(t, 0, handler.GetFragmentCount())

	// Add fragment per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	messageID := uint32(12345)
	fragmentData := []byte("Fragment data")

	blockData := make([]byte, 9+len(fragmentData))
	blockData[0] = 11 // I2NP type
	binary.BigEndian.PutUint32(blockData[1:5], messageID)
	binary.BigEndian.PutUint32(blockData[5:9], uint32(time.Now().Unix()))
	copy(blockData[9:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Should have one fragment set
	assert.Equal(t, 1, handler.GetFragmentCount())
}

func TestDataHandler_Clear(t *testing.T) {
	handler := NewDataHandler(10)

	// Queue messages
	for i := 0; i < 3; i++ {
		i2npData := []byte("Test message")
		block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
		payload, err := SerializeBlocks([]*SSU2Block{block})
		require.NoError(t, err)

		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err = handler.ProcessDataPacket(packet)
		require.NoError(t, err)
	}

	// Add fragments per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	messageID := uint32(12345)
	fragmentData := []byte("Fragment data")

	blockData := make([]byte, 9+len(fragmentData))
	blockData[0] = 11 // I2NP type
	binary.BigEndian.PutUint32(blockData[1:5], messageID)
	binary.BigEndian.PutUint32(blockData[5:9], uint32(time.Now().Unix()))
	copy(blockData[9:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Verify we have messages and fragments
	assert.True(t, handler.HasMessages())
	assert.Equal(t, 1, handler.GetFragmentCount())

	// Clear everything
	handler.Clear()

	// Everything should be gone
	assert.False(t, handler.HasMessages())
	assert.Equal(t, 0, handler.GetFragmentCount())
}

func TestDataHandler_QueueFull(t *testing.T) {
	handler := NewDataHandler(2) // Small queue

	// Fill queue
	for i := 0; i < 2; i++ {
		i2npData := []byte("Test message")
		block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
		payload, err := SerializeBlocks([]*SSU2Block{block})
		require.NoError(t, err)

		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err = handler.ProcessDataPacket(packet)
		require.NoError(t, err)
	}

	// Try to add one more - should fail
	i2npData := []byte("Test message")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "queue full")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(2), stats.MessagesReceived)
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

// Benchmarks

func BenchmarkDataHandler_ProcessI2NPMessage(b *testing.B) {
	handler := NewDataHandler(1000)

	// Create I2NP message packet
	i2npData := make([]byte, 1024) // 1KB message
	for i := range i2npData {
		i2npData[i] = byte(i % 256)
	}

	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, _ := SerializeBlocks([]*SSU2Block{block})

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ProcessDataPacket(packet)

		// Drain queue to avoid filling up
		if i%100 == 0 {
			for handler.HasMessages() {
				handler.GetMessage()
			}
		}
	}
}

func BenchmarkDataHandler_ProcessFragments(b *testing.B) {
	handler := NewDataHandler(1000)

	// Create first fragment packet per spec: I2NPType(1) + MessageID(4) + ShortExp(4) + Data
	messageID := uint32(12345)
	fragmentData := make([]byte, 1024)

	firstBlockData := make([]byte, 9+len(fragmentData))
	firstBlockData[0] = 11 // I2NP type
	binary.BigEndian.PutUint32(firstBlockData[1:5], messageID)
	binary.BigEndian.PutUint32(firstBlockData[5:9], uint32(time.Now().Unix()))
	copy(firstBlockData[9:], fragmentData)

	firstBlock := NewSSU2Block(BlockTypeFirstFragment, firstBlockData)
	payload1, _ := SerializeBlocks([]*SSU2Block{firstBlock})

	packet1 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.Clear() // Clear between iterations
		handler.ProcessDataPacket(packet1)
	}
}

func BenchmarkDataHandler_GetMessage(b *testing.B) {
	handler := NewDataHandler(10000)

	// Pre-fill queue
	i2npData := []byte("Test message data")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, _ := SerializeBlocks([]*SSU2Block{block})

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	for i := 0; i < 1000; i++ {
		handler.ProcessDataPacket(packet)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := handler.GetMessage()
		if msg == nil {
			// Refill queue
			for j := 0; j < 1000; j++ {
				handler.ProcessDataPacket(packet)
			}
		}
	}
}

func BenchmarkDataHandler_CleanupFragments(b *testing.B) {
	handler := NewDataHandler(10)

	// Create some expired fragments
	for i := 0; i < 100; i++ {
		messageID := uint32(i)
		fragmentData := []byte("Fragment data")

		blockData := make([]byte, 9+len(fragmentData))
		blockData[0] = 11 // I2NP type
		binary.BigEndian.PutUint32(blockData[1:5], messageID)
		binary.BigEndian.PutUint32(blockData[5:9], uint32(time.Now().Unix()))
		copy(blockData[9:], fragmentData)

		block := NewSSU2Block(BlockTypeFirstFragment, blockData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})

		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		handler.ProcessDataPacket(packet)
	}

	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.CleanupExpiredFragments(1 * time.Millisecond)
	}
}

// ============================================================================
// Tests for All 20 Block Type Handlers
// ============================================================================

// TestDataHandler_AllBlockTypesExplicitlyHandled verifies all 20 block types
// have explicit handlers and are processed without errors.
func TestDataHandler_AllBlockTypesExplicitlyHandled(t *testing.T) {
	handler := NewDataHandler(100)

	// Define test data for each block type with correct minimum sizes
	tests := []struct {
		blockType uint8
		name      string
		data      []byte
	}{
		{BlockTypeDateTime, "DateTime", make([]byte, 7)},       // minDateTimeSize = 7
		{BlockTypeOptions, "Options", make([]byte, 12)},        // minOptionsSize = 12
		{BlockTypeRouterInfo, "RouterInfo", make([]byte, 100)}, // Variable
		{BlockTypeI2NPMessage, "I2NPMessage", []byte("test i2np message")},
		{BlockTypeFirstFragment, "FirstFragment", append([]byte{11, 0, 0, 0, 1, 0, 0, 0, 0}, make([]byte, 50)...)},
		{BlockTypeFollowOnFragment, "FollowOnFragment", append([]byte{0x02, 0, 0, 0, 1}, make([]byte, 50)...)},
		{BlockTypeTermination, "Termination", make([]byte, 9)},      // minTerminationSize = 9
		{BlockTypeRelayRequest, "RelayRequest", make([]byte, 50)},   // Variable
		{BlockTypeRelayResponse, "RelayResponse", make([]byte, 50)}, // Variable
		{BlockTypeRelayIntro, "RelayIntro", make([]byte, 50)},       // Variable
		{BlockTypePeerTest, "PeerTest", make([]byte, 50)},           // Variable
		{BlockTypeACK, "ACK", make([]byte, 5)},                      // minACKSize = 5
		{BlockTypeNextNonce, "NextNonce", make([]byte, 8)},          // minNextNonceSize = 8
		{BlockTypeAddress, "Address", make([]byte, 9)},              // minAddressSizeIPv4 = 9
		{BlockTypeRelayTagRequest, "RelayTagRequest", nil},          // minRelayTagRequestSize = 0
		{BlockTypeRelayTag, "RelayTag", make([]byte, 4)},            // minRelayTagSize = 4
		{BlockTypeNewToken, "NewToken", make([]byte, 12)},           // minNewTokenSize = 12
		{BlockTypePathChallenge, "PathChallenge", make([]byte, 8)},  // Variable
		{BlockTypePathResponse, "PathResponse", make([]byte, 8)},    // Variable
		{BlockTypePadding, "Padding", make([]byte, 16)},             // Variable
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			block := NewSSU2Block(tc.blockType, tc.data)
			payload, err := SerializeBlocks([]*SSU2Block{block})
			require.NoError(t, err)

			packet := &SSU2Packet{
				MessageType: MessageTypeData,
				Payload:     payload,
			}

			blocks, err := handler.ProcessDataPacket(packet)
			assert.NoError(t, err)
			assert.Len(t, blocks, 1)
			assert.Equal(t, tc.blockType, blocks[0].Type)
		})
	}
}

// TestDataHandler_SetCallbacks verifies callback registration and invocation.
func TestDataHandler_SetCallbacks(t *testing.T) {
	handler := NewDataHandler(100)

	var terminationCalled bool
	var terminationReason uint8
	var newTokenCalled bool
	var dateTimeCalled bool
	var dateTimeValue uint32

	handler.SetCallbacks(DataHandlerCallbacks{
		OnTermination: func(validDataReceived uint64, reason uint8, additionalData []byte) {
			terminationCalled = true
			terminationReason = reason
		},
		OnNewToken: func(token []byte) {
			newTokenCalled = true
		},
		OnDateTime: func(timestamp uint32) error {
			dateTimeCalled = true
			dateTimeValue = timestamp
			return nil
		},
	})

	// Test Termination callback
	t.Run("Termination callback", func(t *testing.T) {
		block := NewSSU2Block(BlockTypeTermination, make([]byte, 9)) // minTerminationSize = 9
		block.Data[8] = 0x05                                         // Set reason code (byte 8 per spec)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, terminationCalled)
		assert.Equal(t, uint8(0x05), terminationReason)
	})

	// Test NewToken callback
	t.Run("NewToken callback", func(t *testing.T) {
		block := NewSSU2Block(BlockTypeNewToken, make([]byte, 12)) // minNewTokenSize = 12
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, newTokenCalled)
	})

	// Test DateTime callback
	t.Run("DateTime callback", func(t *testing.T) {
		// DateTime needs 7 bytes minimum, timestamp in first 4 bytes: 0x12345678
		data := make([]byte, 7)
		data[0] = 0x12
		data[1] = 0x34
		data[2] = 0x56
		data[3] = 0x78
		block := NewSSU2Block(BlockTypeDateTime, data)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, dateTimeCalled)
		assert.Equal(t, uint32(0x12345678), dateTimeValue)
	})
}

// TestDataHandler_RelayCallbacks verifies relay block callbacks.
func TestDataHandler_RelayCallbacks(t *testing.T) {
	handler := NewDataHandler(100)

	var relayRequestCalled, relayResponseCalled, relayIntroCalled bool
	var relayTagRequestCalled, relayTagCalled bool

	dummySig := make([]byte, 64)

	handler.SetCallbacks(DataHandlerCallbacks{
		OnRelayRequest: func(block *SSU2Block) error {
			relayRequestCalled = true
			return nil
		},
		OnRelayResponse: func(block *SSU2Block) error {
			relayResponseCalled = true
			return nil
		},
		OnRelayIntro: func(block *SSU2Block) error {
			relayIntroCalled = true
			return nil
		},
		OnRelayTagRequest: func(block *SSU2Block) error {
			relayTagRequestCalled = true
			return nil
		},
		OnRelayTag: func(block *SSU2Block) error {
			relayTagCalled = true
			return nil
		},
		// Pass-through verifiers for testing (G-2)
		VerifyRelayRequestSignature:  func(block *RelayRequestBlock) error { return nil },
		VerifyRelayResponseSignature: func(block *RelayResponseBlock) error { return nil },
		VerifyRelayIntroSignature:    func(block *RelayIntroBlock) error { return nil },
	})

	t.Run("RelayRequest", func(t *testing.T) {
		relayRequestCalled = false
		block, err := EncodeRelayRequest(&RelayRequestBlock{
			Nonce: 1, RelayTag: 2, Timestamp: 100, Version: 2,
			AlicePort: 8080, AliceIP: net.IPv4(127, 0, 0, 1),
			Signature: dummySig,
		})
		require.NoError(t, err)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		_, err = handler.ProcessDataPacket(&SSU2Packet{MessageType: MessageTypeData, Payload: payload})
		assert.NoError(t, err)
		assert.True(t, relayRequestCalled, "callback should have been called for RelayRequest")
	})

	t.Run("RelayResponse", func(t *testing.T) {
		relayResponseCalled = false
		// Code 1-63 (Bob rejection): no signature needed
		block, err := EncodeRelayResponse(&RelayResponseBlock{Code: 1, Nonce: 1})
		require.NoError(t, err)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		_, err = handler.ProcessDataPacket(&SSU2Packet{MessageType: MessageTypeData, Payload: payload})
		assert.NoError(t, err)
		assert.True(t, relayResponseCalled, "callback should have been called for RelayResponse")
	})

	t.Run("RelayIntro", func(t *testing.T) {
		relayIntroCalled = false
		block, err := EncodeRelayIntro(&RelayIntroBlock{
			AliceRouterHash: make([]byte, 32), Nonce: 1, AliceRelayTag: 2,
			Timestamp: 100, Version: 2, AlicePort: 8080,
			AliceIP: net.IPv4(127, 0, 0, 1), Signature: dummySig,
		})
		require.NoError(t, err)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		_, err = handler.ProcessDataPacket(&SSU2Packet{MessageType: MessageTypeData, Payload: payload})
		assert.NoError(t, err)
		assert.True(t, relayIntroCalled, "callback should have been called for RelayIntro")
	})

	t.Run("RelayTagRequest", func(t *testing.T) {
		relayTagRequestCalled = false
		block, err := EncodeRelayTagRequest(&RelayTagRequestBlock{})
		require.NoError(t, err)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		_, err = handler.ProcessDataPacket(&SSU2Packet{MessageType: MessageTypeData, Payload: payload})
		assert.NoError(t, err)
		assert.True(t, relayTagRequestCalled, "callback should have been called for RelayTagRequest")
	})

	t.Run("RelayTag", func(t *testing.T) {
		relayTagCalled = false
		block, err := EncodeRelayTag(&RelayTagBlock{RelayTag: 42})
		require.NoError(t, err)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		_, err = handler.ProcessDataPacket(&SSU2Packet{MessageType: MessageTypeData, Payload: payload})
		assert.NoError(t, err)
		assert.True(t, relayTagCalled, "callback should have been called for RelayTag")
	})
}

// TestDataHandler_PathValidationCallbacks verifies path validation callbacks.
func TestDataHandler_PathValidationCallbacks(t *testing.T) {
	handler := NewDataHandler(100)

	var pathChallengeCalled, pathResponseCalled bool
	var challengeData, responseData []byte

	handler.SetCallbacks(DataHandlerCallbacks{
		OnPathChallenge: func(data []byte) error {
			pathChallengeCalled = true
			challengeData = data
			return nil
		},
		OnPathResponse: func(data []byte) error {
			pathResponseCalled = true
			responseData = data
			return nil
		},
	})

	t.Run("PathChallenge callback", func(t *testing.T) {
		testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		block := NewSSU2Block(BlockTypePathChallenge, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, pathChallengeCalled)
		assert.Equal(t, testData, challengeData)
	})

	t.Run("PathResponse callback", func(t *testing.T) {
		testData := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
		block := NewSSU2Block(BlockTypePathResponse, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, pathResponseCalled)
		assert.Equal(t, testData, responseData)
	})
}

// TestDataHandler_UnknownBlockTypeLogged verifies unknown blocks are tracked.
func TestDataHandler_UnknownBlockTypeLogged(t *testing.T) {
	handler := NewDataHandler(100)

	// Unknown block type 255
	block := NewSSU2Block(255, []byte{0x01, 0x02, 0x03})
	payload, _ := SerializeBlocks([]*SSU2Block{block})
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	blocks, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.Len(t, blocks, 1)

	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.UnknownBlocks)
	assert.Equal(t, uint64(1), stats.BlocksProcessed)
}

// TestDataHandler_PaddingBlockIgnored verifies padding blocks are silently skipped.
func TestDataHandler_PaddingBlockIgnored(t *testing.T) {
	handler := NewDataHandler(100)

	// Create a packet with only padding
	block := NewSSU2Block(BlockTypePadding, make([]byte, 256))
	payload, _ := SerializeBlocks([]*SSU2Block{block})
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	blocks, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.Len(t, blocks, 1)

	stats := handler.GetStats()
	// Padding is processed but not counted as unknown
	assert.Equal(t, uint64(0), stats.UnknownBlocks)
	assert.Equal(t, uint64(1), stats.BlocksProcessed)
}

// TestDataHandler_BlocksProcessedStat verifies BlocksProcessed stat.
func TestDataHandler_BlocksProcessedStat(t *testing.T) {
	handler := NewDataHandler(100)

	// Create packet with multiple blocks
	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, make([]byte, 7)), // minDateTimeSize = 7
		NewSSU2Block(BlockTypeOptions, make([]byte, 15)),
		NewSSU2Block(BlockTypePadding, make([]byte, 16)),
		NewSSU2Block(BlockTypeI2NPMessage, []byte("test message")),
	}

	payload, _ := SerializeBlocks(blocks)
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)

	stats := handler.GetStats()
	assert.Equal(t, uint64(4), stats.BlocksProcessed)
}

// TestDataHandler_GetBlockRouter verifies router accessor.
func TestDataHandler_GetBlockRouter(t *testing.T) {
	handler := NewDataHandler(100)
	router := handler.GetBlockRouter()

	require.NotNil(t, router)
	assert.IsType(t, &BlockRouter{}, router)
}

// TestDataHandler_TerminationBlockShort verifies that malformed Termination blocks
// are rejected during deserialization (validation happens at deserialize time).
func TestDataHandler_TerminationBlockShort(t *testing.T) {
	handler := NewDataHandler(100)

	// Create raw bytes that bypass serialization validation
	// Block header: Type (1 byte) + Length (2 bytes) + Data
	// Type 6 (Termination) with 0-byte data (minimum is 5 bytes per SSU2 spec)
	rawPayload := []byte{0x06, 0x00, 0x00} // Type=6, Length=0

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     rawPayload,
	}

	// Malformed blocks are rejected during deserialization per SSU2 spec
	blocks, err := handler.ProcessDataPacket(packet)
	assert.Error(t, err) // Validation error during deserialization
	assert.Nil(t, blocks)
	assert.Contains(t, err.Error(), "Termination block too short")
}

// TestDataHandler_NewTokenBlockShort verifies that malformed NewToken blocks
// are rejected during deserialization (validation happens at deserialize time).
func TestDataHandler_NewTokenBlockShort(t *testing.T) {
	handler := NewDataHandler(100)

	// Create raw bytes with Type 17 (NewToken) and 2-byte data (minimum is 15 bytes per SSU2 spec)
	rawPayload := []byte{0x11, 0x00, 0x02, 0x01, 0x02} // Type=17, Length=2, Data=2 bytes

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     rawPayload,
	}

	// Malformed blocks are rejected during deserialization per SSU2 spec
	blocks, err := handler.ProcessDataPacket(packet)
	assert.Error(t, err) // Validation error during deserialization
	assert.Nil(t, blocks)
	assert.Contains(t, err.Error(), "NewToken block too short")
}

// TestDataHandler_DateTimeBlockShort verifies that malformed DateTime blocks
// are rejected during deserialization (validation happens at deserialize time).
func TestDataHandler_DateTimeBlockShort(t *testing.T) {
	handler := NewDataHandler(100)

	// Create raw bytes with Type 0 (DateTime) and 2-byte data (minimum is 7 bytes per SSU2 spec)
	rawPayload := []byte{0x00, 0x00, 0x02, 0x01, 0x02} // Type=0, Length=2, Data=2 bytes

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     rawPayload,
	}

	// Malformed blocks are rejected during deserialization per SSU2 spec
	blocks, err := handler.ProcessDataPacket(packet)
	assert.Error(t, err) // Validation error during deserialization
	assert.Nil(t, blocks)
	assert.Contains(t, err.Error(), "DateTime block too short")
}

// TestDataHandler_MultipleBlockTypes verifies mixed block handling.
func TestDataHandler_MultipleBlockTypes(t *testing.T) {
	handler := NewDataHandler(100)

	var terminationCalled, ackCalled bool
	handler.SetCallbacks(DataHandlerCallbacks{
		OnTermination: func(validDataReceived uint64, reason uint8, additionalData []byte) {
			terminationCalled = true
		},
		OnACK: func(block *SSU2Block) error {
			ackCalled = true
			return nil
		},
	})

	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),    // minDateTimeSize = 7
		NewSSU2Block(BlockTypeACK, make([]byte, 5)),         // minACKSize = 5
		NewSSU2Block(BlockTypeTermination, make([]byte, 9)), // minTerminationSize = 9, byte 8 is reason
		NewSSU2Block(BlockTypePadding, make([]byte, 16)),
	}
	blocks[2].Data[8] = 0x01 // Set termination reason (byte 8 per spec)

	payload, _ := SerializeBlocks(blocks)
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	result, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.Len(t, result, 4)
	assert.True(t, terminationCalled)
	assert.True(t, ackCalled)
}

// TestDataHandler_PeerTestCallback verifies PeerTest callback.
func TestDataHandler_PeerTestCallback(t *testing.T) {
	handler := NewDataHandler(100)

	var peerTestCalled bool
	var receivedBlock *SSU2Block

	dummySig := make([]byte, 64)

	handler.SetCallbacks(DataHandlerCallbacks{
		OnPeerTest: func(block *SSU2Block) error {
			peerTestCalled = true
			receivedBlock = block
			return nil
		},
		// Pass-through verifier for testing (G-2)
		VerifyPeerTestSignature: func(block *PeerTestBlock) error { return nil },
	})

	ptBlock := &PeerTestBlock{
		MessageCode: PeerTestRequest,
		Code:        0,
		Flag:        0,
		Version:     2,
		Nonce:       42,
		Timestamp:   100,
		AlicePort:   8080,
		AliceIP:     net.IPv4(127, 0, 0, 1).To4(),
		Signature:   dummySig,
	}
	block, err := EncodePeerTestBlock(ptBlock)
	require.NoError(t, err)
	payload, _ := SerializeBlocks([]*SSU2Block{block})
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.True(t, peerTestCalled)
	assert.Equal(t, BlockTypePeerTest, receivedBlock.Type)
}

// TestDataHandler_MetadataBlockCallbacks verifies metadata block callbacks.
func TestDataHandler_MetadataBlockCallbacks(t *testing.T) {
	handler := NewDataHandler(100)

	var optionsCalled, routerInfoCalled, addressCalled bool
	var optionsData, routerInfoData, addressData []byte

	handler.SetCallbacks(DataHandlerCallbacks{
		OnOptions: func(data []byte) error {
			optionsCalled = true
			optionsData = data
			return nil
		},
		OnRouterInfo: func(data []byte) error {
			routerInfoCalled = true
			routerInfoData = data
			return nil
		},
		OnAddress: func(data []byte) error {
			addressCalled = true
			addressData = data
			return nil
		},
	})

	t.Run("Options callback", func(t *testing.T) {
		testData := make([]byte, 15)
		block := NewSSU2Block(BlockTypeOptions, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, optionsCalled)
		assert.Equal(t, testData, optionsData)
	})

	t.Run("RouterInfo callback", func(t *testing.T) {
		testData := make([]byte, 100)
		block := NewSSU2Block(BlockTypeRouterInfo, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, routerInfoCalled)
		assert.Equal(t, testData, routerInfoData)
	})

	t.Run("Address callback", func(t *testing.T) {
		testData := make([]byte, 9) // IPv4 + port
		block := NewSSU2Block(BlockTypeAddress, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, addressCalled)
		assert.Equal(t, testData, addressData)
	})
}

// TestDataHandler_FragmentMapCapacity verifies that the fragments map is bounded
// to prevent memory exhaustion from fragmentation attacks (M-5 audit finding).
func TestDataHandler_FragmentMapCapacity(t *testing.T) {
	handler := NewDataHandler(10)

	// Send more unique first fragments than maxFragmentsPerConn
	burstSize := maxFragmentsPerConn + 100
	fragmentData := []byte("test data")

	for i := 0; i < burstSize; i++ {
		messageID := uint32(i + 1)

		// Build first fragment block
		blockData := make([]byte, 9+len(fragmentData))
		blockData[0] = 11 // I2NP type
		binary.BigEndian.PutUint32(blockData[1:5], messageID)
		binary.BigEndian.PutUint32(blockData[5:9], uint32(time.Now().Unix()))
		copy(blockData[9:], fragmentData)

		block := NewSSU2Block(BlockTypeFirstFragment, blockData)
		payload, err := SerializeBlocks([]*SSU2Block{block})
		require.NoError(t, err)

		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err = handler.ProcessDataPacket(packet)
		require.NoError(t, err)

		// Verify map size never exceeds limit
		fragmentCount := handler.GetFragmentCount()
		assert.LessOrEqual(t, fragmentCount, maxFragmentsPerConn,
			"fragment map size should not exceed maxFragmentsPerConn")
	}

	// Verify evictions occurred
	stats := handler.GetStats()
	assert.Greater(t, stats.MessagesDropped, uint64(0),
		"MessagesDropped should be incremented when evicting oldest fragments")

	// Final size should be exactly at limit
	assert.Equal(t, maxFragmentsPerConn, handler.GetFragmentCount(),
		"fragment map should stabilize at maxFragmentsPerConn")
}

// Test for MEDIUM-3 (M-3): Per-set fragment memory bound.
// Verify that fragments exceeding maxI2NPMessageSize (64 KB) are dropped immediately,
// preventing memory exhaustion attacks.
func TestDataHandler_FragmentMemoryBoundEnforced(t *testing.T) {
	handler := NewDataHandler(100)

	// Test 1: Send first fragment with huge size (shouldn't happen in practice,
	// but defense-in-depth). The first fragment's data size should be validated.
	// In this test, we construct a valid but very large first fragment.
	// Since maxI2NPMessageSize is 64 KB, a 65 KB first fragment should be rejected.
	oversizedData := make([]byte, maxI2NPMessageSize+1)

	// Construct a valid FirstFragment header but with oversized payload
	// Format: I2NP type(1) + messageID(4) + shortExpiration(4) + data
	messageID := uint32(100)
	firstFragData := make([]byte, 9+len(oversizedData))
	firstFragData[0] = 42 // I2NP type
	copy(firstFragData[1:5], []byte{0, 0, 0, byte(messageID)})
	copy(firstFragData[5:9], []byte{0, 0, 0, 0}) // shortExpiration
	copy(firstFragData[9:], oversizedData)

	err := handler.handleFirstFragment(firstFragData)
	// Error might be nil since we only validate after setting ReceivedSize.
	// Check that the fragment was dropped.
	assert.Equal(t, 0, handler.GetFragmentCount(),
		"oversized first fragment should be rejected (fragment set not created)")

	// Test 2: Send FollowOnFragments that accumulate beyond the limit.
	// Create a sequence of fragments that cumulatively exceed 64 KB.
	messageID2 := uint32(200)

	// First, send a valid first fragment with reasonable size (~40 KB)
	firstFragPayload := make([]byte, 40000)
	firstFragData2 := make([]byte, 9+len(firstFragPayload))
	firstFragData2[0] = 42 // I2NP type
	copy(firstFragData2[1:5], []byte{0, 0, 0, byte(messageID2)})
	copy(firstFragData2[5:9], []byte{0, 0, 0, 0}) // shortExpiration
	copy(firstFragData2[9:], firstFragPayload)

	err = handler.handleFirstFragment(firstFragData2)
	require.NoError(t, err)
	assert.Equal(t, 1, handler.GetFragmentCount(),
		"first fragment should be accepted")

	// Now send a FollowOnFragment that would push total over 64 KB.
	// FollowOnFragment format: FragInfo(1) + MessageID(4) + data
	// FragInfo: (fragNum << 1) | isLast
	followOnPayload := make([]byte, 30000) // This will push total to 70 KB
	followOnData := make([]byte, 5+len(followOnPayload))
	fragInfo := uint8((1 << 1) | 1) // fragNum=1, isLast=1
	followOnData[0] = fragInfo
	copy(followOnData[1:5], []byte{0, 0, 0, byte(messageID2)})
	copy(followOnData[5:], followOnPayload)

	err = handler.handleFollowOnFragment(followOnData)
	require.NoError(t, err)

	// After the oversized follow-on fragment, the fragment set should be dropped.
	assert.Equal(t, 0, handler.GetFragmentCount(),
		"fragment set should be dropped when ReceivedSize exceeds maxI2NPMessageSize")

	// Verify that MessagesDropped was incremented
	stats := handler.GetStats()
	assert.Greater(t, stats.MessagesDropped, uint64(0),
		"MessagesDropped should be incremented when dropping oversized messages")
}
