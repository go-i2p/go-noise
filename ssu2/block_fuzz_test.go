package ssu2

import (
	"encoding/binary"
	"testing"
)

// FuzzSSU2Block_Deserialize fuzzes the SSU2Block deserialization.
// It ensures the deserialize function handles malformed input gracefully
// without panicking or causing memory corruption.
//
// Run with: go test -fuzz=FuzzSSU2Block_Deserialize ./ssu2/
func FuzzSSU2Block_Deserialize(f *testing.F) {
	// Add seed corpus with valid and boundary cases
	// Empty block
	f.Add([]byte{})

	// Too short for header
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x00})

	// Valid header but no data (type 1, length 0)
	f.Add([]byte{byte(BlockTypeOptions), 0x00, 0x00})

	// Valid FirstFragment block (type 4, length 4)
	f.Add([]byte{byte(BlockTypeFirstFragment), 0x04, 0x00, 0x01, 0x02, 0x03, 0x04})

	// Valid FollowOnFragment block (type 5, length 8)
	f.Add([]byte{byte(BlockTypeFollowOnFragment), 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	// Length overflow - says 255 bytes but only has 3
	f.Add([]byte{byte(BlockTypeOptions), 0xFF, 0x00, 0x01, 0x02, 0x03})

	// Maximum length header
	f.Add([]byte{byte(BlockTypeOptions), 0xFF, 0xFF})

	// Valid Termination block (type 6)
	ri := make([]byte, 51)
	ri[0] = byte(BlockTypeTermination) // Type
	ri[1] = 0x30                       // Length low byte (48)
	ri[2] = 0x00                       // Length high byte
	f.Add(ri)

	// Valid Options block (type 1)
	i2np := make([]byte, 20)
	i2np[0] = byte(BlockTypeOptions)
	i2np[1] = 0x11
	i2np[2] = 0x00
	f.Add(i2np)

	// Padding block (type 254)
	padding := make([]byte, 10)
	padding[0] = byte(BlockTypePadding)
	padding[1] = 0x07
	padding[2] = 0x00
	f.Add(padding)

	// I2NPMessage block (type 3)
	term := make([]byte, 15)
	term[0] = byte(BlockTypeI2NPMessage)
	term[1] = 0x0C
	term[2] = 0x00
	f.Add(term)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		_, err := block.Deserialize(data)

		// We only care about panics and crashes, errors are expected
		// for malformed input
		if err == nil && len(data) >= 3 {
			// If decode succeeded, verify it's internally consistent
			if len(block.Data) > 0 {
				// Try to serialize and check it doesn't panic
				_, _ = block.Serialize()
			}
		}
	})
}

// FuzzDeserializeBlocks fuzzes the multi-block deserialization.
func FuzzDeserializeBlocks(f *testing.F) {
	// Valid single block
	f.Add([]byte{0x01, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04})

	// Two blocks back-to-back
	twoBlocks := []byte{
		0x04, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, // DateTime
		0xFE, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
	}
	f.Add(twoBlocks)

	// Block chain with different types
	chain := make([]byte, 30)
	chain[0] = 0x04 // DateTime
	chain[1] = 0x04
	chain[2] = 0x00
	chain[7] = 0x02 // ACK
	chain[8] = 0x08
	chain[9] = 0x00
	f.Add(chain)

	// Truncated second block
	f.Add([]byte{0x01, 0x01, 0x00, 0xFF, 0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		// DeserializeBlocks should not panic
		blocks, err := DeserializeBlocks(data)

		// If successful, verify each block is valid
		if err == nil && len(blocks) > 0 {
			for _, block := range blocks {
				if block != nil {
					// Serialize should not panic
					_, _ = block.Serialize()
				}
			}
		}
	})
}

// FuzzDecodeRelayRequest fuzzes RelayRequest block decoding.
func FuzzDecodeRelayRequest(f *testing.F) {
	// Valid relay request: nonce(4) + signedData(32) + flag(1) = 37 minimum
	valid := make([]byte, 40)
	valid[0] = BlockTypeRelayRequest
	binary.BigEndian.PutUint16(valid[1:3], 37)
	binary.BigEndian.PutUint32(valid[3:7], 12345) // Nonce
	// bytes 7-39: signed data (zeros ok)
	valid[39] = 0x01 // Flag
	f.Add(valid)

	// With router info fragment appended
	withFragment := make([]byte, 50)
	copy(withFragment, valid)
	binary.BigEndian.PutUint16(withFragment[1:3], 47) // Larger length
	f.Add(withFragment)

	// Wrong type
	wrongType := make([]byte, 40)
	wrongType[0] = 0xFF
	binary.BigEndian.PutUint16(wrongType[1:3], 37)
	f.Add(wrongType)

	// Too short
	f.Add([]byte{BlockTypeRelayRequest, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05})

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return // Can't decode base block
		}

		// Try to decode as RelayRequest - should not panic
		_, _ = DecodeRelayRequest(block)
	})
}

// FuzzDecodeRelayResponse fuzzes RelayResponse block decoding.
func FuzzDecodeRelayResponse(f *testing.F) {
	// Valid relay response per spec: flag(1)+code(1)+nonce(4)=6 minimum
	// For code 0 (accepted): +ts(4)+ver(1)+csz(1)+port(2)+ip(4)+sig(0)+token(8)=26
	valid := make([]byte, 29) // type(1)+size(2)+payload(26)
	valid[0] = BlockTypeRelayResponse
	binary.BigEndian.PutUint16(valid[1:3], 26) // Length
	valid[3] = 0                               // flag
	valid[4] = 0                               // code = accepted
	binary.BigEndian.PutUint32(valid[5:9], 12345)
	binary.BigEndian.PutUint32(valid[9:13], 1700000000) // timestamp
	valid[13] = 2                                       // ver
	valid[14] = 6                                       // csz (IPv4)
	binary.BigEndian.PutUint16(valid[15:17], 9000)      // port
	// bytes 17-20: IP (zeros ok)
	// bytes 21-28: token (zeros ok)
	f.Add(valid)

	// Bob rejection (code 1, minimal)
	failure := make([]byte, 9) // type(1)+size(2)+payload(6)
	failure[0] = BlockTypeRelayResponse
	binary.BigEndian.PutUint16(failure[1:3], 6) // Length
	failure[3] = 0                              // flag
	failure[4] = 1                              // code = Bob rejection
	binary.BigEndian.PutUint32(failure[5:9], 12345)
	f.Add(failure)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodeRelayResponse(block)
	})
}

// FuzzDecodeRelayIntro fuzzes RelayIntro block decoding.
func FuzzDecodeRelayIntro(f *testing.F) {
	// Valid relay intro per spec: flag(1)+hash(32)+nonce(4)+tag(4)+ts(4)+ver(1)+asz(1)+port(2)+ip(4) = 53
	valid := make([]byte, 56) // type(1)+len(2)+data(53)
	valid[0] = BlockTypeRelayIntro
	binary.BigEndian.PutUint16(valid[1:3], 53)           // Length
	valid[3] = 0                                         // Flag
	copy(valid[4:36], make([]byte, 32))                  // Router hash
	binary.BigEndian.PutUint32(valid[36:40], 42)         // Nonce
	binary.BigEndian.PutUint32(valid[40:44], 12345)      // Relay tag
	binary.BigEndian.PutUint32(valid[44:48], 1234567890) // Timestamp
	valid[48] = 2                                        // Version
	valid[49] = 6                                        // Asz (port(2)+IPv4(4))
	binary.BigEndian.PutUint16(valid[50:52], 8080)       // Port
	copy(valid[52:56], []byte{10, 0, 0, 1})              // IP
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodeRelayIntro(block)
	})
}

// FuzzDecodePeerTestBlock fuzzes PeerTest block decoding.
func FuzzDecodePeerTestBlock(f *testing.F) {
	// Minimal peer test block: type(1) + length(2) + msg(1) + status(1) + nonce(4) + timestamp(4) + version(1) = 14
	valid := make([]byte, 14)
	valid[0] = BlockTypePeerTest
	binary.BigEndian.PutUint16(valid[1:3], 11)
	valid[3] = 1  // Message code
	valid[13] = 2 // Version
	f.Add(valid)

	// With signed data
	withSig := make([]byte, 46)
	withSig[0] = BlockTypePeerTest
	binary.BigEndian.PutUint16(withSig[1:3], 43)
	withSig[3] = 1  // Message code
	withSig[13] = 2 // Version
	f.Add(withSig)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodePeerTestBlock(block)
	})
}

// FuzzDecodeRelayTag fuzzes RelayTag block decoding.
func FuzzDecodeRelayTag(f *testing.F) {
	// Valid relay tag: tag(4) + expiration(4)
	valid := make([]byte, 11)
	valid[0] = BlockTypeRelayTag
	binary.BigEndian.PutUint16(valid[1:3], 8)
	binary.BigEndian.PutUint32(valid[3:7], 0x12345678)
	binary.BigEndian.PutUint32(valid[7:11], 3600)
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodeRelayTag(block)
	})
}

// FuzzDecodeRelayTagRequest fuzzes RelayTagRequest block decoding.
func FuzzDecodeRelayTagRequest(f *testing.F) {
	// Valid relay tag request: nonce(4)
	valid := make([]byte, 7)
	valid[0] = BlockTypeRelayTagRequest
	binary.BigEndian.PutUint16(valid[1:3], 4)
	binary.BigEndian.PutUint32(valid[3:7], 0xDEADBEEF)
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodeRelayTagRequest(block)
	})
}

// FuzzDecodePathChallenge fuzzes PathChallenge block decoding.
func FuzzDecodePathChallenge(f *testing.F) {
	// Valid path challenge: nonce(8)
	valid := make([]byte, 11)
	valid[0] = BlockTypePathChallenge
	binary.BigEndian.PutUint16(valid[1:3], 8)
	binary.BigEndian.PutUint64(valid[3:11], 0x123456789ABCDEF0)
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodePathChallenge(block)
	})
}

// FuzzDecodePathResponse fuzzes PathResponse block decoding.
func FuzzDecodePathResponse(f *testing.F) {
	// Valid path response: nonce(8)
	valid := make([]byte, 11)
	valid[0] = BlockTypePathResponse
	binary.BigEndian.PutUint16(valid[1:3], 8)
	binary.BigEndian.PutUint64(valid[3:11], 0x123456789ABCDEF0)
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		block := &SSU2Block{}
		if _, err := block.Deserialize(data); err != nil {
			return
		}

		_, _ = DecodePathResponse(block)
	})
}
