package reliability

import "github.com/go-i2p/go-noise/ssu2/wire"

// Type aliases from ssu2/wire so reliability code can reference these types
// without qualifying them with the wire package name.
type (
	SSU2Block  = wire.SSU2Block
	SSU2Packet = wire.SSU2Packet
)

// Packet size constants
const (
	MaxPacketSizeIPv4 = wire.MaxPacketSizeIPv4
	MaxPacketSizeIPv6 = wire.MaxPacketSizeIPv6
)

// Block type constants
const (
	BlockTypeACK        = wire.BlockTypeACK
	BlockTypeCongestion = wire.BlockTypeCongestion
	BlockTypePadding    = wire.BlockTypePadding

	// The remaining four are the non-ack-eliciting data-phase block types
	// enumerated by ssu2.md §"Congestion Control" -> §"Generating ACKs"; they are
	// aliased from ssu2/wire rather than restated here so the numeric values
	// cannot drift from the wire format.
	BlockTypeDateTime    = wire.BlockTypeDateTime
	BlockTypeAddress     = wire.BlockTypeAddress
	BlockTypeTermination = wire.BlockTypeTermination

	// Non-excluded types, used to assert the ack-eliciting side of the rule.
	BlockTypeI2NPMessage = wire.BlockTypeI2NPMessage
	BlockTypeOptions     = wire.BlockTypeOptions
)

// Constructor aliases
var NewSSU2Block = wire.NewSSU2Block
