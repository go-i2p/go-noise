package handshake

import (
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// OptionsParams holds the parsed or configured values from an SSU2 Options
// block (Type 1, 12 bytes minimum). Padding ratios use 4.4 fixed-point encoding
// where the value = integerPart + fractionPart/16 (range 0.0–15.9375).
// Per spec: tmin(1) | tmax(1) | rmin(1) | rmax(1) | tdmy(2) | rdmy(2) | tdelay(2) | rdelay(2)
type OptionsParams struct {
	TMinRatio float64 // transmit padding minimum ratio
	TMaxRatio float64 // transmit padding maximum ratio
	RMinRatio float64 // receive padding minimum ratio
	RMaxRatio float64 // receive padding maximum ratio
	TDummy    uint16  // transmit dummy traffic rate
	RDummy    uint16  // receive dummy traffic rate
	TDelay    uint16  // transmit delay (ms)
	RDelay    uint16  // receive delay (ms)
}

// fixedPointToFloat decodes a 4.4 fixed-point byte: upper nibble is the
// integer part, lower nibble is the fractional part (sixteenths).
func fixedPointToFloat(b byte) float64 {
	return float64(b>>4) + float64(b&0x0F)/16.0
}

// floatToFixedPoint encodes a float as a 4.4 fixed-point byte.
func floatToFixedPoint(f float64) byte {
	if f < 0 {
		f = 0
	}
	if f > 15.9375 {
		f = 15.9375
	}
	intPart := int(f)
	fracPart := int((f - float64(intPart)) * 16)
	return byte(intPart<<4 | fracPart)
}

// ParseOptionsBlock decodes a 12+ byte Options block into OptionsParams.
// Per spec: tmin(1) | tmax(1) | rmin(1) | rmax(1) | tdmy(2) | rdmy(2) | tdelay(2) | rdelay(2)
func ParseOptionsBlock(data []byte) (*OptionsParams, error) {
	flog("ParseOptionsBlock", logger.Fields{"dataLen": len(data)}).Debug("decoding options block")
	if len(data) < 12 {
		return nil, oops.Errorf("Options block too short: %d bytes, need 12", len(data))
	}
	return &OptionsParams{
		TMinRatio: fixedPointToFloat(data[0]),
		TMaxRatio: fixedPointToFloat(data[1]),
		RMinRatio: fixedPointToFloat(data[2]),
		RMaxRatio: fixedPointToFloat(data[3]),
		TDummy:    binary.BigEndian.Uint16(data[4:6]),
		RDummy:    binary.BigEndian.Uint16(data[6:8]),
		TDelay:    binary.BigEndian.Uint16(data[8:10]),
		RDelay:    binary.BigEndian.Uint16(data[10:12]),
	}, nil
}

// Serialize encodes OptionsParams into a 12-byte Options block per spec.
func (o *OptionsParams) Serialize() []byte {
	flog("Serialize").Debug("encoding OptionsParams to 12-byte block")
	data := make([]byte, 12)
	data[0] = floatToFixedPoint(o.TMinRatio)
	data[1] = floatToFixedPoint(o.TMaxRatio)
	data[2] = floatToFixedPoint(o.RMinRatio)
	data[3] = floatToFixedPoint(o.RMaxRatio)
	binary.BigEndian.PutUint16(data[4:6], o.TDummy)
	binary.BigEndian.PutUint16(data[6:8], o.RDummy)
	binary.BigEndian.PutUint16(data[8:10], o.TDelay)
	binary.BigEndian.PutUint16(data[10:12], o.RDelay)
	return data
}

// NegotiatedPadding computes the effective padding parameters by intersecting
// both peers' preferences: max of minimums, min of maximums.
// Returns nil if either side has not provided options.
func NegotiatedPadding(local, peer *OptionsParams) *OptionsParams {
	if local == nil || peer == nil {
		return nil
	}
	// The peer's transmit limits constrain what we receive, and our transmit
	// limits constrain what the peer receives. Negotiate the overlap.
	negotiated := &OptionsParams{}

	// Our send padding: bounded by our tmin/tmax AND peer's rmin/rmax
	negotiated.TMinRatio = max44(local.TMinRatio, peer.RMinRatio)
	negotiated.TMaxRatio = min44(local.TMaxRatio, peer.RMaxRatio)
	if negotiated.TMaxRatio < negotiated.TMinRatio {
		// Empty intersection — treat as no constraint (zero both).
		negotiated.TMinRatio = 0
		negotiated.TMaxRatio = 0
	}

	// Our receive padding: bounded by our rmin/rmax AND peer's tmin/tmax
	negotiated.RMinRatio = max44(local.RMinRatio, peer.TMinRatio)
	negotiated.RMaxRatio = min44(local.RMaxRatio, peer.TMaxRatio)
	if negotiated.RMaxRatio < negotiated.RMinRatio {
		// Empty intersection — treat as no constraint (zero both).
		negotiated.RMinRatio = 0
		negotiated.RMaxRatio = 0
	}

	// Dummy traffic and delay: use the smaller of the two peers' values
	negotiated.TDummy = minU16(local.TDummy, peer.RDummy)
	negotiated.RDummy = minU16(local.RDummy, peer.TDummy)
	negotiated.TDelay = minU16(local.TDelay, peer.RDelay)
	negotiated.RDelay = minU16(local.RDelay, peer.TDelay)

	return negotiated
}

func max44(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func min44(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func minU16(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}
