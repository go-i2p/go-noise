package reliability

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSpecWorkedExample_Decode feeds the exact byte sequence ssu2.rst's ACK
// worked example prescribes and asserts the resulting acknowledgements.
//
// Spec: "We want to ACK 10 9 8 6 5 2 1 0, and NACK 7 4 3.
//   - Ack Through: 10
//   - acnt: 2 (ack 9 8)
//   - range: 1 2 (nack 7, ack 6 5)
//   - range: 2 3 (nack 4 3, ack 2 1 0)"
func TestSpecWorkedExample_Decode(t *testing.T) {
	data := []byte{0, 0, 0, 10, 2, 1, 2, 2, 3}
	h := NewACKHandler()
	acked, err := h.ProcessACK(&SSU2Block{Type: BlockTypeACK, Data: data})
	require.NoError(t, err)

	got := append([]uint32(nil), acked...)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	require.Equal(t, []uint32{0, 1, 2, 5, 6, 8, 9, 10}, got)
}

// TestSpecWorkedExample_Encode is the outbound half: GenerateACK must emit the
// spec's byte sequence for the same received set.
func TestSpecWorkedExample_Encode(t *testing.T) {
	h := NewACKHandler()
	for _, p := range []uint32{10, 9, 8, 6, 5, 2, 1, 0} {
		h.RecordReceived(p)
	}
	blk, err := h.GenerateACK()
	require.NoError(t, err)
	require.NotNil(t, blk)
	t.Logf("generated ACK data = %v", blk.Data)
	require.Equal(t, []byte{0, 0, 0, 10, 2, 1, 2, 2, 3}, blk.Data)
}

// TestAcntSpill_Over255Run verifies a >256 consecutive run no longer truncates
// acnt; the excess is carried in ack-only ranges.
func TestAcntSpill_Over255Run(t *testing.T) {
	h := NewACKHandler()
	for p := uint32(0); p < 300; p++ {
		h.RecordReceived(p)
	}
	blk, err := h.GenerateACK()
	require.NoError(t, err)
	acnt := blk.Data[4]
	require.Equal(t, byte(255), acnt, "acnt must saturate at 255, not truncate")

	// Round-trip: decoding our own block must acknowledge all 300 packets.
	h2 := NewACKHandler()
	acked, err := h2.ProcessACK(blk)
	require.NoError(t, err)
	require.Len(t, acked, 300)
}

// TestRoundTrip_Gaps exercises sparse packet sets through encode then decode.
func TestRoundTrip_Gaps(t *testing.T) {
	for _, set := range [][]uint32{
		{0, 1, 2, 5, 6, 8, 9, 10},
		{100, 101, 105, 106, 110},
		{0, 300, 301, 700},
		{5, 6, 7, 8, 260, 261, 262},
	} {
		h := NewACKHandler()
		for _, p := range set {
			h.RecordReceived(p)
		}
		blk, err := h.GenerateACK()
		require.NoError(t, err)

		h2 := NewACKHandler()
		acked, err := h2.ProcessACK(blk)
		require.NoError(t, err, "set %v -> data %v", set, blk.Data)

		want := append([]uint32(nil), set...)
		sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
		got := append([]uint32(nil), acked...)
		sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
		require.Equal(t, want, got, "round trip mismatch for set %v (data %v)", set, blk.Data)
	}
}
