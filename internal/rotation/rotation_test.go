package rotation

import (
	"slices"
	"testing"
)

func inputs(static, iv, intro []byte, hash string) Inputs {
	var h [32]byte
	copy(h[:], hash)
	return Inputs{StaticKey: static, IV: iv, IntroKey: intro, IdentityHash: h}
}

func TestCompare_Identical(t *testing.T) {
	a := inputs([]byte("key"), []byte("iv"), []byte("intro"), "hash-value-32-bytes-long-pad!!!!!!")
	if got := Compare(a, a); !got.Empty() {
		t.Fatalf("identical inputs reported changes: %+v", got)
	}
}

func TestCompare_RotationWhileIdentityUnchanged(t *testing.T) {
	base := inputs([]byte("key"), []byte("iv"), []byte("intro"), "hash-value-32-bytes-long-pad!!!!!!")

	cases := []struct {
		name string
		next Inputs
		want []string
	}{
		{"static key", inputs([]byte("new-key"), []byte("iv"), []byte("intro"), "hash-value-32-bytes-long-pad!!!!!!"), []string{"static key"}},
		{"iv", inputs([]byte("key"), []byte("new-iv"), []byte("intro"), "hash-value-32-bytes-long-pad!!!!!!"), []string{"IV"}},
		{"intro key", inputs([]byte("key"), []byte("iv"), []byte("new"), "hash-value-32-bytes-long-pad!!!!!!"), []string{"intro key"}},
		{"dropped key", inputs(nil, []byte("iv"), []byte("intro"), "hash-value-32-bytes-long-pad!!!!!!"), []string{"static key"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			change := Compare(base, tc.next)
			if got := change.Forbidden(); !slices.Equal(got, tc.want) {
				t.Fatalf("Forbidden() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCompare_RekeyAllowsNewMaterial(t *testing.T) {
	// "If the router \"rekeys\" to a different Router Hash, it should generate a
	// new noise key and IV as well."
	base := inputs([]byte("key"), []byte("iv"), []byte("intro"), "hash-value-32-bytes-long-pad!!!!!!")
	next := inputs([]byte("new-key"), []byte("new-iv"), []byte("new-intro"), "OTHER-hash-value-32-bytes-!!!!!!!")

	change := Compare(base, next)
	if !change.IdentityChanged {
		t.Fatal("expected the identity to have changed")
	}
	if got := change.Forbidden(); len(got) != 0 {
		t.Fatalf("a rekey must permit new key material, Forbidden() = %v", got)
	}
}

func TestCompare_FirstPopulationIsNotRotation(t *testing.T) {
	// go-i2p's transports start the listener before loading keys, then publish
	// them; that first fill must not look like a rotation.
	empty := inputs(nil, nil, nil, "hash-value-32-bytes-long-pad!!!!!!")
	filled := inputs([]byte("key"), []byte("iv"), []byte("intro"), "hash-value-32-bytes-long-pad!!!!!!")

	change := Compare(empty, filled)
	if !change.Empty() {
		t.Fatalf("first population reported as a change: %+v", change)
	}
	if got := change.Forbidden(); len(got) != 0 {
		t.Fatalf("Forbidden() = %v, want none", got)
	}
}

func TestCompare_HashOnlyChangeIsAllowed(t *testing.T) {
	// A hash change with no key material at all (e.g. an operator correcting the
	// advertised identity) is not a rotation.
	base := inputs(nil, nil, nil, "hash-value-32-bytes-long-pad!!!!!!")
	next := inputs(nil, nil, nil, "OTHER-hash-value-32-bytes-!!!!!!!")
	if got := Compare(base, next).Forbidden(); len(got) != 0 {
		t.Fatalf("Forbidden() = %v, want none", got)
	}
}

func TestCompare_NilAndEmptyAreTheSame(t *testing.T) {
	base := inputs([]byte{}, []byte{}, nil, "hash-value-32-bytes-long-pad!!!!!!")
	next := inputs(nil, nil, []byte{}, "hash-value-32-bytes-long-pad!!!!!!")
	if got := Compare(base, next); !got.Empty() {
		t.Fatalf("nil vs empty slice treated as a change: %+v", got)
	}
}
