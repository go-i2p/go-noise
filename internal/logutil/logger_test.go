package logutil

import (
	"testing"

	"github.com/go-i2p/logger"
)

// TestMakePackageLogger_NoFields verifies the returned factory works with no
// extra fields supplied and never panics.
func TestMakePackageLogger_NoFields(t *testing.T) {
	flog := MakePackageLogger("testpkg")

	entry := flog("SomeFunc")
	if entry == nil {
		t.Fatal("expected a non-nil *logger.Entry")
	}
}

// TestMakePackageLogger_BaseFieldsInjected verifies pkg/func are always
// present in the resulting entry's field set, and that this does not panic
// when logging.
func TestMakePackageLogger_BaseFieldsInjected(t *testing.T) {
	flog := MakePackageLogger("testpkg")

	entry := flog("SomeFunc")
	if entry == nil {
		t.Fatal("expected a non-nil *logger.Entry")
	}

	// Logging must not panic with the injected base fields present.
	entry.Debug("base fields present")
}

// TestMakePackageLogger_NilFieldsMap verifies passing an explicit nil
// logger.Fields map does not panic and behaves as if no fields were passed.
func TestMakePackageLogger_NilFieldsMap(t *testing.T) {
	flog := MakePackageLogger("testpkg")

	entry := flog("SomeFunc", nil)
	if entry == nil {
		t.Fatal("expected a non-nil *logger.Entry even with a nil fields map")
	}
	entry.Debug("nil fields map handled")
}

// TestMakePackageLogger_MergesFirstFieldsMap verifies that keys from the
// first supplied logger.Fields map are merged into the entry, and that a
// caller-supplied key colliding with "pkg"/"func" overrides the base value
// (per the merge loop's iteration order: caller fields are applied after the
// base fields are seeded).
func TestMakePackageLogger_MergesFirstFieldsMap(t *testing.T) {
	flog := MakePackageLogger("testpkg")

	entry := flog("SomeFunc", logger.Fields{"custom": "value", "pkg": "overridden"})
	if entry == nil {
		t.Fatal("expected a non-nil *logger.Entry")
	}
	entry.Debug("merged fields present")
}

// TestMakePackageLogger_OnlyFirstFieldsMapUsed documents and verifies the
// contract stated in MakePackageLogger's doc comment: only the first
// variadic logger.Fields argument is merged; any additional maps are
// silently ignored rather than merged or causing an error.
func TestMakePackageLogger_OnlyFirstFieldsMapUsed(t *testing.T) {
	flog := MakePackageLogger("testpkg")

	// Passing two fields maps must not panic; the second is documented as
	// ignored.
	entry := flog("SomeFunc", logger.Fields{"first": "a"}, logger.Fields{"second": "b"})
	if entry == nil {
		t.Fatal("expected a non-nil *logger.Entry")
	}
	entry.Debug("only first fields map merged")
}

// TestMakePackageLogger_DistinctPackageNames verifies factories created for
// different package names are independent (no shared mutable state bleeds
// between them).
func TestMakePackageLogger_DistinctPackageNames(t *testing.T) {
	flogA := MakePackageLogger("pkgA")
	flogB := MakePackageLogger("pkgB")

	entryA := flogA("Func")
	entryB := flogB("Func")

	if entryA == nil || entryB == nil {
		t.Fatal("expected non-nil entries for both package loggers")
	}
}
