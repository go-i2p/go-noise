package server

import (
	"reflect"

	"github.com/samber/oops"
)

// validateParam returns an INVALID_* style oops error when a required
// parameter is nil. The caller controls name/code/scope so existing
// error messages and telemetry codes remain unchanged.
func validateParam(param interface{}, name, code, scope string) error {
	if param != nil {
		v := reflect.ValueOf(param)
		switch v.Kind() {
		case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
			if !v.IsNil() {
				return nil
			}
		default:
			return nil
		}
	}

	return oops.
		Code(code).
		In(scope).
		Errorf("%s cannot be nil", name)
}
