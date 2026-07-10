// Package logutil provides shared logger utilities for all go-noise packages.
package logutil

import "github.com/go-i2p/logger"

// MakePackageLogger returns a logger factory for a given package name.
// It returns a function that creates logger entries with pre-seeded package and function context.
//
// The returned function accepts an optional single logger.Fields map as extra
// context. Only the first element of fields is used; any additional elements
// are ignored. Callers needing more than one map of extra fields must merge
// them into a single logger.Fields value before calling.
func MakePackageLogger(pkgName string) func(fn string, fields ...logger.Fields) *logger.Entry {
	log := logger.GetGoI2PLogger()
	return func(fn string, fields ...logger.Fields) *logger.Entry {
		f := logger.Fields{"pkg": pkgName, "func": fn}
		if len(fields) > 0 && fields[0] != nil {
			for k, v := range fields[0] {
				f[k] = v
			}
		}
		return log.WithFields(f)
	}
}
