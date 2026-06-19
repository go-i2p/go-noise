// Package logutil provides shared logger utilities for all go-noise packages.
package logutil

import "github.com/go-i2p/logger"

// MakePackageLogger returns a logger factory for a given package name.
// It returns a function that creates logger entries with pre-seeded package and function context.
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
