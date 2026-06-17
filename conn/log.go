package conn

import "github.com/go-i2p/logger"

var log = logger.GetGoI2PLogger()

// flog returns a logger entry with package and function context pre-seeded.
// It accepts an optional Fields map to merge additional context.
func flog(fn string, fields ...logger.Fields) *logger.Entry {
	f := logger.Fields{"pkg": "noise", "func": fn}
	if len(fields) > 0 && fields[0] != nil {
		for k, v := range fields[0] {
			f[k] = v
		}
	}
	return log.WithFields(f)
}
