package securemem

import "github.com/go-i2p/logger"

var log = logger.GetGoI2PLogger()

func flog(fn string, fields ...logger.Fields) *logger.Entry {
	f := logger.Fields{"pkg": "internal/securemem", "func": fn}
	if len(fields) > 0 && fields[0] != nil {
		for k, v := range fields[0] {
			f[k] = v
		}
	}
	return log.WithFields(f)
}