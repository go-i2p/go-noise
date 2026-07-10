package listener

import (
	"github.com/go-i2p/logger"
)

// log is the package-level logger handle for listener. It is stored on
// *Listener as nl.logger so that runtime log-level changes remain visible
// through the struct field, matching the pattern used by conn/ntcp2.
var log = logger.GetGoI2PLogger()
