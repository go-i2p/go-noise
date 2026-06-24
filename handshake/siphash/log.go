package siphash

import (
	"github.com/go-i2p/go-noise/internal/logutil"
	"github.com/go-i2p/logger"
)

var (
	flog = logutil.MakePackageLogger("handshake/siphash")
	log  = logger.GetGoI2PLogger()
)
