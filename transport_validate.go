package noise

import (
	"github.com/go-i2p/go-noise/mod/validation"
	"github.com/samber/oops"
)

// validateDialParams validates parameters for DialNoise function.
func validateDialParams(network, addr string, config *ConnConfig) error {
	if err := validation.ValidateNetworkAddr(network, addr, "noise"); err != nil {
		return err
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			Errorf("config cannot be nil")
	}

	return config.Validate()
}

// validateListenParams validates parameters for ListenNoise function.
func validateListenParams(network, addr string, config *ListenerConfig) error {
	if err := validation.ValidateNetworkAddr(network, addr, "noise"); err != nil {
		return err
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			Errorf("config cannot be nil")
	}

	return config.Validate()
}
