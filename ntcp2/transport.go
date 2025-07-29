package ntcp2

import (
	"context"
	"net"

	noise "github.com/go-i2p/go-noise"
	"github.com/samber/oops"
)

// DialNTCP2 creates a connection to the given address and wraps it with NTCP2Conn.
// This is a convenience function that combines net.Dial, NoiseConn creation, and NTCP2 wrapping.
// For more control over the underlying connection, use net.Dial followed by NewNoiseConn and NewNTCP2Conn.
func DialNTCP2(network, addr string, config *NTCP2Config) (*NTCP2Conn, error) {
	if err := validateDialParams(network, addr, config); err != nil {
		return nil, err
	}

	conn, err := establishTCPConnection(network, addr)
	if err != nil {
		return nil, err
	}

	noiseConn, err := createNoiseConnection(conn, config, network, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return buildNTCP2Connection(noiseConn, conn, config, network, addr)
}

// DialNTCP2WithHandshake creates a connection and performs the NTCP2 handshake automatically.
// This is a convenience function that combines DialNTCP2 and handshake execution.
func DialNTCP2WithHandshake(network, addr string, config *NTCP2Config) (*NTCP2Conn, error) {
	return DialNTCP2WithHandshakeContext(context.Background(), network, addr, config)
}

// DialNTCP2WithHandshakeContext creates a connection and performs the NTCP2 handshake with context.
// The context can be used to cancel the dial or handshake operations.
func DialNTCP2WithHandshakeContext(ctx context.Context, network, addr string, config *NTCP2Config) (*NTCP2Conn, error) {
	ntcp2Conn, err := DialNTCP2(network, addr, config)
	if err != nil {
		return nil, err
	}

	// Perform the handshake with the provided context on the underlying NoiseConn
	if err := ntcp2Conn.UnderlyingConn().Handshake(ctx); err != nil {
		ntcp2Conn.Close()
		return nil, oops.
			Code("HANDSHAKE_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "NTCP2 handshake failed")
	}

	return ntcp2Conn, nil
}

// ListenNTCP2 creates a listener on the given address and wraps it with NTCP2Listener.
// This is a convenience function that combines net.Listen and NewNTCP2Listener.
// For more control over the underlying listener, use net.Listen followed by NewNTCP2Listener.
func ListenNTCP2(network, addr string, config *NTCP2Config) (*NTCP2Listener, error) {
	if err := validateListenParams(network, addr, config); err != nil {
		return nil, err
	}

	// Create the underlying TCP listener
	listener, err := net.Listen(network, addr)
	if err != nil {
		return nil, oops.
			Code("LISTEN_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to listen on %s://%s", network, addr)
	}

	// Create the NTCP2 listener wrapper
	ntcp2Listener, err := NewNTCP2Listener(listener, config)
	if err != nil {
		listener.Close()
		return nil, oops.
			Code("NTCP2_LISTENER_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create NTCP2 listener")
	}

	return ntcp2Listener, nil
}

// WrapNTCP2Conn wraps an existing net.Conn with NTCP2Conn.
// This function creates the necessary Noise wrapper and NTCP2 addressing.
func WrapNTCP2Conn(conn net.Conn, config *NTCP2Config) (*NTCP2Conn, error) {
	if err := validateWrapConnParams(conn, config); err != nil {
		return nil, err
	}

	noiseConn, err := createWrappedNoiseConnection(conn, config)
	if err != nil {
		return nil, err
	}

	localAddr, remoteAddr, err := createDialAddresses(conn, config)
	if err != nil {
		return nil, oops.
			Code("ADDRESS_CREATION_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to create NTCP2 addresses")
	}

	return NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
}

// validateWrapConnParams validates the input parameters for WrapNTCP2Conn.
func validateWrapConnParams(conn net.Conn, config *NTCP2Config) error {
	if conn == nil {
		return oops.
			Code("INVALID_CONNECTION").
			In("ntcp2").
			Errorf("connection cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			Errorf("config cannot be nil")
	}

	return nil
}

// createWrappedNoiseConnection converts the NTCP2 config and creates a Noise connection.
func createWrappedNoiseConnection(conn net.Conn, config *NTCP2Config) (*noise.NoiseConn, error) {
	noiseConfig, err := config.ToConnConfig()
	if err != nil {
		return nil, oops.
			Code("CONFIG_CONVERSION_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to convert NTCP2 config to Noise config")
	}

	noiseConn, err := noise.NewNoiseConn(conn, noiseConfig)
	if err != nil {
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to create noise connection")
	}

	return noiseConn, nil
}

// WrapNTCP2Listener wraps an existing net.Listener with NTCP2Listener.
// This is an alias for NewNTCP2Listener for consistency with the transport API.
func WrapNTCP2Listener(listener net.Listener, config *NTCP2Config) (*NTCP2Listener, error) {
	return NewNTCP2Listener(listener, config)
}

// validateDialParams validates the parameters for dial operations
func validateDialParams(network, addr string, config *NTCP2Config) error {
	if err := validateBasicDialParams(network, addr, config); err != nil {
		return err
	}

	if err := validateDialConfiguration(config); err != nil {
		return err
	}

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ntcp2").
			Wrapf(err, "NTCP2 config validation failed")
	}

	return nil
}

// validateBasicDialParams validates the basic parameters for dial operations.
func validateBasicDialParams(network, addr string, config *NTCP2Config) error {
	if network == "" {
		return oops.
			Code("INVALID_NETWORK").
			In("ntcp2").
			Errorf("network cannot be empty")
	}

	if addr == "" {
		return oops.
			Code("INVALID_ADDRESS").
			In("ntcp2").
			Errorf("address cannot be empty")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			Errorf("config cannot be nil")
	}

	return nil
}

// validateDialConfiguration validates configuration-specific requirements for dial operations.
func validateDialConfiguration(config *NTCP2Config) error {
	if !config.Initiator {
		return oops.
			Code("INVALID_INITIATOR_FLAG").
			In("ntcp2").
			Errorf("dial operations require initiator=true in config")
	}

	return nil
}

// validateListenParams validates the parameters for listen operations
func validateListenParams(network, addr string, config *NTCP2Config) error {
	if err := validateBasicListenParams(network, addr, config); err != nil {
		return err
	}

	if err := validateListenConfiguration(config); err != nil {
		return err
	}

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ntcp2").
			Wrapf(err, "NTCP2 config validation failed")
	}

	return nil
}

// validateBasicListenParams validates the basic parameters for listen operations.
func validateBasicListenParams(network, addr string, config *NTCP2Config) error {
	if network == "" {
		return oops.
			Code("INVALID_NETWORK").
			In("ntcp2").
			Errorf("network cannot be empty")
	}

	if addr == "" {
		return oops.
			Code("INVALID_ADDRESS").
			In("ntcp2").
			Errorf("address cannot be empty")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			Errorf("config cannot be nil")
	}

	return nil
}

// validateListenConfiguration validates configuration-specific requirements for listen operations.
func validateListenConfiguration(config *NTCP2Config) error {
	if config.Initiator {
		return oops.
			Code("INVALID_INITIATOR_FLAG").
			In("ntcp2").
			Errorf("listen operations require initiator=false in config")
	}

	return nil
}

// createDialAddresses creates the local and remote NTCP2 addresses for dial operations
func createDialAddresses(conn net.Conn, config *NTCP2Config) (*NTCP2Addr, *NTCP2Addr, error) {
	// Create local address from connection's local address
	localAddr, err := NewNTCP2Addr(
		conn.LocalAddr(),
		config.RouterHash,
		"initiator", // Dial operations are always initiators
	)
	if err != nil {
		return nil, nil, oops.
			Code("LOCAL_ADDR_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to create local NTCP2 address")
	}

	// Create remote address from connection's remote address and config
	var remoteRouterHash []byte
	if config.RemoteRouterHash != nil {
		remoteRouterHash = make([]byte, len(config.RemoteRouterHash))
		copy(remoteRouterHash, config.RemoteRouterHash)
	}

	remoteAddr, err := NewNTCP2Addr(
		conn.RemoteAddr(),
		remoteRouterHash,
		"responder", // Remote side is the responder in dial operations
	)
	if err != nil {
		return nil, nil, oops.
			Code("REMOTE_ADDR_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to create remote NTCP2 address")
	}

	return localAddr, remoteAddr, nil
}

// establishTCPConnection dials the underlying TCP connection with proper error handling.
func establishTCPConnection(network, addr string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, oops.
			Code("DIAL_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to dial %s://%s", network, addr)
	}
	return conn, nil
}

// createNoiseConnection converts NTCP2Config to ConnConfig and creates the underlying Noise connection.
func createNoiseConnection(conn net.Conn, config *NTCP2Config, network, addr string) (*noise.NoiseConn, error) {
	noiseConfig, err := config.ToConnConfig()
	if err != nil {
		return nil, oops.
			Code("CONFIG_CONVERSION_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to convert NTCP2 config to Noise config")
	}

	noiseConn, err := noise.NewNoiseConn(conn, noiseConfig)
	if err != nil {
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise connection")
	}

	return noiseConn, nil
}

// buildNTCP2Connection creates NTCP2 addresses and wraps the noise connection with NTCP2Conn.
func buildNTCP2Connection(noiseConn *noise.NoiseConn, conn net.Conn, config *NTCP2Config, network, addr string) (*NTCP2Conn, error) {
	localAddr, remoteAddr, err := createDialAddresses(conn, config)
	if err != nil {
		noiseConn.Close()
		return nil, oops.
			Code("ADDRESS_CREATION_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create NTCP2 addresses")
	}

	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	if err != nil {
		noiseConn.Close()
		return nil, oops.
			Code("NTCP2_CONN_FAILED").
			In("ntcp2").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create NTCP2 connection")
	}

	return ntcp2Conn, nil
}
