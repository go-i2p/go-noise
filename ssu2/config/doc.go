// Package config provides configuration types for the SSU2 transport.
//
// This package holds the settings that control how an SSU2 connection is
// established and behaves:
//
//   - SSU2Config: the main configuration struct, covering timeouts, key
//     material, and behavioral options.
//   - SSU2Addr: the address type for SSU2 connections, which carries the
//     peer's router identity, the connection ID, and optional introducer
//     information for NAT traversal.
//
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for the protocol
// these settings configure.
package config
