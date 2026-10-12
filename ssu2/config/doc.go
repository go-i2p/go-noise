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
// See [I2P Spec: SSU2](https://i2p.net/en/docs/specs/ssu2/) for the protocol
// these settings configure.
package config
