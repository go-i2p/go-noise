// Package shared provides common utilities for go-noise examples
package shared

import (
	"flag"
	"fmt"
	"time"

	"github.com/samber/oops"
)

// CommonArgs holds common command-line arguments for Noise examples
type CommonArgs struct {
	// Network configuration
	ServerAddr string
	ClientAddr string
	Pattern    string

	// Cryptographic material
	StaticKey string
	RemoteKey string

	// Timeouts
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration

	// Operation modes
	Demo     bool
	Generate bool
	Verbose  bool
}

// ParseCommonArgs parses standard command-line arguments for Noise examples
func ParseCommonArgs(appName string) (*CommonArgs, error) {
	args := &CommonArgs{}

	// Network configuration
	flag.StringVar(&args.ServerAddr, "server", "", "Run as server on specified address (e.g., localhost:8080)")
	flag.StringVar(&args.ClientAddr, "client", "", "Run as client connecting to specified address")
	flag.StringVar(&args.Pattern, "pattern", "NN", "Noise handshake pattern to use")

	// Cryptographic material
	flag.StringVar(&args.StaticKey, "static-key", "", "Static private key as 64-character hex string (generated if empty)")
	flag.StringVar(&args.RemoteKey, "remote-key", "", "Remote static public key as 64-character hex string (generated if empty)")

	// Timeouts
	flag.DurationVar(&args.HandshakeTimeout, "handshake-timeout", 30*time.Second, "Handshake timeout duration")
	flag.DurationVar(&args.ReadTimeout, "read-timeout", 60*time.Second, "Read operation timeout")
	flag.DurationVar(&args.WriteTimeout, "write-timeout", 60*time.Second, "Write operation timeout")

	// Operation modes
	flag.BoolVar(&args.Demo, "demo", false, "Run demonstration mode showing configurations and patterns")
	flag.BoolVar(&args.Generate, "generate", false, "Generate and display cryptographic keys for testing")
	flag.BoolVar(&args.Verbose, "verbose", false, "Enable verbose logging")

	flag.Parse()

	// Validate pattern
	if err := ValidatePattern(args.Pattern); err != nil {
		return nil, oops.
			Code("INVALID_ARGS").
			In("examples").
			Wrapf(err, "invalid pattern specified")
	}

	return args, nil
}

// PrintUsage displays usage information for a Noise example
func PrintUsage(appName, description string) {
	fmt.Printf("%s - %s\n\n", appName, description)
	fmt.Println("Usage:")
	fmt.Printf("  %s [options]\n\n", appName)
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Printf("  # Generate keys for testing:\n")
	fmt.Printf("  %s -generate\n\n", appName)
	fmt.Printf("  # Run demo mode:\n")
	fmt.Printf("  %s -demo\n\n", appName)
	fmt.Printf("  # Run server with NN pattern (no keys required):\n")
	fmt.Printf("  %s -server localhost:8080 -pattern NN\n\n", appName)
	fmt.Printf("  # Run client with NN pattern:\n")
	fmt.Printf("  %s -client localhost:8080 -pattern NN\n\n", appName)
	fmt.Printf("  # Run server with XX pattern (keys required):\n")
	fmt.Printf("  %s -server localhost:8080 -pattern XX -static-key <64-char-hex>\n\n", appName)
	fmt.Printf("  # Run client with XX pattern:\n")
	fmt.Printf("  %s -client localhost:8080 -pattern XX -static-key <64-char-hex>\n\n", appName)
	fmt.Println("Supported Patterns:")
	for _, pattern := range SupportedPatterns {
		needsLocal, needsRemote := GetPatternRequirements(pattern)
		requirements := "no keys required"
		if needsLocal && needsRemote {
			requirements = "requires local and remote static keys"
		} else if needsLocal {
			requirements = "requires local static key"
		} else if needsRemote {
			requirements = "requires remote static key"
		}
		fmt.Printf("  %-4s - %s\n", pattern, requirements)
	}
}

// ValidateArgs performs validation on parsed arguments
func (args *CommonArgs) ValidateArgs() error {
	if err := args.validateOperationMode(); err != nil {
		return err
	}

	if err := args.validateKeyRequirements(); err != nil {
		return err
	}

	return nil
}

// validateOperationMode ensures exactly one operation mode is specified
func (args *CommonArgs) validateOperationMode() error {
	modeCount := args.countActiveModes()

	if modeCount == 0 {
		return oops.
			Code("INVALID_ARGS").
			In("examples").
			Errorf("must specify one of: -server, -client, -demo, or -generate")
	}

	if modeCount > 1 {
		return oops.
			Code("INVALID_ARGS").
			In("examples").
			Errorf("cannot specify multiple modes simultaneously")
	}

	return nil
}

// countActiveModes returns the number of operation modes that are enabled
func (args *CommonArgs) countActiveModes() int {
	modeCount := 0
	if args.ServerAddr != "" {
		modeCount++
	}
	if args.ClientAddr != "" {
		modeCount++
	}
	if args.Demo {
		modeCount++
	}
	if args.Generate {
		modeCount++
	}
	return modeCount
}

// validateKeyRequirements ensures required keys are provided for the chosen pattern
func (args *CommonArgs) validateKeyRequirements() error {
	needsLocal, needsRemote := GetPatternRequirements(args.Pattern)

	if err := args.validateLocalKeyRequirement(needsLocal); err != nil {
		return err
	}

	if err := args.validateRemoteKeyRequirement(needsRemote); err != nil {
		return err
	}

	return nil
}

// validateLocalKeyRequirement checks if local static key is provided when required
func (args *CommonArgs) validateLocalKeyRequirement(needsLocal bool) error {
	if needsLocal && args.StaticKey == "" && !args.Demo && !args.Generate {
		return oops.
			Code("MISSING_KEY").
			In("examples").
			With("pattern", args.Pattern).
			Errorf("pattern %s requires a local static key (-static-key)", args.Pattern)
	}
	return nil
}

// validateRemoteKeyRequirement checks if remote static key is provided when required
func (args *CommonArgs) validateRemoteKeyRequirement(needsRemote bool) error {
	if needsRemote && args.RemoteKey == "" && !args.Demo && !args.Generate {
		return oops.
			Code("MISSING_KEY").
			In("examples").
			With("pattern", args.Pattern).
			Errorf("pattern %s requires a remote static key (-remote-key)", args.Pattern)
	}
	return nil
}
