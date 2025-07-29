package main

import (
	"fmt"
	"log"

	"github.com/go-i2p/go-noise/handshake"
)

func main() {
	fmt.Println("Go-Noise Handshake Modifier System Demo")
	fmt.Println("=======================================")

	// Original handshake data (simulated)
	originalData := []byte("This is a Noise protocol handshake message containing sensitive cryptographic data.")
	fmt.Printf("Original Data: %s\n", string(originalData))
	fmt.Printf("Original Length: %d bytes\n\n", len(originalData))

	// Create individual modifiers
	xorModifier, paddingModifier := createModifiers()

	// Run demonstration sections
	demonstrateIndividualModifiers(originalData, xorModifier, paddingModifier)
	chain := demonstrateModifierChaining(originalData, xorModifier, paddingModifier)
	demonstrateHandshakePhases(chain)
	demonstratePerformanceCharacteristics(chain)

	fmt.Println("\nDemo completed successfully!")
	fmt.Println("The modifier system provides secure, composable handshake transformations")
	fmt.Println("suitable for I2P transport protocol obfuscation and padding requirements.")
}

// createModifiers initializes and returns the XOR and padding modifiers for testing.
func createModifiers() (handshake.HandshakeModifier, handshake.HandshakeModifier) {
	xorModifier := handshake.NewXORModifier("obfuscation", []byte{0xAA, 0xBB, 0xCC, 0xDD})
	paddingModifier, err := handshake.NewPaddingModifier("padding", 8, 16)
	if err != nil {
		log.Fatal("Failed to create padding modifier:", err)
	}
	return xorModifier, paddingModifier
}

// demonstrateIndividualModifiers tests XOR and padding modifiers separately to verify round-trip functionality.
func demonstrateIndividualModifiers(originalData []byte, xorModifier, paddingModifier handshake.HandshakeModifier) {
	fmt.Println("1. Testing Individual Modifiers")
	fmt.Println("-------------------------------")

	// Test XOR modifier
	fmt.Println("XOR Modifier:")
	xorResult, err := xorModifier.ModifyOutbound(handshake.PhaseInitial, originalData)
	if err != nil {
		log.Fatal("XOR outbound failed:", err)
	}
	fmt.Printf("  After XOR: %x (length: %d)\n", xorResult, len(xorResult))

	xorRecovered, err := xorModifier.ModifyInbound(handshake.PhaseInitial, xorResult)
	if err != nil {
		log.Fatal("XOR inbound failed:", err)
	}
	fmt.Printf("  Recovered: %s\n", string(xorRecovered))
	fmt.Printf("  Round-trip Success: %t\n\n", string(xorRecovered) == string(originalData))

	// Test Padding modifier
	fmt.Println("Padding Modifier:")
	paddedResult, err := paddingModifier.ModifyOutbound(handshake.PhaseExchange, originalData)
	if err != nil {
		log.Fatal("Padding outbound failed:", err)
	}
	fmt.Printf("  After Padding: [%d bytes] %x...\n", len(paddedResult), paddedResult[:20])

	paddingRecovered, err := paddingModifier.ModifyInbound(handshake.PhaseExchange, paddedResult)
	if err != nil {
		log.Fatal("Padding inbound failed:", err)
	}
	fmt.Printf("  Recovered: %s\n", string(paddingRecovered))
	fmt.Printf("  Round-trip Success: %t\n\n", string(paddingRecovered) == string(originalData))
}

// demonstrateModifierChaining creates and tests a modifier chain with both XOR and padding modifiers.
func demonstrateModifierChaining(originalData []byte, xorModifier, paddingModifier handshake.HandshakeModifier) *handshake.ModifierChain {
	fmt.Println("2. Testing Modifier Chaining")
	fmt.Println("-----------------------------")

	// Create a chain with both modifiers
	chain := handshake.NewModifierChain("demo-chain", xorModifier, paddingModifier)
	fmt.Printf("Created chain '%s' with %d modifiers:\n", chain.Name(), chain.Count())
	for i, name := range chain.ModifierNames() {
		fmt.Printf("  %d. %s\n", i+1, name)
	}
	fmt.Println()

	// Apply chain transformations (XOR then Padding)
	fmt.Println("Applying chain transformations (outbound):")
	chainResult, err := chain.ModifyOutbound(handshake.PhaseFinal, originalData)
	if err != nil {
		log.Fatal("Chain outbound failed:", err)
	}
	fmt.Printf("  Original: %d bytes\n", len(originalData))
	fmt.Printf("  After Chain: %d bytes (%+d bytes added)\n", len(chainResult), len(chainResult)-len(originalData))
	fmt.Printf("  Transformed Data: %x...\n", chainResult[:min(32, len(chainResult))])
	fmt.Println()

	// Reverse chain transformations (Padding removal then XOR)
	fmt.Println("Reversing chain transformations (inbound):")
	chainRecovered, err := chain.ModifyInbound(handshake.PhaseFinal, chainResult)
	if err != nil {
		log.Fatal("Chain inbound failed:", err)
	}
	fmt.Printf("  Recovered: %s\n", string(chainRecovered))
	fmt.Printf("  Chain Round-trip Success: %t\n\n", string(chainRecovered) == string(originalData))

	return chain
}

// demonstrateHandshakePhases tests the modifier chain across different handshake phases.
func demonstrateHandshakePhases(chain *handshake.ModifierChain) {
	fmt.Println("3. Testing Different Handshake Phases")
	fmt.Println("------------------------------------")

	phases := []handshake.HandshakePhase{
		handshake.PhaseInitial,
		handshake.PhaseExchange,
		handshake.PhaseFinal,
	}

	for _, phase := range phases {
		fmt.Printf("Phase: %s\n", phase.String())
		phaseResult, err := chain.ModifyOutbound(phase, []byte("test data for phase"))
		if err != nil {
			log.Printf("  Error: %v\n", err)
		} else {
			fmt.Printf("  Transformed: %d bytes\n", len(phaseResult))

			// Verify round-trip
			recovered, err := chain.ModifyInbound(phase, phaseResult)
			if err != nil {
				log.Printf("  Recovery Error: %v\n", err)
			} else {
				fmt.Printf("  Round-trip: %t\n", string(recovered) == "test data for phase")
			}
		}
		fmt.Println()
	}
}

// demonstratePerformanceCharacteristics tests the modifier chain performance with different data sizes.
func demonstratePerformanceCharacteristics(chain *handshake.ModifierChain) {
	fmt.Println("4. Performance Characteristics")
	fmt.Println("------------------------------")

	testSizes := []int{64, 256, 1024, 4096}
	for _, size := range testSizes {
		testData := make([]byte, size)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		result, err := chain.ModifyOutbound(handshake.PhaseExchange, testData)
		if err != nil {
			log.Printf("Error with %d byte data: %v\n", size, err)
			continue
		}

		overhead := len(result) - len(testData)
		overheadPercent := float64(overhead) / float64(len(testData)) * 100

		fmt.Printf("  %d bytes -> %d bytes (overhead: %d bytes, %.1f%%)\n",
			size, len(result), overhead, overheadPercent)
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
