// Command modifiers demonstrates the NTCP2 handshake modifier system defined
// by ntcp2.md §"Additions to the Framework".
//
// The two modifiers shown are the ones the spec actually defines:
//
//   - AES ephemeral-key obfuscation (§"Obfuscation of the ephemeral key"):
//     messages 1 and 2 carry their 32-byte ephemeral key in AES-256-CBC, keyed
//     with the peer's router hash and the IV published in the network database.
//   - Padding (§"Padding", line 151): "Padding is outside the authenticated
//     data frame for messages 1 and 2. ... Starting in message 3, padding is
//     inside the authenticated data frame." This demo uses the AEAD-padding
//     variant, which appends a self-describing I2P block ([254][size][data])
//     and so strips symmetrically. Cleartext padding for messages 1 and 2 is
//     NOT symmetric here: its length is carried in the message's own options
//     block (padLen), so the framing layer in ntcp2/handshake.go
//     (readCleartextPadding) reads and MixHashes exactly that many bytes
//     rather than the modifier guessing at them.
//
// Both are composed through a [handshake.ModifierChain], which applies outbound
// modifiers in order and inbound modifiers in reverse, so each peer can undo
// exactly what the other applied.
package main

import (
	"fmt"
	"log"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/ntcp2"
)

func main() {
	fmt.Println("Go-Noise NTCP2 Handshake Modifier System Demo")
	fmt.Println("=============================================")

	originalData := []byte("This is a Noise protocol handshake message containing sensitive cryptographic data.")
	fmt.Printf("Original Data: %s\n", string(originalData))
	fmt.Printf("Original Length: %d bytes\n\n", len(originalData))

	aesMod, paddingMod, err := createModifiers()
	if err != nil {
		log.Fatal("Failed to create modifiers: ", err)
	}

	demonstrateIndividualModifiers(originalData, aesMod, paddingMod)
	chain := demonstrateModifierChaining(originalData, aesMod, paddingMod)
	demonstrateHandshakePhases(chain)
	demonstratePerformanceCharacteristics(chain)

	fmt.Println("\nDemo completed successfully!")
	fmt.Println("The modifier system provides composable handshake transformations")
	fmt.Println("matching the obfuscation and padding extensions NTCP2 defines.")
}

// createModifiers builds the two spec-defined NTCP2 modifiers.
func createModifiers() (handshake.HandshakeModifier, handshake.HandshakeModifier, error) {
	// Demo material only: a 32-byte router hash and the 16-byte IV that a real
	// deployment reads out of the peer's network database entry.
	routerHash := make([]byte, ntcp2.RouterHashSize)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}
	iv := make([]byte, ntcp2.IVSize)
	for i := range iv {
		iv[i] = byte(0xA0 + i)
	}

	aesModifier, err := ntcp2.NewAESObfuscationModifier("ntcp2-aes-obfuscation", routerHash, iv)
	if err != nil {
		return nil, nil, err
	}
	// useAEADPadding = true: the padding is an I2P block inside the AEAD frame,
	// which the modifier can locate and strip on the inbound side.
	paddingModifier, err := ntcp2.NewNTCP2PaddingModifier("ntcp2-padding", 8, 16, true)
	if err != nil {
		return nil, nil, err
	}
	return aesModifier, paddingModifier, nil
}

// demonstrateIndividualModifiers exercises each modifier on its own.
//
// AES obfuscation only transforms the leading 32-byte ephemeral key, so a
// round trip through one phase restores the original bytes.
func demonstrateIndividualModifiers(originalData []byte, aesModifier, paddingModifier handshake.HandshakeModifier) {
	fmt.Println("1. Testing Individual Modifiers")
	fmt.Println("-------------------------------")

	fmt.Println("AES Obfuscation Modifier (message 1, cleartext padding):")
	aesResult, err := aesModifier.ModifyOutbound(handshake.PhaseInitial, originalData)
	if err != nil {
		log.Fatal("AES outbound failed: ", err)
	}
	fmt.Printf("  After AES: %x... (length: %d)\n", aesResult[:20], len(aesResult))

	aesRecovered, err := aesModifier.ModifyInbound(handshake.PhaseInitial, aesResult)
	if err != nil {
		log.Fatal("AES inbound failed: ", err)
	}
	fmt.Printf("  Recovered: %s\n", string(aesRecovered))
	fmt.Printf("  Round-trip Success: %t\n\n", string(aesRecovered) == string(originalData))

	fmt.Println("Padding Modifier (AEAD block padding, PhaseData):")
	paddedResult, err := paddingModifier.ModifyOutbound(handshake.PhaseData, originalData)
	if err != nil {
		log.Fatal("Padding outbound failed: ", err)
	}
	fmt.Printf("  After Padding: [%d bytes] %x...\n", len(paddedResult), paddedResult[:20])

	paddingRecovered, err := paddingModifier.ModifyInbound(handshake.PhaseData, paddedResult)
	if err != nil {
		log.Fatal("Padding inbound failed: ", err)
	}
	fmt.Printf("  Recovered: %s\n", string(paddingRecovered))
	fmt.Printf("  Round-trip Success: %t\n\n", string(paddingRecovered) == string(originalData))
}

// demonstrateModifierChaining composes both modifiers into a chain.
func demonstrateModifierChaining(originalData []byte, aesModifier, paddingModifier handshake.HandshakeModifier) *handshake.ModifierChain {
	fmt.Println("2. Testing Modifier Chaining")
	fmt.Println("-----------------------------")

	chain := handshake.NewModifierChain("demo-chain", aesModifier, paddingModifier)
	fmt.Printf("Created chain '%s' with %d modifiers:\n", chain.Name(), chain.Count())
	for i, name := range chain.ModifierNames() {
		fmt.Printf("  %d. %s\n", i+1, name)
	}
	fmt.Println()

	fmt.Println("Applying chain transformations (outbound):")
	chainResult, err := chain.ModifyOutbound(handshake.PhaseData, originalData)
	if err != nil {
		log.Fatal("Chain outbound failed: ", err)
	}
	fmt.Printf("  Original: %d bytes\n", len(originalData))
	fmt.Printf("  After Chain: %d bytes (%+d bytes added)\n", len(chainResult), len(chainResult)-len(originalData))
	fmt.Printf("  Transformed Data: %x...\n", chainResult[:minInt(32, len(chainResult))])
	fmt.Println()

	// Inbound runs the modifiers in reverse order, so padding is stripped
	// before the AES layer sees the data again.
	fmt.Println("Reversing chain transformations (inbound):")
	chainRecovered, err := chain.ModifyInbound(handshake.PhaseData, chainResult)
	if err != nil {
		log.Fatal("Chain inbound failed: ", err)
	}
	fmt.Printf("  Recovered: %s\n", string(chainRecovered))
	fmt.Printf("  Chain Round-trip Success: %t\n\n", string(chainRecovered) == string(originalData))

	return chain
}

// demonstrateHandshakePhases tests the chain across handshake phases.
func demonstrateHandshakePhases(chain *handshake.ModifierChain) {
	fmt.Println("3. Testing Different Handshake Phases")
	fmt.Println("------------------------------------")

	phases := []handshake.HandshakePhase{
		handshake.PhaseInitial,
		handshake.PhaseExchange,
		handshake.PhaseFinal,
		handshake.PhaseData,
	}

	for _, phase := range phases {
		fmt.Printf("Phase: %s\n", phase.String())
		phaseResult, err := chain.ModifyOutbound(phase, []byte("test data for phase"))
		if err != nil {
			log.Printf("  Error: %v\n", err)
		} else {
			fmt.Printf("  Transformed: %d bytes\n", len(phaseResult))

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

// demonstratePerformanceCharacteristics reports padding overhead by size.
func demonstratePerformanceCharacteristics(chain *handshake.ModifierChain) {
	fmt.Println("4. Performance Characteristics")
	fmt.Println("------------------------------")

	testSizes := []int{64, 256, 1024, 4096}
	for _, size := range testSizes {
		testData := make([]byte, size)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		result, err := chain.ModifyOutbound(handshake.PhaseData, testData)
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
