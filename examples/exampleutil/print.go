// Package exampleutil provides common utilities for go-noise examples
package exampleutil

import "fmt"

// PrintLines prints each provided string on its own line, consolidating
// repeated fmt.Println sequences into a single function call to reduce
// code duplication across example programs.
func PrintLines(lines ...string) {
	for _, line := range lines {
		fmt.Println(line)
	}
}
