//go:build !debug

package debug

const Debug = false

func Print(format string, args ...interface{}) {
	// Completely removed in an ordinary build
}
