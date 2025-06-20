//go:build debug

package debug

import "fmt"

const Debug = true

func Print(format string, args ...interface{}) {
	fmt.Printf("DEBUG: "+format, args...)
}
