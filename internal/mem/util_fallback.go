//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows
// +build !linux,!darwin,!freebsd,!openbsd,!netbsd,!dragonfly,!windows

package mem

func lockMemoryPlatform() (MemoryProtectionLevel, error) {
	// On unsupported platforms, we can still provide basic protection
	// through zeroing memory, but can't prevent swapping
	return MemoryProtectionPartial, nil
}

func unlockMemoryPlatform() error {
	// Nothing to unlock on unsupported platforms
	return nil
}
