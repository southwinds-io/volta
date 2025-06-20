//go:build windows
// +build windows

package mem

func lockMemoryPlatform() (MemoryProtectionLevel, error) {
	// On Windows, we can use VirtualLock but it has limitations
	// For simplicity, we'll just use memory clearing
	return MemoryProtectionPartial, nil
}

func unlockMemoryPlatform() error {
	// Nothing to unlock
	return nil
}
