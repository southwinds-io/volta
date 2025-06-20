package mem

// ProtectionLevel indicates how well the vault can protect memory
type ProtectionLevel int

const (
	ProtectionNone    ProtectionLevel = iota // No memory protection available
	ProtectionPartial                        // Some protection measures applied
	ProtectionFull                           // Full memory protection (locked memory)
)

// Lock attempts to prevent sensitive data from being swapped to disk
// Returns the protection level achieved and any error encountered
func Lock() (ProtectionLevel, error) {
	// Platform-specific implementation
	return lockMemoryPlatform()
}

// Unlock releases memory locks if they were applied
func Unlock() error {
	// Platform-specific implementation
	return unlockMemoryPlatform()
}
