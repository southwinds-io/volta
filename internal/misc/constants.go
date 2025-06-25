package misc

const (
	// DefaultKeyVersion defines the current version of the encryption algorithm
	DefaultKeyVersion = 1

	// ArgonTime Key derivation parameters
	ArgonTime    uint32 = 4
	ArgonMemory  uint32 = 128 * 1024
	ArgonThreads uint8  = 4
	ArgonKeyLen  uint32 = 32
	SaltSize            = 16

	FilePermissions = 0600 // user read + write
)
