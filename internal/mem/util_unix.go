//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package mem

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
)

func lockMemoryPlatform() (ProtectionLevel, error) {
	err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			// Permission denied but still continue
			return ProtectionPartial, nil
		} else if errors.Is(err, unix.ENOSYS) {
			// Function not implemented on this system
			return ProtectionPartial, nil
		}
		return ProtectionNone, fmt.Errorf("failed to lock memory: %w", err)
	}
	return ProtectionFull, nil
}

func unlockMemoryPlatform() error {
	err := unix.Munlockall()
	if err != nil {
		// Non-critical error, just log it
		return fmt.Errorf("failed to unlock memory: %w", err)
	}
	return nil
}
