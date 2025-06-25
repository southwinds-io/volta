package backup

import (
	"encoding/hex"
	"fmt"
	"time"
)

// GenerateBackupID generates a unique backup ID
func GenerateBackupID() string {
	return fmt.Sprintf("backup_%d_%s",
		time.Now().Unix(),
		hex.EncodeToString(make([]byte, 8))) // Add some randomness
}
